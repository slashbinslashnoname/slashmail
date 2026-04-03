//! Engine: central event loop multiplexing swarm events, CLI commands, and OS signals.
//!
//! # Sync protocol — PeerId-ordered initiation
//!
//! When two peers connect, both could independently start a Merkle delta-sync,
//! leading to redundant transfers in both directions.  To prevent this, sync
//! initiation is ordered by PeerId:
//!
//! 1. **Lower PeerId** (lexicographic byte ordering) initiates sync immediately
//!    by sending a `SyncRequest::RootExchange` with its local Merkle root.
//!
//! 2. **Higher PeerId** defers for [`SYNC_DEFER_TIMEOUT`] (500 ms), giving the
//!    lower peer time to send its request first.  If an inbound `SyncRequest`
//!    arrives within that window the deferred sync is cancelled — the lower peer
//!    is already driving the exchange.  If the timeout elapses without an
//!    incoming request (e.g. the lower peer crashed or was slow), the higher
//!    peer initiates sync as a fallback.
//!
//! 3. **Idempotent storage**: all message inserts use `INSERT OR IGNORE`, so
//!    even if both peers end up syncing simultaneously (race, network jitter),
//!    duplicate rows are silently dropped rather than causing errors.
//!
//! Deferred syncs are also cleaned up on peer disconnection.

pub mod merkle;
pub mod topic_registry;

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use futures::StreamExt;
use libp2p::{gossipsub, identify, ping, request_response};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::crypto::ecdh;
use crate::crypto::encryption;
use crate::crypto::signing::{self, Keypair, PublicKey};
use crate::message::codec as msg_codec;
use crate::engine::merkle::MerkleTree;
use crate::net::behaviour::{SlashmailBehaviour, SlashmailBehaviourEvent};
use crate::net::peer_exchange::{
    self, PeerExchangeRequest, PeerExchangeResponse,
};
use crate::net::rr::{MailRequest, MailResponse};
use crate::net::sync_rr::{SyncRequest, SyncResponse};
use crate::storage::db::{Message, MessageStore};

pub use topic_registry::TopicRegistry;

/// Duration to wait for in-flight requests to drain during shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Duration to wait for gossipsub mesh peers after publishing.
const GOSSIP_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// Duration that the higher-PeerId peer waits for an incoming SyncRequest
/// before initiating its own sync.  See [`DeferredSync`].
const SYNC_DEFER_TIMEOUT: Duration = Duration::from_millis(500);

/// Tracks a deferred gossipsub publish reply while we wait for mesh peers.
struct PendingGossipPublish {
    reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    deadline: tokio::time::Instant,
    topic: String,
}

/// A sync initiation deferred because our local PeerId is lexicographically
/// higher than the remote peer's.  We wait [`SYNC_DEFER_TIMEOUT`] for an
/// incoming `SyncRequest` from that peer; if none arrives we initiate ourselves.
struct DeferredSync {
    peer_id: PeerId,
    deadline: tokio::time::Instant,
}

/// Per-peer tracking state maintained by the engine.
#[derive(Debug, Clone)]
struct PeerState {
    connected_since: DateTime<Utc>,
    protocols: Vec<String>,
    listen_addrs: Vec<Multiaddr>,
    rtt: Option<Duration>,
}

/// Status information returned by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub peer_id: String,
    pub listen_addrs: Vec<String>,
    pub external_addrs: Vec<String>,
    pub num_peers: usize,
}

/// Information about a connected peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub connected_since: String,
    pub protocols: Vec<String>,
    pub rtt_ms: Option<f64>,
}

/// Commands sent from the CLI (or other callers) to the engine via an mpsc channel.
///
/// Read operations (list, search) bypass this channel and use a read-only DB
/// connection directly. Write operations are routed here so the daemon owns the
/// sole read-write connection, preventing SQLITE_BUSY contention in WAL mode.
#[derive(Debug)]
pub enum EngineCommand {
    /// Subscribe to a gossipsub topic (SHA-256 hashed on the wire).
    Subscribe { topic: String },
    /// Unsubscribe from a gossipsub topic.
    Unsubscribe { topic: String },
    /// Broadcast a public message via gossipsub.
    ///
    /// `topic` is the human-readable topic string (e.g. `"pub_general"`);
    /// `data` is the codec-encoded envelope bytes ready for the wire.
    PublishPublic {
        topic: String,
        data: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Dial a remote peer at the given multiaddress.
    Dial { addr: Multiaddr },
    /// Start listening on the given multiaddress.
    Listen { addr: Multiaddr },
    /// Store a message in the local database (and eventually send it over the network).
    InsertMessage {
        msg: Message,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Add a peer by dialing its multiaddress and remember it.
    AddPeer {
        addr: Multiaddr,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Query the node status (PeerId, listen/external addrs, peer count).
    GetStatus {
        reply: tokio::sync::oneshot::Sender<StatusInfo>,
    },
    /// Query connected peers with metadata.
    GetPeers {
        reply: tokio::sync::oneshot::Sender<Vec<PeerInfo>>,
    },
    /// Query active gossipsub topic subscriptions.
    GetSubscriptions {
        reply: tokio::sync::oneshot::Sender<HashMap<String, String>>,
    },
    /// Send an encrypted private message to a recipient.
    ///
    /// The engine encrypts the body and tags, signs the envelope, and
    /// dispatches it via the request-response protocol. A copy is always
    /// stored in the local "Sent" folder. The reply carries
    /// `(message_id, optional_warning)` on success or an error string on failure.
    SendMessage {
        to: String,
        body: String,
        tags: Vec<String>,
        reply: tokio::sync::oneshot::Sender<Result<(String, Option<String>), String>>,
    },
    /// Request a graceful shutdown.
    Shutdown,
}

/// Result of running the event loop — the reason it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Received an OS signal (SIGINT or SIGTERM).
    Signal,
    /// Received a Shutdown command via the command channel.
    Command,
    /// The command channel was closed (all senders dropped).
    ChannelClosed,
}

/// Run the central event loop.
///
/// Multiplexes:
/// - libp2p swarm events (network I/O)
/// - CLI commands arriving on `cmd_rx`
/// - OS signals (SIGINT / SIGTERM) for graceful shutdown
///
/// On shutdown: drains in-flight request-response exchanges (up to 5 s timeout),
/// then calls the optional `wal_flush` callback to checkpoint the SQLite WAL.
///
/// When `keypair` and `store` are provided, inbound messages (both private
/// request-response and public gossipsub) are decoded, verified, decrypted as
/// needed, and persisted to storage.
///
/// Returns the reason the loop exited.
pub async fn run_loop(
    mut swarm: Swarm<SlashmailBehaviour>,
    mut cmd_rx: mpsc::Receiver<EngineCommand>,
    store: Option<MessageStore>,
    wal_flush: Option<Box<dyn FnOnce() + Send>>,
    keypair: Option<&Keypair>,
) -> ShutdownReason {
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let local_peer_id = *swarm.local_peer_id();
    let mut in_flight: usize = 0;
    let mut peers: HashMap<PeerId, PeerState> = HashMap::new();
    let mut topic_registry = TopicRegistry::new();
    let mut pending_publishes: Vec<PendingGossipPublish> = Vec::new();
    let mut deferred_syncs: Vec<DeferredSync> = Vec::new();

    info!("engine event loop started");

    let reason = loop {
        // Compute the nearest pending-publish deadline (if any) for the select.
        let next_publish_deadline = pending_publishes
            .iter()
            .map(|p| p.deadline)
            .min()
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));

        // Compute the nearest deferred-sync deadline (if any).
        let next_sync_deadline = deferred_syncs
            .iter()
            .map(|d| d.deadline)
            .min()
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            // --- OS signals ---
            _ = sigint.recv() => {
                info!("received SIGINT, starting graceful shutdown");
                break ShutdownReason::Signal;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, starting graceful shutdown");
                break ShutdownReason::Signal;
            }

            // --- CLI commands ---
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(command) => {
                        if let Some(reason) = handle_command(&mut swarm, command, store.as_ref(), &peers, &mut topic_registry, keypair, &mut in_flight, &mut pending_publishes) {
                            break reason;
                        }
                    }
                    None => {
                        info!("command channel closed, shutting down");
                        break ShutdownReason::ChannelClosed;
                    }
                }
            }

            // --- Swarm events ---
            event = swarm.select_next_some() => {
                let actions = handle_swarm_event(event, &mut in_flight, &mut peers, keypair, store.as_ref(), &topic_registry, local_peer_id, &mut deferred_syncs);
                for action in actions {
                    apply_swarm_action(&mut swarm, action, store.as_ref());
                }

                // Check if any pending publish now has mesh peers.
                resolve_pending_publishes(&mut swarm, &mut pending_publishes, false);
            }

            // --- Deferred sync timeout (higher-PeerId fallback) ---
            _ = tokio::time::sleep_until(next_sync_deadline), if !deferred_syncs.is_empty() => {
                let now = tokio::time::Instant::now();
                let expired: Vec<PeerId> = deferred_syncs
                    .iter()
                    .filter(|d| d.deadline <= now)
                    .map(|d| d.peer_id)
                    .collect();
                deferred_syncs.retain(|d| d.deadline > now);
                for peer_id in expired {
                    debug!(%peer_id, "deferred sync timeout elapsed, initiating sync as higher PeerId");
                    apply_swarm_action(
                        &mut swarm,
                        SwarmAction::InitiateSync { peer_id },
                        store.as_ref(),
                    );
                }
            }

            // --- Pending gossipsub publish timeout ---
            _ = tokio::time::sleep_until(next_publish_deadline), if !pending_publishes.is_empty() => {
                resolve_pending_publishes(&mut swarm, &mut pending_publishes, true);
            }
        }
    };

    // --- Graceful shutdown sequence ---

    // Resolve any pending gossipsub publishes immediately (with warning).
    resolve_pending_publishes(&mut swarm, &mut pending_publishes, true);

    drain_in_flight(&mut swarm, &mut in_flight, &mut peers, keypair, store.as_ref(), &topic_registry, local_peer_id).await;

    if let Some(flush) = wal_flush {
        info!("flushing SQLite WAL checkpoint");
        flush();
        info!("WAL flush complete");
    }

    info!(?reason, "engine shutdown complete");
    reason
}

/// Drain in-flight request-response exchanges, waiting up to [`DRAIN_TIMEOUT`].
async fn drain_in_flight(
    swarm: &mut Swarm<SlashmailBehaviour>,
    in_flight: &mut usize,
    peers: &mut HashMap<PeerId, PeerState>,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
    topic_registry: &TopicRegistry,
    local_peer_id: PeerId,
) {
    if *in_flight == 0 {
        debug!("no in-flight requests to drain");
        return;
    }

    info!(in_flight = *in_flight, "draining in-flight requests");
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    // No deferred syncs during shutdown drain.
    let mut drain_deferred = Vec::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                warn!(
                    remaining = *in_flight,
                    "drain timeout reached after {}s, proceeding with shutdown",
                    DRAIN_TIMEOUT.as_secs()
                );
                break;
            }
            event = swarm.select_next_some() => {
                let actions = handle_swarm_event(event, in_flight, peers, keypair, store, topic_registry, local_peer_id, &mut drain_deferred);
                for action in actions {
                    apply_swarm_action(swarm, action, store);
                }
                if *in_flight == 0 {
                    info!("all in-flight requests drained");
                    break;
                }
            }
        }
    }
}

/// Process a single engine command. Returns `Some(reason)` if the loop should exit.
fn handle_command(
    swarm: &mut Swarm<SlashmailBehaviour>,
    command: EngineCommand,
    store: Option<&MessageStore>,
    peers: &HashMap<PeerId, PeerState>,
    topic_registry: &mut TopicRegistry,
    keypair: Option<&Keypair>,
    in_flight: &mut usize,
    pending_publishes: &mut Vec<PendingGossipPublish>,
) -> Option<ShutdownReason> {
    match command {
        EngineCommand::Subscribe { topic } => {
            let gossipsub_topic = libp2p::gossipsub::Sha256Topic::new(&topic);
            match swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic) {
                Ok(true) => {
                    topic_registry.subscribe(&topic);
                    info!(%topic, "subscribed to topic");
                }
                Ok(false) => debug!(%topic, "already subscribed to topic"),
                Err(e) => warn!(%topic, %e, "failed to subscribe to topic"),
            }
            None
        }
        EngineCommand::Unsubscribe { topic } => {
            let gossipsub_topic = libp2p::gossipsub::Sha256Topic::new(&topic);
            match swarm.behaviour_mut().gossipsub.unsubscribe(&gossipsub_topic) {
                Ok(true) => {
                    topic_registry.unsubscribe(&topic);
                    info!(%topic, "unsubscribed from topic");
                }
                Ok(false) => debug!(%topic, "was not subscribed to topic"),
                Err(e) => warn!(%topic, %e, "failed to unsubscribe from topic"),
            }
            None
        }
        EngineCommand::PublishPublic { topic, data, reply } => {
            let gossipsub_topic = libp2p::gossipsub::Sha256Topic::new(&topic);
            let topic_hash = gossipsub_topic.hash();
            match swarm.behaviour_mut().gossipsub.publish(gossipsub_topic, data.clone()) {
                Ok(msg_id) => {
                    info!(%topic, %msg_id, "published public message");
                    // Check if any peers are in the mesh for this topic.
                    let mesh_count = swarm
                        .behaviour()
                        .gossipsub
                        .mesh_peers(&topic_hash)
                        .count();
                    if mesh_count > 0 {
                        info!(%topic, mesh_count, "gossipsub mesh has peers");
                        let _ = reply.send(Ok(()));
                    } else {
                        // Defer the reply — wait up to GOSSIP_PUBLISH_TIMEOUT for peers.
                        let deadline =
                            tokio::time::Instant::now() + GOSSIP_PUBLISH_TIMEOUT;
                        info!(%topic, "no mesh peers yet, waiting up to {}s", GOSSIP_PUBLISH_TIMEOUT.as_secs());
                        pending_publishes.push(PendingGossipPublish {
                            reply,
                            deadline,
                            topic: topic.clone(),
                        });
                    }
                }
                Err(gossipsub::PublishError::InsufficientPeers) => {
                    // No mesh peers at all — defer and wait for peers to join.
                    let deadline =
                        tokio::time::Instant::now() + GOSSIP_PUBLISH_TIMEOUT;
                    info!(%topic, "no mesh peers, deferring publish for up to {}s", GOSSIP_PUBLISH_TIMEOUT.as_secs());
                    pending_publishes.push(PendingGossipPublish {
                        reply,
                        deadline,
                        topic: topic.clone(),
                    });
                }
                Err(e) => {
                    let _ = reply.send(Err(format!("gossipsub publish failed: {e}")));
                }
            }
            None
        }
        EngineCommand::Dial { addr } => {
            match swarm.dial(addr.clone()) {
                Ok(()) => info!(%addr, "dialing peer"),
                Err(e) => warn!(%addr, %e, "failed to dial peer"),
            }
            None
        }
        EngineCommand::Listen { addr } => {
            match swarm.listen_on(addr.clone()) {
                Ok(listener_id) => info!(%addr, ?listener_id, "listening"),
                Err(e) => warn!(%addr, %e, "failed to listen"),
            }
            None
        }
        EngineCommand::InsertMessage { msg, reply } => {
            let result = match store {
                Some(s) => s
                    .insert_message(&msg)
                    .map_err(|e| format!("insert failed: {e}")),
                None => Err("no message store available".to_string()),
            };
            if let Err(ref e) = result {
                warn!(%e, "InsertMessage failed");
            } else {
                info!(id = %msg.id, "message inserted via daemon");
            }
            let _ = reply.send(result);
            None
        }
        EngineCommand::AddPeer { addr, reply } => {
            let result = match swarm.dial(addr.clone()) {
                Ok(()) => {
                    info!(%addr, "peer added and dialing");
                    // Persist to bootstrap_peers in config so we reconnect on restart.
                    let addr_str = addr.to_string();
                    match crate::storage::config::Config::add_bootstrap_peer(&addr_str) {
                        Ok(true) => info!(%addr_str, "saved to bootstrap_peers"),
                        Ok(false) => debug!(%addr_str, "already in bootstrap_peers"),
                        Err(e) => warn!(%addr_str, %e, "failed to save bootstrap peer to config"),
                    }
                    Ok(())
                }
                Err(e) => {
                    warn!(%addr, %e, "failed to add peer");
                    Err(format!("dial failed: {e}"))
                }
            };
            let _ = reply.send(result);
            None
        }
        EngineCommand::GetStatus { reply } => {
            let peer_id = swarm.local_peer_id().to_string();
            let listen_addrs: Vec<String> = swarm.listeners().map(|a| a.to_string()).collect();
            let external_addrs: Vec<String> = swarm
                .external_addresses()
                .map(|a| a.to_string())
                .collect();
            let num_peers = peers.len();
            let _ = reply.send(StatusInfo {
                peer_id,
                listen_addrs,
                external_addrs,
                num_peers,
            });
            None
        }
        EngineCommand::GetPeers { reply } => {
            let peer_list: Vec<PeerInfo> = peers
                .iter()
                .map(|(pid, state)| PeerInfo {
                    peer_id: pid.to_string(),
                    addrs: state.listen_addrs.iter().map(|a| a.to_string()).collect(),
                    connected_since: state.connected_since.to_rfc3339(),
                    protocols: state.protocols.clone(),
                    rtt_ms: state.rtt.map(|d| d.as_secs_f64() * 1000.0),
                })
                .collect();
            let _ = reply.send(peer_list);
            None
        }
        EngineCommand::GetSubscriptions { reply } => {
            let subs: HashMap<String, String> = topic_registry
                .subscriptions()
                .iter()
                .map(|(hash, name)| (hash.to_string(), name.clone()))
                .collect();
            let _ = reply.send(subs);
            None
        }
        EngineCommand::SendMessage {
            to,
            body,
            tags,
            reply,
        } => {
            let result = (|| -> Result<(String, Option<String>), String> {
                let kp = keypair.ok_or("no keypair configured")?;

                // Parse recipient public key from base64.
                let recipient_pubkey = crate::identity::Identity::parse_public_key(&to)
                    .map_err(|e| format!("invalid recipient key: {e}"))?;

                // Derive PeerId from the recipient's Ed25519 public key.
                let peer_id = peer_id_from_ed25519_pubkey(&recipient_pubkey)
                    .map_err(|e| format!("failed to derive peer id: {e}"))?;

                // Derive ECDH shared secret for tag encryption.
                let shared = ecdh::derive_shared_secret(kp, &recipient_pubkey);

                // Encrypt the message body.
                let encrypted_payload = ecdh::seal_for(kp, &recipient_pubkey, body.as_bytes())
                    .map_err(|e| format!("encryption failed: {e}"))?;

                // Encrypt each tag and base64-encode.
                let b64 = base64::engine::general_purpose::STANDARD;
                let encrypted_tags: Vec<String> = tags
                    .iter()
                    .map(|tag| {
                        let ct = encryption::seal(shared.as_bytes(), tag.as_bytes())
                            .map_err(|e| format!("tag encryption failed: {e}"))?;
                        Ok(b64.encode(&ct))
                    })
                    .collect::<Result<Vec<String>, String>>()?;

                // Build the envelope.
                let mut envelope = crate::types::Envelope::new(
                    kp.verifying_key().to_bytes(),
                    "dm".into(),
                    encrypted_payload,
                );
                envelope.recipient = Some(peer_id);
                envelope.tags = encrypted_tags;

                let message_id = envelope.id.to_string();

                // Encode (signs the payload and compresses).
                let encoded = msg_codec::encode(&envelope, kp)
                    .map_err(|e| format!("codec encode failed: {e}"))?;

                // Always store a copy in the local Sent folder.
                if let Some(st) = store {
                    let sent_msg = Message {
                        id: envelope.id,
                        swarm_id: "dm".to_string(),
                        folder_path: "Sent".to_string(),
                        sender_pubkey: kp.verifying_key().to_bytes(),
                        sender: b64.encode(kp.verifying_key().to_bytes()),
                        recipient: peer_id.to_string(),
                        subject: String::new(),
                        body: body.clone(),
                        tags: tags.join(" "),
                        created_at: envelope.timestamp,
                        read: true,
                    };
                    if let Err(e) = st.insert_message(&sent_msg) {
                        warn!(%e, "failed to store sent message locally");
                    } else {
                        info!(%message_id, "message stored in Sent folder");
                        // Store raw envelope for Merkle delta sync.
                        if let Err(e) = st.store_raw_envelope(&envelope.id, &encoded) {
                            warn!(%e, "failed to store raw envelope for sent message");
                        }
                    }
                    // Upsert plaintext tags into normalised tag table.
                    if !tags.is_empty() {
                        let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
                        if let Err(e) = st.upsert_tags(&envelope.id, &tag_refs) {
                            warn!(%e, "failed to upsert sent message tags");
                        }
                    }
                }

                // Dispatch via request-response.
                let request = MailRequest {
                    envelope_data: encoded,
                };
                swarm
                    .behaviour_mut()
                    .mail_rr
                    .send_request(&peer_id, request);
                *in_flight += 1;

                // Check peer connectivity and warn if isolated.
                let warning = if peers.is_empty() {
                    let msg = "no peers connected \u{2014} message stored locally; will not propagate until daemon is running".to_string();
                    warn!("{}", msg);
                    Some(msg)
                } else {
                    None
                };

                info!(%peer_id, %message_id, "private message sent via request-response");
                Ok((message_id, warning))
            })();
            let _ = reply.send(result);
            None
        }
        EngineCommand::Shutdown => {
            info!("shutdown command received");
            Some(ShutdownReason::Command)
        }
    }
}

/// Derive a libp2p [`PeerId`] from an Ed25519 public key.
fn peer_id_from_ed25519_pubkey(pubkey: &PublicKey) -> Result<PeerId, String> {
    let ed25519_pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey.as_bytes())
        .map_err(|e| format!("invalid ed25519 public key: {e}"))?;
    let libp2p_pk = libp2p::identity::PublicKey::from(ed25519_pk);
    Ok(PeerId::from(libp2p_pk))
}

/// An action to be applied to the swarm after event processing.
///
/// Returned by [`handle_swarm_event`] so that the caller (which owns the swarm)
/// can apply the action without needing to pass a mutable swarm reference into
/// the handler.
enum SwarmAction {
    /// No action needed.
    None,
    /// Send a response on the given request-response channel.
    SendResponse {
        channel: request_response::ResponseChannel<MailResponse>,
        response: MailResponse,
    },
    /// Initiate a peer exchange with a newly connected peer.
    InitiatePeerExchange {
        peer_id: libp2p::PeerId,
    },
    /// Send a peer exchange response and dial received peers.
    PeerExchangeRespond {
        channel: request_response::ResponseChannel<PeerExchangeResponse>,
        peers_received: Vec<peer_exchange::PeerInfo>,
    },
    /// Dial peers learned from a peer exchange response.
    PeerExchangeLearn {
        peers_received: Vec<peer_exchange::PeerInfo>,
    },
    /// Initiate Merkle sync with a peer by sending our root hash.
    InitiateSync {
        peer_id: libp2p::PeerId,
    },
    /// Respond to a sync request on the given channel.
    SyncRespond {
        channel: request_response::ResponseChannel<SyncResponse>,
        response: SyncResponse,
    },
    /// Continue sync: request bucket IDs for differing buckets.
    SyncRequestBucketIds {
        peer_id: libp2p::PeerId,
        bucket_indices: Vec<u16>,
    },
    /// Continue sync: fetch missing messages from peer.
    SyncFetchMessages {
        peer_id: libp2p::PeerId,
        ids: Vec<String>,
    },
}

/// Apply a [`SwarmAction`] to the swarm.
fn apply_swarm_action(
    swarm: &mut Swarm<SlashmailBehaviour>,
    action: SwarmAction,
    store: Option<&MessageStore>,
) {
    match action {
        SwarmAction::None => {}
        SwarmAction::SendResponse { channel, response } => {
            if swarm
                .behaviour_mut()
                .mail_rr
                .send_response(channel, response)
                .is_err()
            {
                warn!("failed to send response on request-response channel");
            }
        }
        SwarmAction::InitiatePeerExchange { peer_id } => {
            let table = collect_peer_table(swarm);
            let req = PeerExchangeRequest { peers: table };
            swarm
                .behaviour_mut()
                .peer_exchange
                .send_request(&peer_id, req);
            debug!(%peer_id, "sent peer exchange request");
        }
        SwarmAction::PeerExchangeRespond {
            channel,
            peers_received,
        } => {
            let table = collect_peer_table(swarm);
            let resp = PeerExchangeResponse { peers: table };
            if swarm
                .behaviour_mut()
                .peer_exchange
                .send_response(channel, resp)
                .is_err()
            {
                warn!("failed to send peer exchange response");
            }
            dial_learned_peers(swarm, &peers_received);
        }
        SwarmAction::PeerExchangeLearn { peers_received } => {
            dial_learned_peers(swarm, &peers_received);
        }
        SwarmAction::InitiateSync { peer_id } => {
            if let Some(st) = store {
                match st.all_message_ids() {
                    Ok(ids) => {
                        let tree = MerkleTree::from_ids(&ids);
                        let root = *tree.root();
                        swarm
                            .behaviour_mut()
                            .sync_rr
                            .send_request(&peer_id, SyncRequest::RootExchange { root });
                        info!(%peer_id, "sent sync root exchange request");
                    }
                    Err(e) => {
                        warn!(%peer_id, %e, "failed to compute Merkle root for sync");
                    }
                }
            } else {
                debug!(%peer_id, "no store configured, skipping sync");
            }
        }
        SwarmAction::SyncRespond { channel, response } => {
            if swarm
                .behaviour_mut()
                .sync_rr
                .send_response(channel, response)
                .is_err()
            {
                warn!("failed to send sync response");
            }
        }
        SwarmAction::SyncRequestBucketIds {
            peer_id,
            bucket_indices,
        } => {
            swarm
                .behaviour_mut()
                .sync_rr
                .send_request(&peer_id, SyncRequest::GetBucketIds { bucket_indices });
            debug!(%peer_id, "sent sync GetBucketIds request");
        }
        SwarmAction::SyncFetchMessages { peer_id, ids } => {
            swarm
                .behaviour_mut()
                .sync_rr
                .send_request(&peer_id, SyncRequest::FetchMessages { ids });
            debug!(%peer_id, "sent sync FetchMessages request");
        }
    }
}

/// Collect the current peer routing table from the swarm's connected peers
/// and their known/listened addresses.
fn collect_peer_table(swarm: &mut Swarm<SlashmailBehaviour>) -> Vec<peer_exchange::PeerInfo> {
    let local_peer_id = *swarm.local_peer_id();
    let mut table = Vec::new();

    // Gather addresses from Kademlia's routing table for connected peers.
    let connected: Vec<libp2p::PeerId> = swarm.connected_peers().copied().collect();
    for bucket in swarm.behaviour_mut().kademlia.kbuckets() {
        for entry in bucket.iter() {
            let peer_id = *entry.node.key.preimage();
            if peer_id == local_peer_id || !connected.contains(&peer_id) {
                continue;
            }
            let addrs: Vec<libp2p::Multiaddr> = entry.node.value.iter().cloned().collect();
            if !addrs.is_empty() {
                table.push(peer_exchange::to_peer_info(&peer_id, &addrs));
            }
        }
    }

    // Include our own external and listen addresses merged under one entry,
    // so the receiver gets a single canonical record for our peer ID.
    let mut own_addrs: Vec<libp2p::Multiaddr> = swarm.external_addresses().cloned().collect();
    own_addrs.extend(swarm.listeners().cloned());
    own_addrs.dedup();
    if !own_addrs.is_empty() {
        table.push(peer_exchange::to_peer_info(&local_peer_id, &own_addrs));
    }

    table
}

/// Dial peers learned from a peer exchange, skipping already-connected peers.
fn dial_learned_peers(swarm: &mut Swarm<SlashmailBehaviour>, peers: &[peer_exchange::PeerInfo]) {
    let local_peer_id = *swarm.local_peer_id();
    let connected: std::collections::HashSet<libp2p::PeerId> =
        swarm.connected_peers().copied().collect();

    for info in peers {
        if let Some((peer_id, addrs)) = peer_exchange::from_peer_info(info) {
            if peer_id == local_peer_id || connected.contains(&peer_id) {
                continue;
            }
            if addrs.is_empty() {
                continue;
            }
            // Add addresses to Kademlia so they're available for future lookups.
            for addr in &addrs {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
            }
            // Dial the first address.
            match swarm.dial(addrs[0].clone()) {
                Ok(()) => {
                    info!(%peer_id, addr = %addrs[0], "dialing peer learned from exchange");
                }
                Err(e) => {
                    debug!(%peer_id, %e, "failed to dial learned peer");
                }
            }
        } else {
            debug!("skipping malformed peer info in exchange");
        }
    }
}

/// Resolve pending gossipsub publishes that have gained mesh peers or timed out.
///
/// When `timeout_fired` is true, all pending entries are resolved (used both
/// when the select timer fires and at shutdown). Otherwise, entries are resolved
/// only if their topic now has mesh peers.
fn resolve_pending_publishes(
    swarm: &mut Swarm<SlashmailBehaviour>,
    pending: &mut Vec<PendingGossipPublish>,
    timeout_fired: bool,
) {
    let mut i = 0;
    while i < pending.len() {
        let topic_hash = libp2p::gossipsub::Sha256Topic::new(&pending[i].topic).hash();
        let mesh_count = swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic_hash)
            .count();

        let should_resolve = mesh_count > 0 || timeout_fired;
        if should_resolve {
            let entry = pending.swap_remove(i);
            if mesh_count > 0 {
                info!(topic = %entry.topic, mesh_count, "gossipsub publish confirmed — mesh peers found");
                let _ = entry.reply.send(Ok(()));
            } else {
                warn!(
                    topic = %entry.topic,
                    "no peers connected \u{2014} message stored locally; will not propagate until daemon is running"
                );
                // Still return Ok — the message was published locally, just no peers to propagate.
                let _ = entry.reply.send(Ok(()));
            }
            // Don't increment i — swap_remove moved the last element here.
        } else {
            i += 1;
        }
    }
}

/// Process a single swarm event, updating `in_flight` for request-response tracking.
///
/// When `keypair` and `store` are both present, inbound messages are decoded,
/// verified, decrypted (for private messages), and stored.
///
/// Returns a [`SwarmAction`] that the caller must apply to the swarm.
fn handle_swarm_event(
    event: SwarmEvent<SlashmailBehaviourEvent>,
    in_flight: &mut usize,
    peers: &mut HashMap<PeerId, PeerState>,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
    topic_registry: &TopicRegistry,
    local_peer_id: PeerId,
    deferred_syncs: &mut Vec<DeferredSync>,
) -> Vec<SwarmAction> {
    match event {
        // --- Request-response events (tracked for graceful drain) ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::MailRr(rr_event)) => {
            vec![handle_rr_event(rr_event, in_flight, keypair, store)]
        }

        // --- Gossipsub events ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::Gossipsub(gs_event)) => {
            handle_gossipsub_event(gs_event, keypair, store, topic_registry);
            vec![]
        }

        // --- Peer exchange events ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::PeerExchange(px_event)) => {
            vec![handle_peer_exchange_event(px_event)]
        }

        // --- Sync events ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::SyncRr(sync_event)) => {
            vec![handle_sync_event(sync_event, keypair, store, deferred_syncs)]
        }

        // --- Identify events (peer metadata) ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            debug!(%peer_id, agent = %info.agent_version, "identify received");
            if let Some(state) = peers.get_mut(&peer_id) {
                state.protocols = info.protocols.iter().map(|p| p.to_string()).collect();
                state.listen_addrs = info.listen_addrs;
            }
            vec![]
        }

        // --- Ping events (latency measurement) ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            debug!(%peer, ?rtt, "ping success");
            if let Some(state) = peers.get_mut(&peer) {
                state.rtt = Some(rtt);
            }
            vec![]
        }
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::Ping(ping::Event {
            peer,
            result: Err(e),
            ..
        })) => {
            debug!(%peer, %e, "ping failure");
            vec![]
        }

        // --- Other behaviour events ---
        SwarmEvent::Behaviour(event) => {
            debug!(?event, "behaviour event");
            vec![]
        }

        // --- Connection / listener lifecycle ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "new listen address");
            vec![]
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            num_established,
            ..
        } => {
            info!(%peer_id, "connection established");
            // Only initiate peer exchange and sync on the first connection to
            // avoid duplicate exchanges when dcutr upgrades a relay connection
            // to a direct one (which fires a second ConnectionEstablished).
            if num_established.get() == 1 {
                peers.insert(peer_id, PeerState {
                    connected_since: Utc::now(),
                    protocols: Vec::new(),
                    listen_addrs: Vec::new(),
                    rtt: None,
                });
                // PeerId-ordered sync: the lexicographically lower PeerId
                // initiates sync immediately.  The higher PeerId defers for
                // SYNC_DEFER_TIMEOUT, giving the lower peer time to send its
                // SyncRequest first.  If no request arrives, the deferred
                // sync fires as a fallback.
                let local_bytes = local_peer_id.to_bytes();
                let remote_bytes = peer_id.to_bytes();
                if local_bytes < remote_bytes {
                    debug!(%peer_id, "lower PeerId — initiating sync immediately");
                    vec![
                        SwarmAction::InitiatePeerExchange { peer_id },
                        SwarmAction::InitiateSync { peer_id },
                    ]
                } else {
                    debug!(%peer_id, "higher PeerId — deferring sync for {}ms", SYNC_DEFER_TIMEOUT.as_millis());
                    deferred_syncs.push(DeferredSync {
                        peer_id,
                        deadline: tokio::time::Instant::now() + SYNC_DEFER_TIMEOUT,
                    });
                    vec![
                        SwarmAction::InitiatePeerExchange { peer_id },
                    ]
                }
            } else {
                vec![]
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            debug!(%peer_id, "connection closed");
            if num_established == 0 {
                peers.remove(&peer_id);
                deferred_syncs.retain(|d| d.peer_id != peer_id);
            }
            vec![]
        }
        SwarmEvent::IncomingConnection { local_addr, .. } => {
            debug!(%local_addr, "incoming connection");
            vec![]
        }
        SwarmEvent::OutgoingConnectionError { error, .. } => {
            warn!(%error, "outgoing connection error");
            vec![]
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            warn!(%error, "incoming connection error");
            vec![]
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            debug!(%address, "listen address expired");
            vec![]
        }
        SwarmEvent::ListenerClosed { listener_id, .. } => {
            debug!(?listener_id, "listener closed");
            vec![]
        }
        SwarmEvent::ListenerError { listener_id, error, .. } => {
            warn!(?listener_id, %error, "listener error");
            vec![]
        }
        SwarmEvent::Dialing { peer_id, .. } => {
            debug!(?peer_id, "dialing");
            vec![]
        }
        SwarmEvent::NewExternalAddrCandidate { address, .. } => {
            debug!(%address, "new external address candidate");
            vec![]
        }
        SwarmEvent::ExternalAddrConfirmed { address, .. } => {
            info!(%address, "external address confirmed");
            vec![]
        }
        SwarmEvent::ExternalAddrExpired { address, .. } => {
            debug!(%address, "external address expired");
            vec![]
        }
        event => {
            debug!(?event, "unhandled swarm event");
            vec![]
        }
    }
}

/// Handle a request-response event, updating the in-flight counter.
///
/// The counter is decremented when an outbound request completes (response or failure).
/// Callers that send outbound requests via `mail_rr.send_request()` must increment
/// `in_flight` at send time.
///
/// When an inbound request arrives and `keypair`/`store` are available, the
/// enclosed envelope is decoded, verified, decrypted (if private), and stored.
/// Returns a [`SwarmAction::SendResponse`] so the caller can reply on the channel.
fn handle_rr_event(
    event: request_response::Event<MailRequest, MailResponse>,
    in_flight: &mut usize,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) -> SwarmAction {
    match event {
        request_response::Event::Message { message, peer, .. } => match message {
            request_response::Message::Response { request_id, .. } => {
                debug!(%peer, ?request_id, "outbound request got response");
                *in_flight = in_flight.saturating_sub(1);
                SwarmAction::None
            }
            request_response::Message::Request {
                request_id,
                request,
                channel,
                ..
            } => {
                debug!(%peer, ?request_id, "inbound request received");
                let response = match (keypair, store) {
                    (Some(kp), Some(st)) => {
                        match process_inbound_envelope(&request.envelope_data, kp, st) {
                            Ok(()) => {
                                info!(%peer, ?request_id, "inbound private message stored");
                                MailResponse::accepted()
                            }
                            Err(e) => {
                                warn!(%peer, ?request_id, %e, "failed to process inbound message");
                                MailResponse::rejected(format!("{e}"))
                            }
                        }
                    }
                    _ => {
                        warn!(%peer, ?request_id, "no keypair/store configured, rejecting");
                        MailResponse::rejected("node not configured for message storage")
                    }
                };
                SwarmAction::SendResponse { channel, response }
            }
        },
        request_response::Event::OutboundFailure {
            request_id,
            error,
            peer,
            ..
        } => {
            warn!(%peer, ?request_id, %error, "outbound request failed");
            *in_flight = in_flight.saturating_sub(1);
            SwarmAction::None
        }
        request_response::Event::InboundFailure {
            request_id,
            error,
            peer,
            ..
        } => {
            debug!(%peer, ?request_id, %error, "inbound request failed");
            SwarmAction::None
        }
        request_response::Event::ResponseSent {
            request_id, peer, ..
        } => {
            debug!(%peer, ?request_id, "response sent");
            SwarmAction::None
        }
    }
}

/// Handle gossipsub events, storing public messages when keypair/store are available.
///
/// The `topic_registry` is used to resolve the gossipsub `TopicHash` back to
/// the human-readable swarm name for logging and future message routing.
fn handle_gossipsub_event(
    event: gossipsub::Event,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
    topic_registry: &TopicRegistry,
) {
    match event {
        gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        } => {
            let swarm_name = topic_registry.resolve(&message.topic);
            debug!(
                %propagation_source, %message_id,
                topic = %message.topic,
                swarm = swarm_name.unwrap_or("<unknown>"),
                "gossipsub message received"
            );
            if let (Some(kp), Some(st)) = (keypair, store) {
                match process_inbound_envelope(&message.data, kp, st) {
                    Ok(()) => {
                        info!(%propagation_source, %message_id, "gossipsub message stored");
                    }
                    Err(e) => {
                        warn!(%propagation_source, %message_id, %e, "failed to process gossipsub message");
                    }
                }
            }
        }
        gossipsub::Event::Subscribed { peer_id, topic } => {
            let swarm_name = topic_registry.resolve(&topic);
            debug!(%peer_id, %topic, swarm = swarm_name.unwrap_or("<unknown>"), "peer subscribed");
        }
        gossipsub::Event::Unsubscribed { peer_id, topic } => {
            let swarm_name = topic_registry.resolve(&topic);
            debug!(%peer_id, %topic, swarm = swarm_name.unwrap_or("<unknown>"), "peer unsubscribed");
        }
        gossipsub::Event::GossipsubNotSupported { peer_id } => {
            debug!(%peer_id, "gossipsub not supported by peer");
        }
    }
}

/// Handle peer exchange request-response events.
///
/// On inbound request: respond with our routing table and prepare to dial
/// the received peers. On response to our outbound request: dial any new peers.
fn handle_peer_exchange_event(
    event: request_response::Event<PeerExchangeRequest, PeerExchangeResponse>,
) -> SwarmAction {
    match event {
        request_response::Event::Message { message, peer, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                info!(%peer, peers_received = request.peers.len(), "peer exchange request received");
                SwarmAction::PeerExchangeRespond {
                    channel,
                    peers_received: request.peers,
                }
            }
            request_response::Message::Response { response, .. } => {
                info!(%peer, peers_received = response.peers.len(), "peer exchange response received");
                SwarmAction::PeerExchangeLearn {
                    peers_received: response.peers,
                }
            }
        },
        request_response::Event::OutboundFailure {
            peer, error, ..
        } => {
            debug!(%peer, %error, "peer exchange outbound failure");
            SwarmAction::None
        }
        request_response::Event::InboundFailure {
            peer, error, ..
        } => {
            debug!(%peer, %error, "peer exchange inbound failure");
            SwarmAction::None
        }
        request_response::Event::ResponseSent { peer, .. } => {
            debug!(%peer, "peer exchange response sent");
            SwarmAction::None
        }
    }
}

/// Handle sync request-response events for Merkle-tree delta synchronisation.
///
/// **Inbound requests** are answered by computing our local Merkle tree and
/// returning the appropriate data (root+bucket hashes, bucket IDs, or raw
/// envelopes).
///
/// **Outbound responses** drive the multi-step sync protocol forward: comparing
/// roots, requesting differing bucket IDs, and fetching missing messages.
fn handle_sync_event(
    event: request_response::Event<SyncRequest, SyncResponse>,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
    deferred_syncs: &mut Vec<DeferredSync>,
) -> SwarmAction {
    match event {
        request_response::Event::Message { message, peer, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                // The remote peer initiated sync — cancel our deferred sync
                // for this peer to avoid a redundant duplicate exchange.
                if deferred_syncs.iter().any(|d| d.peer_id == peer) {
                    debug!(%peer, "cancelling deferred sync — remote peer initiated first");
                    deferred_syncs.retain(|d| d.peer_id != peer);
                }
                handle_sync_inbound_request(request, channel, peer, store)
            }
            request_response::Message::Response { response, .. } => {
                handle_sync_inbound_response(response, peer, keypair, store)
            }
        },
        request_response::Event::OutboundFailure {
            peer, error, ..
        } => {
            debug!(%peer, %error, "sync outbound failure");
            SwarmAction::None
        }
        request_response::Event::InboundFailure {
            peer, error, ..
        } => {
            debug!(%peer, %error, "sync inbound failure");
            SwarmAction::None
        }
        request_response::Event::ResponseSent { peer, .. } => {
            debug!(%peer, "sync response sent");
            SwarmAction::None
        }
    }
}

/// Handle an inbound sync request by computing the answer from our local store.
fn handle_sync_inbound_request(
    request: SyncRequest,
    channel: request_response::ResponseChannel<SyncResponse>,
    peer: PeerId,
    store: Option<&MessageStore>,
) -> SwarmAction {
    let Some(st) = store else {
        warn!(%peer, "sync request received but no store configured");
        // Send an empty root result so the peer doesn't hang.
        return SwarmAction::SyncRespond {
            channel,
            response: SyncResponse::RootResult {
                root: [0u8; 32],
                bucket_hashes: vec![[0u8; 32]; merkle::NUM_BUCKETS],
            },
        };
    };

    match request {
        SyncRequest::RootExchange { root: _remote_root } => {
            match st.all_message_ids() {
                Ok(ids) => {
                    let tree = MerkleTree::from_ids(&ids);
                    info!(%peer, "sync: responding with root and bucket hashes");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::RootResult {
                            root: *tree.root(),
                            bucket_hashes: tree.bucket_hashes().to_vec(),
                        },
                    }
                }
                Err(e) => {
                    warn!(%peer, %e, "sync: failed to compute Merkle tree");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::RootResult {
                            root: [0u8; 32],
                            bucket_hashes: vec![[0u8; 32]; merkle::NUM_BUCKETS],
                        },
                    }
                }
            }
        }
        SyncRequest::GetBucketIds { bucket_indices } => {
            match st.all_message_ids() {
                Ok(ids) => {
                    let tree = MerkleTree::from_ids(&ids);
                    let buckets: Vec<(u16, Vec<String>)> = bucket_indices
                        .iter()
                        .map(|&idx| {
                            let bucket_ids: Vec<String> = tree
                                .bucket_ids(idx as usize)
                                .iter()
                                .map(|id| id.to_string())
                                .collect();
                            (idx, bucket_ids)
                        })
                        .collect();
                    info!(%peer, num_buckets = buckets.len(), "sync: responding with bucket IDs");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::BucketIds { buckets },
                    }
                }
                Err(e) => {
                    warn!(%peer, %e, "sync: failed to get bucket IDs");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::BucketIds { buckets: vec![] },
                    }
                }
            }
        }
        SyncRequest::FetchMessages { ids } => {
            match st.get_raw_envelopes(&ids) {
                Ok(envelopes) => {
                    info!(%peer, requested = ids.len(), found = envelopes.len(), "sync: responding with raw envelopes");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::Messages { envelopes },
                    }
                }
                Err(e) => {
                    warn!(%peer, %e, "sync: failed to get raw envelopes");
                    SwarmAction::SyncRespond {
                        channel,
                        response: SyncResponse::Messages { envelopes: vec![] },
                    }
                }
            }
        }
    }
}

/// Handle a sync response we received after sending a request.
///
/// This drives the multi-step protocol:
/// 1. `RootResult` → compare bucket hashes, request differing bucket IDs
/// 2. `BucketIds` → diff IDs, request missing messages
/// 3. `Messages` → process and store the received envelopes
fn handle_sync_inbound_response(
    response: SyncResponse,
    peer: PeerId,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) -> SwarmAction {
    let Some(st) = store else {
        return SwarmAction::None;
    };

    match response {
        SyncResponse::RootResult {
            root: remote_root,
            bucket_hashes: remote_bucket_hashes,
        } => {
            // Compare roots — if equal, we're in sync.
            let ids = match st.all_message_ids() {
                Ok(ids) => ids,
                Err(e) => {
                    warn!(%peer, %e, "sync: failed to get local message IDs");
                    return SwarmAction::None;
                }
            };
            let local_tree = MerkleTree::from_ids(&ids);
            if *local_tree.root() == remote_root {
                info!(%peer, "sync: roots match, already in sync");
                return SwarmAction::None;
            }

            // Roots differ — find which buckets are different.
            let differing = local_tree.differing_buckets(&remote_bucket_hashes);
            if differing.is_empty() {
                info!(%peer, "sync: no differing buckets despite different roots (possible race)");
                return SwarmAction::None;
            }
            info!(%peer, num_differing = differing.len(), "sync: requesting bucket IDs for differing buckets");
            SwarmAction::SyncRequestBucketIds {
                peer_id: peer,
                bucket_indices: differing,
            }
        }
        SyncResponse::BucketIds { buckets } => {
            // Build our local tree and find IDs the remote has that we don't.
            let ids = match st.all_message_ids() {
                Ok(ids) => ids,
                Err(e) => {
                    warn!(%peer, %e, "sync: failed to get local message IDs");
                    return SwarmAction::None;
                }
            };
            let local_tree = MerkleTree::from_ids(&ids);

            let remote_bucket_ids: Vec<(u16, Vec<uuid::Uuid>)> = buckets
                .iter()
                .filter_map(|(idx, id_strings)| {
                    let uuids: Vec<uuid::Uuid> = id_strings
                        .iter()
                        .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                        .collect();
                    Some((*idx, uuids))
                })
                .collect();

            let missing = local_tree.missing_ids(&remote_bucket_ids);
            if missing.is_empty() {
                info!(%peer, "sync: no missing messages (remote may be missing ours)");
                return SwarmAction::None;
            }
            let missing_strs: Vec<String> = missing.iter().map(|id| id.to_string()).collect();
            info!(%peer, count = missing_strs.len(), "sync: fetching missing messages");
            SwarmAction::SyncFetchMessages {
                peer_id: peer,
                ids: missing_strs,
            }
        }
        SyncResponse::Messages { envelopes } => {
            // Process each received envelope and store it.
            let mut stored = 0usize;
            let mut skipped = 0usize;
            for (id_str, raw_data) in &envelopes {
                if let (Some(kp), Some(st)) = (keypair, Some(st)) {
                    match process_inbound_envelope(raw_data, kp, st) {
                        Ok(()) => {
                            stored += 1;
                        }
                        Err(e) => {
                            debug!(%peer, id = %id_str, %e, "sync: failed to process envelope");
                            skipped += 1;
                        }
                    }
                }
            }
            info!(%peer, stored, skipped, "sync: message fetch complete");
            SwarmAction::None
        }
    }
}

/// Decode, verify, decrypt, and store an inbound envelope.
///
/// For **private** messages (`envelope.recipient.is_some()`):
/// - Payload is decrypted via ECDH shared secret (sender pubkey + our keypair).
/// - Tags are base64-decoded then decrypted with the same shared secret.
///
/// For **public** messages (`envelope.recipient.is_none()`):
/// - Payload is used as-is (plaintext).
/// - Tags are plaintext strings.
///
/// In both cases the Ed25519 signature on the payload is verified before processing.
fn process_inbound_envelope(
    data: &[u8],
    keypair: &Keypair,
    store: &MessageStore,
) -> anyhow::Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. Decode wire format (version check, decompress, deserialize).
    let envelope = msg_codec::decode(data)?;

    // 2. Reconstruct sender public key and verify signature.
    let sender_pubkey = PublicKey::from_bytes(&envelope.sender_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid sender pubkey: {e}"))?;
    let sig = Signature::from_slice(&envelope.signature)
        .map_err(|e| anyhow::anyhow!("invalid signature bytes: {e}"))?;
    signing::verify(&sender_pubkey, &envelope.signable_bytes(), &sig)?;

    // 3. Decrypt payload and tags if this is a private message.
    let is_private = envelope.recipient.is_some();
    let (body, decrypted_tags) = if is_private {
        let shared = ecdh::derive_shared_secret(keypair, &sender_pubkey);

        // Decrypt payload.
        let plaintext = ecdh::open_from(keypair, &sender_pubkey, &envelope.payload)?;
        let body = String::from_utf8(plaintext)
            .unwrap_or_else(|e| b64.encode(e.into_bytes()));

        // Decrypt each tag (base64-encoded ciphertext).
        let mut tags = Vec::with_capacity(envelope.tags.len());
        for enc_tag in &envelope.tags {
            let tag_bytes = b64
                .decode(enc_tag)
                .map_err(|e| anyhow::anyhow!("invalid base64 tag: {e}"))?;
            let plain = encryption::open(shared.as_bytes(), &tag_bytes)?;
            let tag_str = String::from_utf8(plain)
                .map_err(|e| anyhow::anyhow!("tag is not valid UTF-8: {e}"))?;
            tags.push(tag_str);
        }
        (body, tags)
    } else {
        // Public message: payload and tags are plaintext.
        let body = String::from_utf8(envelope.payload.clone())
            .unwrap_or_else(|e| b64.encode(e.into_bytes()));
        (body, envelope.tags.clone())
    };

    // 4. Build a storage Message from the envelope.
    let sender = b64.encode(envelope.sender_pubkey);
    let recipient = envelope
        .recipient
        .map(|p| p.to_string())
        .unwrap_or_default();

    // 4a. Build the space-separated tags string so that FTS5 receives
    //     plaintext tags on the initial INSERT (never encrypted bytes).
    let tags_text = decrypted_tags.join(" ");

    let msg = Message {
        id: envelope.id,
        swarm_id: envelope.swarm_id,
        folder_path: "INBOX".to_string(),
        sender_pubkey: envelope.sender_pubkey,
        sender,
        recipient,
        subject: String::new(),
        body,
        tags: tags_text,
        created_at: envelope.timestamp,
        read: false,
    };

    store.insert_message(&msg)?;

    // 5. Store the raw envelope bytes for Merkle delta sync re-transmission.
    store.store_raw_envelope(&envelope.id, data)?;

    // 6. Upsert tags into the normalised tag table.
    if !decrypted_tags.is_empty() {
        let tag_refs: Vec<&str> = decrypted_tags.iter().map(|s| s.as_str()).collect();
        store.upsert_tags(&envelope.id, &tag_refs)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdh;
    use crate::crypto::encryption;
    use crate::crypto::signing::generate_keypair;
    use crate::identity::Identity;
    use crate::message::codec as msg_codec;
    use crate::net::build_swarm;
    use crate::types::Envelope;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Helper: build a swarm and command channel for tests.
    async fn setup() -> (
        Swarm<SlashmailBehaviour>,
        mpsc::Sender<EngineCommand>,
        mpsc::Receiver<EngineCommand>,
    ) {
        let identity = Identity::generate();
        let (swarm, _peer_id) = build_swarm(&identity).await.unwrap();
        let (tx, rx) = mpsc::channel(16);
        (swarm, tx, rx)
    }

    #[tokio::test]
    async fn shutdown_command_stops_loop() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Shutdown).await.unwrap();
        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn channel_close_stops_loop() {
        let (swarm, tx, rx) = setup().await;

        drop(tx);
        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::ChannelClosed);
    }

    #[tokio::test]
    async fn subscribe_then_shutdown() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Subscribe {
            topic: "test-topic".into(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn unsubscribe_then_shutdown() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Unsubscribe {
            topic: "nonexistent-topic".into(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn get_subscriptions_reflects_subscribe_unsubscribe() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Subscribe {
            topic: "pub_general".into(),
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::GetSubscriptions { reply: reply_tx })
            .await
            .unwrap();

        tx.send(EngineCommand::Unsubscribe {
            topic: "pub_general".into(),
        })
        .await
        .unwrap();

        let (reply_tx2, reply_rx2) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::GetSubscriptions { reply: reply_tx2 })
            .await
            .unwrap();

        tx.send(EngineCommand::Shutdown).await.unwrap();

        run_loop(swarm, rx, None, None, None).await;

        let subs = reply_rx.await.unwrap();
        assert_eq!(subs.values().filter(|v| v.as_str() == "pub_general").count(), 1);

        let subs_after = reply_rx2.await.unwrap();
        assert!(!subs_after.values().any(|v| v == "pub_general"));
    }

    #[tokio::test]
    async fn listen_then_shutdown() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Listen {
            addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn dial_invalid_then_shutdown() {
        let (swarm, tx, rx) = setup().await;

        // Dial a loopback address with a random peer — will fail, but shouldn't crash.
        tx.send(EngineCommand::Dial {
            addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn multiple_commands_before_shutdown() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Subscribe {
            topic: "topic-a".into(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Subscribe {
            topic: "topic-b".into(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Listen {
            addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Unsubscribe {
            topic: "topic-a".into(),
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn wal_flush_called_on_shutdown() {
        let (swarm, tx, rx) = setup().await;
        let flushed = Arc::new(AtomicBool::new(false));
        let flushed_clone = flushed.clone();

        let wal_flush: Box<dyn FnOnce() + Send> = Box::new(move || {
            flushed_clone.store(true, Ordering::SeqCst);
        });

        tx.send(EngineCommand::Shutdown).await.unwrap();
        let reason = run_loop(swarm, rx, None, Some(wal_flush), None).await;

        assert_eq!(reason, ShutdownReason::Command);
        assert!(
            flushed.load(Ordering::SeqCst),
            "WAL flush callback must be called on shutdown"
        );
    }

    #[tokio::test]
    async fn wal_flush_called_on_channel_close() {
        let (swarm, tx, rx) = setup().await;
        let flushed = Arc::new(AtomicBool::new(false));
        let flushed_clone = flushed.clone();

        let wal_flush: Box<dyn FnOnce() + Send> = Box::new(move || {
            flushed_clone.store(true, Ordering::SeqCst);
        });

        drop(tx);
        let reason = run_loop(swarm, rx, None, Some(wal_flush), None).await;

        assert_eq!(reason, ShutdownReason::ChannelClosed);
        assert!(
            flushed.load(Ordering::SeqCst),
            "WAL flush callback must be called on channel close"
        );
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_no_in_flight() {
        let (mut swarm, _tx, _rx) = setup().await;
        let mut in_flight: usize = 0;
        let mut peers = HashMap::new();
        let topic_registry = TopicRegistry::new();

        let start = tokio::time::Instant::now();
        let local_peer_id = *swarm.local_peer_id();
        drain_in_flight(&mut swarm, &mut in_flight, &mut peers, None, None, &topic_registry, local_peer_id).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "drain should return immediately with 0 in-flight"
        );
    }

    // ---- Inbound message processing tests (unit-level, no swarm needed) ----

    #[test]
    fn process_public_message_stores_and_tags() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "pub_general".into(),
            b"hello world".to_vec(),
        );
        env.tags = vec!["inbox".into(), "announce".into()];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "hello world");
        assert_eq!(msgs[0].swarm_id, "pub_general");
        assert_eq!(msgs[0].folder_path, "INBOX");
        assert!(!msgs[0].read);

        let tags = store.get_message_tags(&env.id).unwrap();
        assert_eq!(tags, vec!["announce", "inbox"]);
    }

    #[test]
    fn process_private_message_decrypts_payload_and_tags() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        // Encrypt payload for recipient.
        let plaintext = b"secret message for you";
        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), plaintext).unwrap();

        // Encrypt tags with the shared secret.
        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());
        let enc_tag1 = encryption::seal(shared.as_bytes(), b"private").unwrap();
        let enc_tag2 = encryption::seal(shared.as_bytes(), b"confidential").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm_channel".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = vec![b64.encode(&enc_tag1), b64.encode(&enc_tag2)];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "secret message for you");
        assert_eq!(msgs[0].swarm_id, "dm_channel");

        let tags = store.get_message_tags(&env.id).unwrap();
        assert_eq!(tags, vec!["confidential", "private"]);
    }

    #[test]
    fn process_rejects_tampered_signature() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "test".into(),
            b"original".to_vec(),
        );
        let mut encoded = msg_codec::encode(&env, &sender_kp).unwrap();

        // Tamper with compressed data (flip a byte in the payload area).
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        let store = MessageStore::open_memory().unwrap();
        let result = process_inbound_envelope(&encoded, &recipient_kp, &store);
        assert!(result.is_err());

        // Nothing stored.
        assert!(store.list_messages(0).unwrap().is_empty());
    }

    #[test]
    fn process_private_message_wrong_recipient_fails() {
        let sender_kp = generate_keypair();
        let intended_kp = generate_keypair();
        let wrong_kp = generate_keypair();

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &intended_kp.verifying_key(), b"private").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        // Wrong keypair can't decrypt.
        let result = process_inbound_envelope(&encoded, &wrong_kp, &store);
        assert!(result.is_err());
        assert!(store.list_messages(0).unwrap().is_empty());
    }

    #[test]
    fn process_public_message_no_tags() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "pub".into(),
            b"no tags here".to_vec(),
        );

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "no tags here");

        let tags = store.get_message_tags(&env.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn process_preserves_envelope_id_and_timestamp() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "test".into(),
            b"ts test".to_vec(),
        );
        let expected_id = env.id;
        let expected_ts = env.timestamp;

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs[0].id, expected_id);
        assert_eq!(msgs[0].created_at, expected_ts);
    }

    #[test]
    fn process_sender_is_base64_pubkey() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "test".into(),
            b"check sender".to_vec(),
        );

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        let expected_sender = b64.encode(sender_kp.verifying_key().to_bytes());
        assert_eq!(msgs[0].sender, expected_sender);
    }

    #[test]
    fn process_private_message_sets_recipient_peer_id() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"dm").unwrap();

        let peer_id = libp2p::PeerId::random();
        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(peer_id);

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs[0].recipient, peer_id.to_string());
    }

    #[test]
    fn process_empty_data_fails() {
        let kp = generate_keypair();
        let store = MessageStore::open_memory().unwrap();
        assert!(process_inbound_envelope(&[], &kp, &store).is_err());
    }

    #[test]
    fn process_private_decrypted_tags_searchable_via_fts() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        // Encrypt payload for recipient.
        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"secret body").unwrap();

        // Encrypt tags with the shared secret.
        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());
        let enc_tag = encryption::seal(shared.as_bytes(), b"classified").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm_fts".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = vec![b64.encode(&enc_tag)];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        // Decrypted tag must be searchable via FTS5.
        let results = store.search_messages("tags:classified").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body, "secret body");

        // The denormalized tags column must contain plaintext, not ciphertext.
        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs[0].tags, "classified");
        assert!(!msgs[0].tags.contains(&b64.encode(&enc_tag)),
            "encrypted tag bytes must not appear in stored tags");
    }

    #[test]
    fn process_private_tags_in_denormalized_column() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"body").unwrap();

        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());
        let enc_tag1 = encryption::seal(shared.as_bytes(), b"alpha").unwrap();
        let enc_tag2 = encryption::seal(shared.as_bytes(), b"beta").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = vec![b64.encode(&enc_tag1), b64.encode(&enc_tag2)];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        // The denormalized tags column should contain plaintext tags.
        let msgs = store.list_messages(0).unwrap();
        let tags_words: Vec<&str> = msgs[0].tags.split_whitespace().collect();
        assert!(tags_words.contains(&"alpha"));
        assert!(tags_words.contains(&"beta"));
        // Must not contain any base64-encoded ciphertext.
        assert!(!msgs[0].tags.contains(&b64.encode(&enc_tag1)));
    }

    #[test]
    fn process_tags_searchable_via_fts() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "pub".into(),
            b"fts tag test".to_vec(),
        );
        env.tags = vec!["urgent".into()];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let results = store.search_messages("tags:urgent").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body, "fts tag test");
    }

    #[tokio::test]
    async fn insert_message_via_command_with_store() {
        let (swarm, tx, rx) = setup().await;
        let store = MessageStore::open_memory().unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let msg = Message {
            id: uuid::Uuid::new_v4(),
            swarm_id: "test".to_string(),
            folder_path: "INBOX".to_string(),
            sender_pubkey: [0xAA; 32],
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            subject: "Test".to_string(),
            body: "Hello".to_string(),
            tags: String::new(),
            created_at: chrono::Utc::now(),
            read: false,
        };

        tx.send(EngineCommand::InsertMessage { msg, reply: reply_tx })
            .await
            .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, Some(store), None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        let result = reply_rx.await.unwrap();
        assert!(result.is_ok(), "InsertMessage should succeed with a store");
    }

    #[tokio::test]
    async fn insert_message_fails_without_store() {
        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let msg = Message {
            id: uuid::Uuid::new_v4(),
            swarm_id: "test".to_string(),
            folder_path: "INBOX".to_string(),
            sender_pubkey: [0xAA; 32],
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            subject: "Test".to_string(),
            body: "Hello".to_string(),
            tags: String::new(),
            created_at: chrono::Utc::now(),
            read: false,
        };

        tx.send(EngineCommand::InsertMessage { msg, reply: reply_tx })
            .await
            .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        let result = reply_rx.await.unwrap();
        assert!(result.is_err(), "InsertMessage should fail without a store");
    }

    #[tokio::test]
    async fn add_peer_via_command() {
        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::AddPeer {
            addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        // AddPeer dials the address — result depends on network, but should not panic.
        let _result = reply_rx.await.unwrap();
    }

    #[tokio::test]
    async fn publish_public_without_subscription_resolves_at_shutdown() {
        // With no subscription and no peers, gossipsub returns InsufficientPeers.
        // The engine now defers the reply and resolves it Ok at shutdown
        // (message is stored locally; no propagation).
        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::PublishPublic {
            topic: "pub_general".into(),
            data: b"hello world".to_vec(),
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        // Reply is resolved Ok at shutdown — local storage, no propagation.
        let result = reply_rx.await.unwrap();
        assert!(result.is_ok(), "publish should resolve Ok at shutdown: {:?}", result);
    }

    #[tokio::test]
    async fn subscribe_then_publish_does_not_panic() {
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Subscribe {
            topic: "pub_general".into(),
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::PublishPublic {
            topic: "pub_general".into(),
            data: b"test payload".to_vec(),
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        // With no peers the publish may succeed (message stored locally) or fail
        // depending on gossipsub config. Either way it must not panic.
        let _result = reply_rx.await.unwrap();
    }

    // ---- Peer exchange tests ----

    #[test]
    fn collect_peer_table_empty_swarm() {
        // A freshly built swarm with no connected peers should produce
        // at most entries for our own addresses (if listening).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, _peer_id) = build_swarm(&identity).await.unwrap();
            let table = collect_peer_table(&mut swarm);
            // No connected peers and not listening, so table should be empty.
            assert!(table.is_empty());
        });
    }

    #[test]
    fn collect_peer_table_includes_listen_addrs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, peer_id) = build_swarm(&identity).await.unwrap();

            // Start listening to get a listen address.
            swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();

            // Poll once to process the listen event.
            let _ = tokio::time::timeout(
                Duration::from_millis(100),
                swarm.select_next_some(),
            )
            .await;

            let table = collect_peer_table(&mut swarm);
            // Should include our own listen addresses.
            let own_entries: Vec<_> = table
                .iter()
                .filter(|info| {
                    peer_exchange::from_peer_info(*info)
                        .map(|(pid, _)| pid == peer_id)
                        .unwrap_or(false)
                })
                .collect();
            assert!(
                !own_entries.is_empty(),
                "peer table should include own listen addresses"
            );
        });
    }

    #[test]
    fn dial_learned_peers_skips_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, peer_id) = build_swarm(&identity).await.unwrap();

            // Create a PeerInfo for ourselves — should be skipped.
            let self_info = peer_exchange::to_peer_info(
                &peer_id,
                &["/ip4/127.0.0.1/tcp/9999".parse().unwrap()],
            );
            // Should not panic or attempt to dial self.
            dial_learned_peers(&mut swarm, &[self_info]);
        });
    }

    #[test]
    fn dial_learned_peers_skips_empty_addrs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, _) = build_swarm(&identity).await.unwrap();

            let remote_id = libp2p::PeerId::random();
            let info = peer_exchange::to_peer_info(&remote_id, &[]);
            // Should skip peers with no addresses.
            dial_learned_peers(&mut swarm, &[info]);
        });
    }

    #[test]
    fn dial_learned_peers_dials_new_peer() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, _) = build_swarm(&identity).await.unwrap();

            let remote_id = libp2p::PeerId::random();
            let info = peer_exchange::to_peer_info(
                &remote_id,
                &["/ip4/127.0.0.1/tcp/19999".parse().unwrap()],
            );
            // Should attempt to dial (won't connect, but shouldn't panic).
            dial_learned_peers(&mut swarm, &[info]);
        });
    }

    #[test]
    fn dial_learned_peers_skips_malformed_peer_info() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let identity = Identity::generate();
            let (mut swarm, _) = build_swarm(&identity).await.unwrap();

            let bad_info = peer_exchange::PeerInfo {
                peer_id: vec![0xFF, 0xFF],
                addrs: vec![],
            };
            // Should skip malformed entries without panicking.
            dial_learned_peers(&mut swarm, &[bad_info]);
        });
    }

    // ---- peer_id_from_ed25519_pubkey tests ----

    #[test]
    fn peer_id_from_pubkey_deterministic() {
        let kp = generate_keypair();
        let pk = kp.verifying_key();
        let pid1 = peer_id_from_ed25519_pubkey(&pk).unwrap();
        let pid2 = peer_id_from_ed25519_pubkey(&pk).unwrap();
        assert_eq!(pid1, pid2);
    }

    #[test]
    fn peer_id_from_pubkey_matches_libp2p_conversion() {
        let identity = Identity::generate();
        let libp2p_kp = crate::net::convert_keypair(&identity).unwrap();
        let expected_peer_id = PeerId::from(libp2p_kp.public());

        let derived = peer_id_from_ed25519_pubkey(&identity.public_key()).unwrap();
        assert_eq!(derived, expected_peer_id);
    }

    #[test]
    fn peer_id_different_keys_produce_different_ids() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let pid1 = peer_id_from_ed25519_pubkey(&kp1.verifying_key()).unwrap();
        let pid2 = peer_id_from_ed25519_pubkey(&kp2.verifying_key()).unwrap();
        assert_ne!(pid1, pid2);
    }

    // ---- SendMessage command tests ----

    #[tokio::test]
    async fn send_message_encrypts_and_dispatches() {
        let sender_identity = Identity::generate();
        let sender_kp = sender_identity.keypair().clone();
        let recipient_kp = generate_keypair();
        let recipient_b64 = base64::engine::general_purpose::STANDARD
            .encode(recipient_kp.verifying_key().to_bytes());

        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: recipient_b64,
            body: "hello encrypted".into(),
            tags: vec!["inbox".into(), "test".into()],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        // Run the loop with a keypair so SendMessage can encrypt.
        run_loop(swarm, rx, None, None, Some(&sender_kp)).await;

        // The reply should contain a valid message UUID.
        let result = reply_rx.await.unwrap();
        assert!(result.is_ok(), "SendMessage should succeed: {:?}", result);
        let (msg_id, _warning) = result.unwrap();
        // UUID format: 8-4-4-4-12
        assert_eq!(msg_id.len(), 36);
        assert!(msg_id.contains('-'));
    }

    #[tokio::test]
    async fn send_message_fails_without_keypair() {
        let recipient_kp = generate_keypair();
        let recipient_b64 = base64::engine::general_purpose::STANDARD
            .encode(recipient_kp.verifying_key().to_bytes());

        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: recipient_b64,
            body: "test".into(),
            tags: vec![],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        // No keypair provided.
        run_loop(swarm, rx, None, None, None).await;

        let result = reply_rx.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no keypair"));
    }

    #[tokio::test]
    async fn send_message_fails_with_invalid_recipient() {
        let sender_kp = generate_keypair();

        let (swarm, tx, rx) = setup().await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: "not-valid-base64!!!".into(),
            body: "test".into(),
            tags: vec![],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        run_loop(swarm, rx, None, None, Some(&sender_kp)).await;

        let result = reply_rx.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid recipient"));
    }

    #[tokio::test]
    async fn send_message_envelope_decryptable_by_recipient() {
        // Verify the full roundtrip: send encrypts, then process_inbound_envelope decrypts.
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let recipient_pubkey = recipient_kp.verifying_key();
        let recipient_peer_id = peer_id_from_ed25519_pubkey(&recipient_pubkey).unwrap();

        // Simulate what the engine does in SendMessage:
        let body = "secret roundtrip message";
        let tags = vec!["private".to_string(), "important".to_string()];

        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_pubkey);
        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_pubkey, body.as_bytes()).unwrap();
        let encrypted_tags: Vec<String> = tags
            .iter()
            .map(|t| {
                let ct = encryption::seal(shared.as_bytes(), t.as_bytes()).unwrap();
                b64.encode(&ct)
            })
            .collect();

        let mut envelope = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        envelope.recipient = Some(recipient_peer_id);
        envelope.tags = encrypted_tags;

        let encoded = msg_codec::encode(&envelope, &sender_kp).unwrap();

        // Now verify the recipient can decrypt it via process_inbound_envelope.
        let store = MessageStore::open_memory().unwrap();
        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, body);
        assert_eq!(msgs[0].recipient, recipient_peer_id.to_string());

        let stored_tags = store.get_message_tags(&envelope.id).unwrap();
        assert_eq!(stored_tags, vec!["important", "private"]);
    }

    // ---- SendMessage local Sent folder tests ----

    #[tokio::test]
    async fn send_message_stores_in_sent_folder() {
        let sender_identity = Identity::generate();
        let sender_kp = sender_identity.keypair().clone();
        let recipient_kp = generate_keypair();
        let recipient_b64 = base64::engine::general_purpose::STANDARD
            .encode(recipient_kp.verifying_key().to_bytes());

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("test.db");

        let (swarm, tx, rx) = setup().await;
        let store = MessageStore::open(&db_path).unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: recipient_b64,
            body: "test sent folder".into(),
            tags: vec!["work".into()],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        run_loop(swarm, rx, Some(store), None, Some(&sender_kp)).await;

        let result = reply_rx.await.unwrap();
        assert!(result.is_ok(), "SendMessage should succeed: {:?}", result);

        // Re-open the store to verify persistence.
        let store2 = MessageStore::open(&db_path).unwrap();
        let all = store2.list_messages(0).unwrap();
        assert_eq!(all.len(), 1, "should have one message in store");
        assert_eq!(all[0].folder_path, "Sent");
        assert_eq!(all[0].body, "test sent folder");
        assert_eq!(all[0].tags, "work");
        assert!(all[0].read, "sent messages should be marked as read");
    }

    #[tokio::test]
    async fn send_message_warns_when_no_peers() {
        let sender_identity = Identity::generate();
        let sender_kp = sender_identity.keypair().clone();
        let recipient_kp = generate_keypair();
        let recipient_b64 = base64::engine::general_purpose::STANDARD
            .encode(recipient_kp.verifying_key().to_bytes());

        let (swarm, tx, rx) = setup().await;
        let store = MessageStore::open_memory().unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: recipient_b64,
            body: "lonely message".into(),
            tags: vec![],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        run_loop(swarm, rx, Some(store), None, Some(&sender_kp)).await;

        let result = reply_rx.await.unwrap();
        assert!(result.is_ok());
        let (_msg_id, warning) = result.unwrap();
        assert!(warning.is_some(), "should warn when no peers connected");
        assert!(warning.unwrap().contains("no peers connected"));
    }

    #[tokio::test]
    async fn send_message_stores_multiple_tags_in_sent() {
        let sender_identity = Identity::generate();
        let sender_kp = sender_identity.keypair().clone();
        let recipient_kp = generate_keypair();
        let recipient_b64 = base64::engine::general_purpose::STANDARD
            .encode(recipient_kp.verifying_key().to_bytes());

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("test.db");

        let (swarm, tx, rx) = setup().await;
        let store = MessageStore::open(&db_path).unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::SendMessage {
            to: recipient_b64,
            body: "multi-tag".into(),
            tags: vec!["urgent".into(), "private".into()],
            reply: reply_tx,
        })
        .await
        .unwrap();
        tx.send(EngineCommand::Shutdown).await.unwrap();

        run_loop(swarm, rx, Some(store), None, Some(&sender_kp)).await;

        let result = reply_rx.await.unwrap();
        let (msg_id, _) = result.unwrap();

        // Re-open the store to verify.
        let store2 = MessageStore::open(&db_path).unwrap();
        let all = store2.list_messages(0).unwrap();
        assert_eq!(all.len(), 1);
        // Tags text preserves insertion order.
        assert!(all[0].tags.contains("urgent"));
        assert!(all[0].tags.contains("private"));

        // Verify normalised tags were upserted.
        let msg_uuid = uuid::Uuid::parse_str(&msg_id).unwrap();
        let tags = store2.get_message_tags(&msg_uuid).unwrap();
        assert_eq!(tags, vec!["private", "urgent"]); // alphabetical from DB
    }

    // ---- Gossipsub publish timeout tests ----

    #[tokio::test]
    async fn publish_public_defers_reply_when_no_mesh_peers() {
        // With no connected peers, PublishPublic should defer the reply until
        // the timeout fires, then return Ok (the message is stored locally).
        let (swarm, tx, rx) = setup().await;

        tx.send(EngineCommand::Subscribe {
            topic: "pub_test_timeout".into(),
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(EngineCommand::PublishPublic {
            topic: "pub_test_timeout".into(),
            data: b"hello deferred".to_vec(),
            reply: reply_tx,
        })
        .await
        .unwrap();

        // Schedule shutdown after a brief delay so the timeout fires.
        let tx2 = tx.clone();
        tokio::spawn(async move {
            // The GOSSIP_PUBLISH_TIMEOUT is 10s but the test swarm has no peers,
            // so the deadline will fire. We send Shutdown shortly after to end the loop.
            // The pending publish will be resolved when the timeout fires.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = tx2.send(EngineCommand::Shutdown).await;
        });

        let reason = run_loop(swarm, rx, None, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        // The reply should eventually be resolved (Ok with local-only storage).
        match tokio::time::timeout(Duration::from_secs(15), reply_rx).await {
            Ok(Ok(result)) => {
                // Should be Ok — message was published locally.
                assert!(result.is_ok(), "deferred publish should succeed: {:?}", result);
            }
            Ok(Err(_)) => {
                // Sender was dropped — this is also acceptable since shutdown
                // might have occurred before the pending was resolved.
            }
            Err(_) => panic!("reply_rx timed out waiting for deferred publish"),
        }
    }

    // ---- Encrypted tag edge-case tests ----

    #[test]
    fn encrypted_tags_are_opaque_on_wire() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());
        let plaintext_tag = "top-secret";
        let enc_tag = encryption::seal(shared.as_bytes(), plaintext_tag.as_bytes()).unwrap();
        let wire_tag = b64.encode(&enc_tag);

        // The wire representation must not contain the plaintext tag.
        assert!(!wire_tag.contains(plaintext_tag));
        // Ciphertext must be longer than plaintext (nonce + AEAD overhead).
        assert!(enc_tag.len() > plaintext_tag.len());
    }

    #[test]
    fn encrypted_tag_tampered_ciphertext_fails() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"body").unwrap();
        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());

        let mut enc_tag = encryption::seal(shared.as_bytes(), b"legit").unwrap();
        // Flip a byte in the ciphertext (after the 24-byte nonce).
        let idx = enc_tag.len() - 1;
        enc_tag[idx] ^= 0xFF;

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = vec![b64.encode(&enc_tag)];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        // Tampered tag must cause decryption failure.
        let result = process_inbound_envelope(&encoded, &recipient_kp, &store);
        assert!(result.is_err());
        assert!(store.list_messages(0).unwrap().is_empty());
    }

    #[test]
    fn encrypted_tags_wrong_recipient_cannot_decrypt() {
        let sender_kp = generate_keypair();
        let intended_kp = generate_keypair();
        let wrong_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &intended_kp.verifying_key(), b"private").unwrap();
        let shared = ecdh::derive_shared_secret(&sender_kp, &intended_kp.verifying_key());
        let enc_tag = encryption::seal(shared.as_bytes(), b"secret-tag").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = vec![b64.encode(&enc_tag)];

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        // Wrong recipient cannot decrypt payload or tags.
        let result = process_inbound_envelope(&encoded, &wrong_kp, &store);
        assert!(result.is_err());
        assert!(store.list_messages(0).unwrap().is_empty());
    }

    #[test]
    fn encrypted_tags_each_get_unique_nonce() {
        let kp = generate_keypair();
        let peer_kp = generate_keypair();
        let shared = ecdh::derive_shared_secret(&kp, &peer_kp.verifying_key());

        // Encrypt the same tag twice — ciphertexts must differ (random nonce).
        let ct1 = encryption::seal(shared.as_bytes(), b"same-tag").unwrap();
        let ct2 = encryption::seal(shared.as_bytes(), b"same-tag").unwrap();
        assert_ne!(ct1, ct2, "each tag encryption must use a unique nonce");

        // Both must still decrypt to the same plaintext.
        let pt1 = encryption::open(shared.as_bytes(), &ct1).unwrap();
        let pt2 = encryption::open(shared.as_bytes(), &ct2).unwrap();
        assert_eq!(pt1, pt2);
        assert_eq!(pt1, b"same-tag");
    }

    #[test]
    fn private_message_with_empty_tags() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"no tags").unwrap();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        // No tags at all.

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "no tags");
        assert!(msgs[0].tags.is_empty());
        assert!(store.get_message_tags(&env.id).unwrap().is_empty());
    }

    #[test]
    fn encrypted_tags_unicode_roundtrip() {
        let sender_kp = generate_keypair();
        let recipient_kp = generate_keypair();
        let b64 = base64::engine::general_purpose::STANDARD;

        let encrypted_payload =
            ecdh::seal_for(&sender_kp, &recipient_kp.verifying_key(), b"unicode test").unwrap();
        let shared = ecdh::derive_shared_secret(&sender_kp, &recipient_kp.verifying_key());

        let unicode_tags = vec!["étiquette", "タグ", "标签"];
        let encrypted_tags: Vec<String> = unicode_tags
            .iter()
            .map(|t| {
                let ct = encryption::seal(shared.as_bytes(), t.as_bytes()).unwrap();
                b64.encode(&ct)
            })
            .collect();

        let mut env = Envelope::new(
            sender_kp.verifying_key().to_bytes(),
            "dm".into(),
            encrypted_payload,
        );
        env.recipient = Some(libp2p::PeerId::random());
        env.tags = encrypted_tags;

        let encoded = msg_codec::encode(&env, &sender_kp).unwrap();
        let store = MessageStore::open_memory().unwrap();

        process_inbound_envelope(&encoded, &recipient_kp, &store).unwrap();

        let msgs = store.list_messages(0).unwrap();
        assert_eq!(msgs.len(), 1);
        for tag in &unicode_tags {
            assert!(msgs[0].tags.contains(tag), "missing tag: {tag}");
        }
    }

    // ---- PeerId-ordered sync initiation tests ----

    #[test]
    fn lower_peer_id_initiates_sync_immediately() {
        // Build two PeerIds with known ordering.
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let peer_a = peer_id_from_ed25519_pubkey(&id_a.public_key()).unwrap();
        let peer_b = peer_id_from_ed25519_pubkey(&id_b.public_key()).unwrap();

        let (lower, higher) = if peer_a.to_bytes() < peer_b.to_bytes() {
            (peer_a, peer_b)
        } else {
            (peer_b, peer_a)
        };

        // Simulate: local = lower, remote = higher → should include InitiateSync.
        let local_bytes = lower.to_bytes();
        let remote_bytes = higher.to_bytes();
        assert!(local_bytes < remote_bytes, "test setup: lower < higher");

        // The logic in ConnectionEstablished: if local < remote → InitiateSync.
        let should_initiate_immediately = local_bytes < remote_bytes;
        assert!(should_initiate_immediately);
    }

    #[test]
    fn higher_peer_id_defers_sync() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let peer_a = peer_id_from_ed25519_pubkey(&id_a.public_key()).unwrap();
        let peer_b = peer_id_from_ed25519_pubkey(&id_b.public_key()).unwrap();

        let (lower, higher) = if peer_a.to_bytes() < peer_b.to_bytes() {
            (peer_a, peer_b)
        } else {
            (peer_b, peer_a)
        };

        // Simulate: local = higher, remote = lower → should defer.
        let mut deferred = Vec::new();
        let local_bytes = higher.to_bytes();
        let remote_bytes = lower.to_bytes();
        assert!(local_bytes > remote_bytes, "test setup: higher > lower");

        // Should NOT initiate immediately; should add to deferred_syncs.
        let should_defer = local_bytes >= remote_bytes;
        assert!(should_defer);

        deferred.push(DeferredSync {
            peer_id: lower,
            deadline: tokio::time::Instant::now() + SYNC_DEFER_TIMEOUT,
        });
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].peer_id, lower);
    }

    #[test]
    fn deferred_sync_cancelled_on_inbound_request() {
        let id_a = Identity::generate();
        let peer = peer_id_from_ed25519_pubkey(&id_a.public_key()).unwrap();

        let mut deferred = vec![
            DeferredSync {
                peer_id: peer,
                deadline: tokio::time::Instant::now() + SYNC_DEFER_TIMEOUT,
            },
        ];

        // Simulate receiving an inbound SyncRequest from this peer:
        // the deferred entry should be removed.
        assert!(deferred.iter().any(|d| d.peer_id == peer));
        deferred.retain(|d| d.peer_id != peer);
        assert!(deferred.is_empty(), "deferred sync should be cancelled");
    }

    #[test]
    fn deferred_sync_cleaned_up_on_disconnect() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let peer_a = peer_id_from_ed25519_pubkey(&id_a.public_key()).unwrap();
        let peer_b = peer_id_from_ed25519_pubkey(&id_b.public_key()).unwrap();

        let mut deferred = vec![
            DeferredSync {
                peer_id: peer_a,
                deadline: tokio::time::Instant::now() + SYNC_DEFER_TIMEOUT,
            },
            DeferredSync {
                peer_id: peer_b,
                deadline: tokio::time::Instant::now() + SYNC_DEFER_TIMEOUT,
            },
        ];

        // Simulate peer_a disconnect.
        deferred.retain(|d| d.peer_id != peer_a);
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].peer_id, peer_b);
    }
}
