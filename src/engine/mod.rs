//! Engine: central event loop multiplexing swarm events, CLI commands, and OS signals.

use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::Signature;
use futures::StreamExt;
use libp2p::{gossipsub, request_response};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, Swarm};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::crypto::ecdh;
use crate::crypto::encryption;
use crate::crypto::signing::{self, Keypair, PublicKey};
use crate::message::codec as msg_codec;
use crate::net::behaviour::{SlashmailBehaviour, SlashmailBehaviourEvent};
use crate::net::rr::{MailRequest, MailResponse};
use crate::storage::db::{Message, MessageStore};

/// Duration to wait for in-flight requests to drain during shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Commands sent from the CLI (or other callers) to the engine via an mpsc channel.
#[derive(Debug)]
pub enum EngineCommand {
    /// Subscribe to a gossipsub topic.
    Subscribe { topic: String },
    /// Unsubscribe from a gossipsub topic.
    Unsubscribe { topic: String },
    /// Dial a remote peer at the given multiaddress.
    Dial { addr: Multiaddr },
    /// Start listening on the given multiaddress.
    Listen { addr: Multiaddr },
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
    wal_flush: Option<Box<dyn FnOnce() + Send>>,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) -> ShutdownReason {
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut in_flight: usize = 0;

    info!("engine event loop started");

    let reason = loop {
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
                        if let Some(reason) = handle_command(&mut swarm, command) {
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
                let action = handle_swarm_event(event, &mut in_flight, keypair, store);
                apply_swarm_action(&mut swarm, action);
            }
        }
    };

    // --- Graceful shutdown sequence ---
    drain_in_flight(&mut swarm, &mut in_flight, keypair, store).await;

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
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) {
    if *in_flight == 0 {
        debug!("no in-flight requests to drain");
        return;
    }

    info!(in_flight = *in_flight, "draining in-flight requests");
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;

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
                let action = handle_swarm_event(event, in_flight, keypair, store);
                apply_swarm_action(swarm, action);
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
) -> Option<ShutdownReason> {
    match command {
        EngineCommand::Subscribe { topic } => {
            let gossipsub_topic = libp2p::gossipsub::IdentTopic::new(&topic);
            match swarm.behaviour_mut().gossipsub.subscribe(&gossipsub_topic) {
                Ok(true) => info!(%topic, "subscribed to topic"),
                Ok(false) => debug!(%topic, "already subscribed to topic"),
                Err(e) => warn!(%topic, %e, "failed to subscribe to topic"),
            }
            None
        }
        EngineCommand::Unsubscribe { topic } => {
            let gossipsub_topic = libp2p::gossipsub::IdentTopic::new(&topic);
            match swarm.behaviour_mut().gossipsub.unsubscribe(&gossipsub_topic) {
                Ok(true) => info!(%topic, "unsubscribed from topic"),
                Ok(false) => debug!(%topic, "was not subscribed to topic"),
                Err(e) => warn!(%topic, %e, "failed to unsubscribe from topic"),
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
        EngineCommand::Shutdown => {
            info!("shutdown command received");
            Some(ShutdownReason::Command)
        }
    }
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
}

/// Apply a [`SwarmAction`] to the swarm.
fn apply_swarm_action(
    swarm: &mut Swarm<SlashmailBehaviour>,
    action: SwarmAction,
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
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) -> SwarmAction {
    match event {
        // --- Request-response events (tracked for graceful drain) ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::MailRr(rr_event)) => {
            handle_rr_event(rr_event, in_flight, keypair, store)
        }

        // --- Gossipsub events ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::Gossipsub(gs_event)) => {
            handle_gossipsub_event(gs_event, keypair, store);
            SwarmAction::None
        }

        // --- Other behaviour events ---
        SwarmEvent::Behaviour(event) => {
            debug!(?event, "behaviour event");
            SwarmAction::None
        }

        // --- Connection / listener lifecycle ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "new listen address");
            SwarmAction::None
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!(%peer_id, "connection established");
            SwarmAction::None
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "connection closed");
            SwarmAction::None
        }
        SwarmEvent::IncomingConnection { local_addr, .. } => {
            debug!(%local_addr, "incoming connection");
            SwarmAction::None
        }
        SwarmEvent::OutgoingConnectionError { error, .. } => {
            warn!(%error, "outgoing connection error");
            SwarmAction::None
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            warn!(%error, "incoming connection error");
            SwarmAction::None
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            debug!(%address, "listen address expired");
            SwarmAction::None
        }
        SwarmEvent::ListenerClosed { listener_id, .. } => {
            debug!(?listener_id, "listener closed");
            SwarmAction::None
        }
        SwarmEvent::ListenerError { listener_id, error, .. } => {
            warn!(?listener_id, %error, "listener error");
            SwarmAction::None
        }
        SwarmEvent::Dialing { peer_id, .. } => {
            debug!(?peer_id, "dialing");
            SwarmAction::None
        }
        SwarmEvent::NewExternalAddrCandidate { address, .. } => {
            debug!(%address, "new external address candidate");
            SwarmAction::None
        }
        SwarmEvent::ExternalAddrConfirmed { address, .. } => {
            info!(%address, "external address confirmed");
            SwarmAction::None
        }
        SwarmEvent::ExternalAddrExpired { address, .. } => {
            debug!(%address, "external address expired");
            SwarmAction::None
        }
        event => {
            debug!(?event, "unhandled swarm event");
            SwarmAction::None
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
fn handle_gossipsub_event(
    event: gossipsub::Event,
    keypair: Option<&Keypair>,
    store: Option<&MessageStore>,
) {
    match event {
        gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        } => {
            debug!(%propagation_source, %message_id, "gossipsub message received");
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
            debug!(%peer_id, %topic, "peer subscribed");
        }
        gossipsub::Event::Unsubscribed { peer_id, topic } => {
            debug!(%peer_id, %topic, "peer unsubscribed");
        }
        gossipsub::Event::GossipsubNotSupported { peer_id } => {
            debug!(%peer_id, "gossipsub not supported by peer");
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
    signing::verify(&sender_pubkey, &envelope.payload, &sig)?;

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

    // 5. Upsert tags into the normalised tag table.
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
        let reason = run_loop(swarm, rx, Some(wal_flush), None, None).await;

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
        let reason = run_loop(swarm, rx, Some(wal_flush), None, None).await;

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

        let start = tokio::time::Instant::now();
        drain_in_flight(&mut swarm, &mut in_flight, None, None).await;
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
}
