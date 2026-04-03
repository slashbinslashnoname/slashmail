//! Engine: central event loop multiplexing swarm events, CLI commands, and OS signals.

use std::time::Duration;

use futures::StreamExt;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, Swarm};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::net::behaviour::{SlashmailBehaviour, SlashmailBehaviourEvent};
use crate::net::rr::{MailRequest, MailResponse};
use crate::storage::db::{Message, MessageStore};

/// Duration to wait for in-flight requests to drain during shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Commands sent from the CLI (or other callers) to the engine via an mpsc channel.
///
/// Read operations (list, search) bypass this channel and use a read-only DB
/// connection directly. Write operations are routed here so the daemon owns the
/// sole read-write connection, preventing SQLITE_BUSY contention in WAL mode.
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
/// Returns the reason the loop exited.
pub async fn run_loop(
    mut swarm: Swarm<SlashmailBehaviour>,
    mut cmd_rx: mpsc::Receiver<EngineCommand>,
    store: Option<MessageStore>,
    wal_flush: Option<Box<dyn FnOnce() + Send>>,
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
                        if let Some(reason) = handle_command(&mut swarm, command, store.as_ref()) {
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
                handle_swarm_event(event, &mut in_flight);
            }
        }
    };

    // --- Graceful shutdown sequence ---
    drain_in_flight(&mut swarm, &mut in_flight).await;

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
                handle_swarm_event(event, in_flight);
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
        EngineCommand::Shutdown => {
            info!("shutdown command received");
            Some(ShutdownReason::Command)
        }
    }
}

/// Process a single swarm event, updating `in_flight` for request-response tracking.
fn handle_swarm_event(event: SwarmEvent<SlashmailBehaviourEvent>, in_flight: &mut usize) {
    match event {
        // --- Request-response events (tracked for graceful drain) ---
        SwarmEvent::Behaviour(SlashmailBehaviourEvent::MailRr(rr_event)) => {
            handle_rr_event(rr_event, in_flight);
        }

        // --- Other behaviour events ---
        SwarmEvent::Behaviour(event) => {
            debug!(?event, "behaviour event");
        }

        // --- Connection / listener lifecycle ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "new listen address");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!(%peer_id, "connection established");
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "connection closed");
        }
        SwarmEvent::IncomingConnection { local_addr, .. } => {
            debug!(%local_addr, "incoming connection");
        }
        SwarmEvent::OutgoingConnectionError { error, .. } => {
            warn!(%error, "outgoing connection error");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            warn!(%error, "incoming connection error");
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            debug!(%address, "listen address expired");
        }
        SwarmEvent::ListenerClosed { listener_id, .. } => {
            debug!(?listener_id, "listener closed");
        }
        SwarmEvent::ListenerError { listener_id, error, .. } => {
            warn!(?listener_id, %error, "listener error");
        }
        SwarmEvent::Dialing { peer_id, .. } => {
            debug!(?peer_id, "dialing");
        }
        SwarmEvent::NewExternalAddrCandidate { address, .. } => {
            debug!(%address, "new external address candidate");
        }
        SwarmEvent::ExternalAddrConfirmed { address, .. } => {
            info!(%address, "external address confirmed");
        }
        SwarmEvent::ExternalAddrExpired { address, .. } => {
            debug!(%address, "external address expired");
        }
        event => {
            debug!(?event, "unhandled swarm event");
        }
    }
}

/// Handle a request-response event, updating the in-flight counter.
///
/// The counter is decremented when an outbound request completes (response or failure).
/// Callers that send outbound requests via `mail_rr.send_request()` must increment
/// `in_flight` at send time.
fn handle_rr_event(
    event: request_response::Event<MailRequest, MailResponse>,
    in_flight: &mut usize,
) {
    match event {
        request_response::Event::Message { message, peer, .. } => match message {
            request_response::Message::Response { request_id, .. } => {
                debug!(%peer, ?request_id, "outbound request got response");
                *in_flight = in_flight.saturating_sub(1);
            }
            request_response::Message::Request { request_id, .. } => {
                debug!(%peer, ?request_id, "inbound request received");
            }
        },
        request_response::Event::OutboundFailure {
            request_id, error, peer, ..
        } => {
            warn!(%peer, ?request_id, %error, "outbound request failed");
            *in_flight = in_flight.saturating_sub(1);
        }
        request_response::Event::InboundFailure {
            request_id, error, peer, ..
        } => {
            debug!(%peer, ?request_id, %error, "inbound request failed");
        }
        request_response::Event::ResponseSent { request_id, peer, .. } => {
            debug!(%peer, ?request_id, "response sent");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::net::build_swarm;
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
        let reason = run_loop(swarm, rx, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn channel_close_stops_loop() {
        let (swarm, tx, rx) = setup().await;

        drop(tx);
        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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
        let reason = run_loop(swarm, rx, None, Some(wal_flush)).await;

        assert_eq!(reason, ShutdownReason::Command);
        assert!(flushed.load(Ordering::SeqCst), "WAL flush callback must be called on shutdown");
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
        let reason = run_loop(swarm, rx, None, Some(wal_flush)).await;

        assert_eq!(reason, ShutdownReason::ChannelClosed);
        assert!(flushed.load(Ordering::SeqCst), "WAL flush callback must be called on channel close");
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_no_in_flight() {
        // Verify that drain_in_flight is a no-op with 0 in-flight requests
        // (i.e., does not block for 5 seconds).
        let (mut swarm, _tx, _rx) = setup().await;
        let mut in_flight: usize = 0;

        let start = tokio::time::Instant::now();
        drain_in_flight(&mut swarm, &mut in_flight).await;
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_millis(100), "drain should return immediately with 0 in-flight");
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

        let reason = run_loop(swarm, rx, Some(store), None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
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

        let reason = run_loop(swarm, rx, None, None).await;
        assert_eq!(reason, ShutdownReason::Command);

        // AddPeer dials the address — result depends on network, but should not panic.
        let _result = reply_rx.await.unwrap();
    }
}
