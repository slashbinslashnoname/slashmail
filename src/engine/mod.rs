//! Engine: central event loop multiplexing swarm events, CLI commands, and OS signals.

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, Swarm};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::net::behaviour::{SlashmailBehaviour, SlashmailBehaviourEvent};

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
/// Returns the reason the loop exited.
pub async fn run_loop(
    mut swarm: Swarm<SlashmailBehaviour>,
    mut cmd_rx: mpsc::Receiver<EngineCommand>,
) -> ShutdownReason {
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

    info!("engine event loop started");

    loop {
        tokio::select! {
            // --- OS signals ---
            _ = sigint.recv() => {
                info!("received SIGINT, shutting down");
                return ShutdownReason::Signal;
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                return ShutdownReason::Signal;
            }

            // --- CLI commands ---
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(command) => {
                        if let Some(reason) = handle_command(&mut swarm, command) {
                            return reason;
                        }
                    }
                    None => {
                        info!("command channel closed, shutting down");
                        return ShutdownReason::ChannelClosed;
                    }
                }
            }

            // --- Swarm events ---
            event = swarm.select_next_some() => {
                handle_swarm_event(event);
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

/// Process a single swarm event. Logs the event for now; downstream beads will
/// add message handling, peer management, etc.
fn handle_swarm_event(event: SwarmEvent<SlashmailBehaviourEvent>) {
    match &event {
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
        _ => {
            debug!(?event, "unhandled swarm event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::net::build_swarm;

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
        let reason = run_loop(swarm, rx).await;
        assert_eq!(reason, ShutdownReason::Command);
    }

    #[tokio::test]
    async fn channel_close_stops_loop() {
        let (swarm, tx, rx) = setup().await;

        drop(tx);
        let reason = run_loop(swarm, rx).await;
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

        let reason = run_loop(swarm, rx).await;
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

        let reason = run_loop(swarm, rx).await;
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

        let reason = run_loop(swarm, rx).await;
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

        let reason = run_loop(swarm, rx).await;
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

        let reason = run_loop(swarm, rx).await;
        assert_eq!(reason, ShutdownReason::Command);
    }
}
