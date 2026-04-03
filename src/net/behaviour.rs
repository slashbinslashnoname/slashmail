//! Composite network behaviour combining Gossipsub, Kademlia, Identify, mDNS,
//! and request-response for direct mail delivery.

use libp2p::identity::Keypair;
use libp2p::{gossipsub, identify, kad, mdns, ping, request_response, swarm::NetworkBehaviour, PeerId};
use std::time::Duration;
use thiserror::Error;

use super::rr::{self, MailCodec};

/// Combined libp2p behaviour for slashmail.
#[derive(NetworkBehaviour)]
pub struct SlashmailBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub mail_rr: request_response::Behaviour<MailCodec>,
    pub ping: ping::Behaviour,
}

/// Error type for behaviour construction.
#[derive(Debug, Error)]
#[error("behaviour error: {0}")]
pub struct BehaviourError(String);

impl SlashmailBehaviour {
    /// Build a new composite behaviour from a libp2p identity keypair.
    pub fn new(key: &Keypair) -> Result<Self, BehaviourError> {
        let peer_id = PeerId::from(key.public());

        // Gossipsub with message signing and deduplication.
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| BehaviourError(format!("gossipsub config: {e}")))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        )
        .map_err(|e| BehaviourError(format!("gossipsub: {e}")))?;

        // Kademlia DHT for peer and content discovery.
        let store = kad::store::MemoryStore::new(peer_id);
        let kademlia = kad::Behaviour::new(peer_id, store);

        // Identify protocol for exchanging peer metadata.
        let identify = identify::Behaviour::new(identify::Config::new(
            "/slashmail/id/1.0.0".to_string(),
            key.public(),
        ));

        // mDNS for local network peer discovery.
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
            .map_err(|e| BehaviourError(format!("mdns: {e}")))?;

        // Request-response for direct private mail delivery.
        let mail_rr = rr::mail_behaviour();

        // Ping for latency measurement.
        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            mdns,
            mail_rr,
            ping,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_new_succeeds() {
        let key = Keypair::generate_ed25519();
        let behaviour = SlashmailBehaviour::new(&key);
        assert!(behaviour.is_ok());
    }

    #[test]
    fn behaviour_gossipsub_subscribe_then_unsubscribe() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = SlashmailBehaviour::new(&key).unwrap();
        let topic = gossipsub::IdentTopic::new("another-topic");
        assert!(behaviour.gossipsub.subscribe(&topic).is_ok());
        assert!(behaviour.gossipsub.unsubscribe(&topic).is_ok());
    }

    #[test]
    fn behaviour_gossipsub_accepts_subscription() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = SlashmailBehaviour::new(&key).unwrap();
        let topic = gossipsub::IdentTopic::new("test-topic");
        let result = behaviour.gossipsub.subscribe(&topic);
        assert!(result.is_ok());
    }
}
