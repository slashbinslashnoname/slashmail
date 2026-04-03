//! Composite network behaviour combining Gossipsub, Kademlia, Identify, mDNS,
//! request-response for direct mail delivery, relay client, dcutr (NAT
//! hole-punching), and autonat (NAT status detection).

use libp2p::identity::Keypair;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, relay, request_response,
    swarm::NetworkBehaviour, PeerId,
};
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
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
}

/// Error type for behaviour construction.
#[derive(Debug, Error)]
#[error("behaviour error: {0}")]
pub struct BehaviourError(String);

impl SlashmailBehaviour {
    /// Build a new composite behaviour from a libp2p identity keypair and an already-constructed
    /// relay client behaviour. The relay client must be obtained from [`relay::client::new`] with
    /// its paired transport registered in the swarm's transport stack (use
    /// [`SwarmBuilder::with_relay_client`] to ensure this).
    pub fn new(key: &Keypair, relay_client: relay::client::Behaviour) -> Result<Self, BehaviourError> {
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

        // DCUtR (Direct Connection Upgrade through Relay) for NAT hole punching.
        let dcutr = dcutr::Behaviour::new(peer_id);

        // AutoNAT for automatic NAT status detection.
        let autonat = autonat::Behaviour::new(peer_id, Default::default());

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            mdns,
            mail_rr,
            relay_client,
            dcutr,
            autonat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_behaviour(key: &Keypair) -> SlashmailBehaviour {
        let peer_id = PeerId::from(key.public());
        // relay::client::new returns a (transport, behaviour) pair. In tests we
        // drop the transport immediately; this is safe because unit tests never
        // poll the swarm and therefore never trigger the relay behaviour's internal
        // channel. Production code uses SwarmBuilder::with_relay_client so the
        // transport stays alive for the swarm's lifetime.
        let (_relay_transport, relay_client) = relay::client::new(peer_id);
        SlashmailBehaviour::new(key, relay_client).unwrap()
    }

    #[test]
    fn behaviour_new_succeeds() {
        let key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(key.public());
        let (_relay_transport, relay_client) = relay::client::new(peer_id);
        assert!(SlashmailBehaviour::new(&key, relay_client).is_ok());
    }

    #[test]
    fn behaviour_gossipsub_subscribe_then_unsubscribe() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = make_behaviour(&key);
        let topic = gossipsub::IdentTopic::new("another-topic");
        assert!(behaviour.gossipsub.subscribe(&topic).is_ok());
        assert!(behaviour.gossipsub.unsubscribe(&topic).is_ok());
    }

    #[test]
    fn behaviour_gossipsub_accepts_subscription() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = make_behaviour(&key);
        let topic = gossipsub::IdentTopic::new("test-topic");
        let result = behaviour.gossipsub.subscribe(&topic);
        assert!(result.is_ok());
    }

    #[test]
    fn behaviour_has_relay_client() {
        let key = Keypair::generate_ed25519();
        let behaviour = make_behaviour(&key);
        let _ = &behaviour.relay_client;
    }

    #[test]
    fn behaviour_has_dcutr() {
        let key = Keypair::generate_ed25519();
        let behaviour = make_behaviour(&key);
        let _ = &behaviour.dcutr;
    }

    #[test]
    fn behaviour_has_autonat() {
        let key = Keypair::generate_ed25519();
        let behaviour = make_behaviour(&key);
        let _ = &behaviour.autonat;
    }
}
