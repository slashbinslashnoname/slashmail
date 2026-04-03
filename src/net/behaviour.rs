//! Composite network behaviour combining Gossipsub, Kademlia, Identify, mDNS,
//! request-response for direct mail delivery, relay client, dcutr (NAT
//! hole-punching), and autonat (NAT status detection).

use libp2p::identity::Keypair;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response,
    swarm::NetworkBehaviour, PeerId,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

use super::rr::{self, MailCodec};

/// Maximum gossipsub message size (256 KiB).
///
/// Must be large enough for a compressed [`Envelope`] but bounded to prevent
/// memory exhaustion from oversized messages.
const MAX_GOSSIPSUB_MESSAGE_SIZE: usize = 256 * 1024;

/// Combined libp2p behaviour for slashmail.
#[derive(NetworkBehaviour)]
pub struct SlashmailBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub mail_rr: request_response::Behaviour<MailCodec>,
    pub ping: ping::Behaviour,
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

        // Gossipsub with message signing, content-based deduplication, and tuned mesh.
        //
        // Topic hashing: callers use `gossipsub::Sha256Topic` so topic strings are
        // never leaked on the wire — peers see only the SHA-256 hash.
        //
        // Message ID: derived from SHA-256(data) to deduplicate by content rather
        // than by (source, seqno), which avoids re-processing identical envelopes
        // relayed through different paths.
        //
        // Mesh parameters are tuned for a small-to-medium overlay:
        //   mesh_n = 4       target mesh peers per topic
        //   mesh_n_low = 2   minimum before grafting
        //   mesh_n_high = 8  maximum before pruning
        //   gossip_lazy = 3  peers receiving IHAVE gossip each heartbeat
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .mesh_n(4)
            .mesh_n_low(2)
            .mesh_n_high(8)
            .gossip_lazy(3)
            .max_transmit_size(MAX_GOSSIPSUB_MESSAGE_SIZE)
            .message_id_fn(|msg: &gossipsub::Message| {
                let hash = Sha256::digest(&msg.data);
                gossipsub::MessageId::from(hash.to_vec())
            })
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
            ping,
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
        let topic = gossipsub::Sha256Topic::new("pub_general");
        assert!(behaviour.gossipsub.subscribe(&topic).is_ok());
        assert!(behaviour.gossipsub.unsubscribe(&topic).is_ok());
    }

    #[test]
    fn behaviour_gossipsub_accepts_subscription() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = make_behaviour(&key);
        let topic = gossipsub::Sha256Topic::new("pub_general");
        let result = behaviour.gossipsub.subscribe(&topic);
        assert!(result.is_ok());
    }

    #[test]
    fn behaviour_gossipsub_sha256_topic_hides_plaintext() {
        // Sha256Topic hashes the topic string so the raw name is never on the wire.
        let topic = gossipsub::Sha256Topic::new("pub_secret_room");
        let hash = topic.hash();
        assert_ne!(hash.as_str(), "pub_secret_room");
        // The hash string must not contain the plaintext topic.
        assert!(!hash.as_str().contains("pub_secret_room"));
    }

    #[test]
    fn behaviour_gossipsub_duplicate_subscribe_returns_false() {
        let key = Keypair::generate_ed25519();
        let mut behaviour = make_behaviour(&key);
        let topic = gossipsub::Sha256Topic::new("pub_dup");
        assert_eq!(behaviour.gossipsub.subscribe(&topic).unwrap(), true);
        assert_eq!(behaviour.gossipsub.subscribe(&topic).unwrap(), false);
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
