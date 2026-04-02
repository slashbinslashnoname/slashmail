use libp2p::{gossipsub, identify, kad, mdns, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
pub struct SlashmailBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}
