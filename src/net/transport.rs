//! Transport configuration: QUIC (primary) with TCP+Noise+Yamux (fallback).
//!
//! QUIC is UDP-based and better suited for NAT hole-punching (dcutr).
//! TCP+Noise+Yamux is kept as a fallback for environments where UDP is blocked.
//! The dual-stack is built via [`SwarmBuilder`] in [`super::build_swarm`].

pub use libp2p::noise;
pub use libp2p::tcp;
pub use libp2p::yamux;
