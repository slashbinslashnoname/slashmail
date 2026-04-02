//! Transport configuration for TCP + Noise + Yamux.
//!
//! In libp2p 0.54, the transport stack is configured via [`SwarmBuilder`] in
//! [`super::build_swarm`] using `.with_tcp(Config, noise::Config, yamux::Config)`.
//! This module re-exports the relevant configuration types for convenience.

pub use libp2p::noise;
pub use libp2p::tcp;
pub use libp2p::yamux;
