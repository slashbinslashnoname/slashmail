//! Swarm identification and topic hashing.

use sha2::{Digest, Sha256};
use std::fmt;

/// Prefix for public (broadcast) swarm IDs.
const PUBLIC_PREFIX: &str = "pub_";
/// Prefix for private (direct-message) swarm IDs.
const PRIVATE_PREFIX: &str = "prv_";

/// The kind of swarm a message belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmKind {
    /// A public broadcast swarm.
    Public(String),
    /// A private direct-message swarm.
    Private(String),
}

impl fmt::Display for SwarmKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwarmKind::Public(id) => write!(f, "{PUBLIC_PREFIX}{id}"),
            SwarmKind::Private(id) => write!(f, "{PRIVATE_PREFIX}{id}"),
        }
    }
}

/// Error returned when a swarm ID has an unrecognised prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSwarmId(pub String);

impl fmt::Display for InvalidSwarmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid swarm id: {}", self.0)
    }
}

impl std::error::Error for InvalidSwarmId {}

/// Parse a swarm ID string into a [`SwarmKind`].
///
/// Expects the format `pub_<name>` or `prv_<name>`.
pub fn parse_swarm_id(id: &str) -> Result<SwarmKind, InvalidSwarmId> {
    if let Some(name) = id.strip_prefix(PUBLIC_PREFIX) {
        if name.is_empty() {
            return Err(InvalidSwarmId(id.to_string()));
        }
        Ok(SwarmKind::Public(name.to_string()))
    } else if let Some(name) = id.strip_prefix(PRIVATE_PREFIX) {
        if name.is_empty() {
            return Err(InvalidSwarmId(id.to_string()));
        }
        Ok(SwarmKind::Private(name.to_string()))
    } else {
        Err(InvalidSwarmId(id.to_string()))
    }
}

/// Compute a SHA-256 topic hash for a swarm ID.
///
/// This is used as the gossipsub topic identifier.
pub fn topic_hash(swarm_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(swarm_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_swarm() {
        let kind = parse_swarm_id("pub_general").unwrap();
        assert_eq!(kind, SwarmKind::Public("general".into()));
        assert_eq!(kind.to_string(), "pub_general");
    }

    #[test]
    fn parse_private_swarm() {
        let kind = parse_swarm_id("prv_alice_bob").unwrap();
        assert_eq!(kind, SwarmKind::Private("alice_bob".into()));
        assert_eq!(kind.to_string(), "prv_alice_bob");
    }

    #[test]
    fn parse_missing_prefix_fails() {
        assert!(parse_swarm_id("general").is_err());
    }

    #[test]
    fn parse_empty_name_fails() {
        assert!(parse_swarm_id("pub_").is_err());
        assert!(parse_swarm_id("prv_").is_err());
    }

    #[test]
    fn parse_unknown_prefix_fails() {
        let err = parse_swarm_id("xyz_room").unwrap_err();
        assert_eq!(err.0, "xyz_room");
    }

    #[test]
    fn topic_hash_deterministic() {
        let h1 = topic_hash("pub_general");
        let h2 = topic_hash("pub_general");
        assert_eq!(h1, h2);
    }

    #[test]
    fn topic_hash_different_inputs() {
        let h1 = topic_hash("pub_general");
        let h2 = topic_hash("prv_alice_bob");
        assert_ne!(h1, h2);
    }

    #[test]
    fn topic_hash_is_32_bytes() {
        let h = topic_hash("pub_test");
        assert_eq!(h.len(), 32);
    }
}
