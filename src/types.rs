//! Shared domain types.

use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Core wire-format envelope for all messages.
///
/// Carried over the network via bincode serialization and zstd compression.
/// Used by both inbound and outbound pipelines.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Unique message identifier.
    pub id: Uuid,
    /// Ed25519 public key of the sender (32 bytes).
    pub sender_pubkey: [u8; 32],
    /// Optional recipient peer. `None` for public/broadcast messages.
    pub recipient: Option<PeerId>,
    /// Swarm / topic this message belongs to.
    pub swarm_id: String,
    /// Opaque message payload (cleartext or ciphertext depending on pipeline stage).
    pub payload: Vec<u8>,
    /// Ed25519 signature over the full envelope (64 bytes when signed, empty before signing).
    pub signature: Vec<u8>,
    /// When the envelope was created.
    pub timestamp: DateTime<Utc>,
    /// Tags for categorisation. Plaintext for public messages, encrypted base64
    /// for private messages.
    pub tags: Vec<String>,
}

impl Envelope {
    /// Create a new envelope with an auto-generated id and current timestamp.
    /// The signature field is left empty; use [`message::codec::encode`] to sign.
    pub fn new(sender_pubkey: [u8; 32], swarm_id: String, payload: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender_pubkey,
            recipient: None,
            swarm_id,
            payload,
            signature: Vec::new(),
            timestamp: Utc::now(),
            tags: Vec::new(),
        }
    }

    /// Produce deterministic bytes covering **all** envelope fields except the
    /// signature itself.  Used as the message fed to Ed25519 sign / verify so
    /// that metadata (id, sender_pubkey, recipient, swarm_id, timestamp, tags)
    /// is covered by the signature, not just the payload.
    ///
    /// The canonical form is simply the bincode serialization of the envelope
    /// with `signature` set to an empty vec (the same sentinel value used
    /// before signing).  Because bincode serialization is deterministic for
    /// identical input (confirmed by the `bincode_deterministic` unit test),
    /// this is safe to use as a signing message.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut canonical = self.clone();
        canonical.signature = Vec::new();
        bincode::serialize(&canonical).expect("bincode serialization of Envelope is infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_new_generates_id_and_timestamp() {
        let pubkey = [0xAA; 32];
        let env = Envelope::new(pubkey, "my-swarm".into(), vec![1, 2, 3]);
        assert_eq!(env.sender_pubkey, pubkey);
        assert_eq!(env.swarm_id, "my-swarm");
        assert_eq!(env.payload, vec![1, 2, 3]);
        assert_eq!(env.recipient, None);
        assert!(env.tags.is_empty());
        // id should be a valid v4 UUID
        assert_eq!(env.id.get_version_num(), 4);
    }

    #[test]
    fn envelope_new_with_recipient_and_tags() {
        let pubkey = [0xBB; 32];
        let recipient = PeerId::random();
        let mut env = Envelope::new(pubkey, "dm-swarm".into(), vec![5, 6]);
        env.recipient = Some(recipient);
        env.tags = vec!["urgent".into(), "encrypted-tag".into()];

        assert_eq!(env.recipient, Some(recipient));
        assert_eq!(env.tags, vec!["urgent", "encrypted-tag"]);
    }

    #[test]
    fn bincode_roundtrip() {
        let env = Envelope::new([0x42; 32], "test-swarm".into(), vec![0xDE, 0xAD]);
        let encoded = bincode::serialize(&env).unwrap();
        let decoded: Envelope = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn bincode_roundtrip_with_recipient() {
        let mut env = Envelope::new([0x42; 32], "test-swarm".into(), vec![0xDE, 0xAD]);
        env.recipient = Some(PeerId::random());
        env.tags = vec!["tag1".into(), "tag2".into()];
        let encoded = bincode::serialize(&env).unwrap();
        let decoded: Envelope = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn json_roundtrip() {
        let env = Envelope::new([0x01; 32], "json-swarm".into(), vec![9, 8, 7]);
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn json_roundtrip_with_recipient_and_tags() {
        let mut env = Envelope::new([0x01; 32], "json-swarm".into(), vec![9, 8, 7]);
        env.recipient = Some(PeerId::random());
        env.tags = vec!["inbox".into()];
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn signable_bytes_excludes_signature() {
        let mut env = Envelope::new([0xAA; 32], "s".into(), vec![1, 2, 3]);
        let bytes_before = env.signable_bytes();
        env.signature = vec![0xDE; 64];
        let bytes_after = env.signable_bytes();
        assert_eq!(bytes_before, bytes_after, "signable_bytes must not depend on signature field");
    }

    #[test]
    fn signable_bytes_differs_on_metadata_change() {
        let env = Envelope::new([0xAA; 32], "swarm-a".into(), vec![1]);
        let mut env2 = env.clone();
        env2.swarm_id = "swarm-b".into();
        assert_ne!(env.signable_bytes(), env2.signable_bytes());
    }

    #[test]
    fn bincode_deterministic() {
        let ts = Utc::now();
        let env = Envelope {
            id: Uuid::nil(),
            sender_pubkey: [0xFF; 32],
            recipient: None,
            swarm_id: "s".into(),
            payload: vec![1],
            signature: vec![0xAB; 64],
            timestamp: ts,
            tags: vec!["a".into()],
        };
        let a = bincode::serialize(&env).unwrap();
        let b = bincode::serialize(&env).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bincode_deserialize_garbage_fails() {
        let result = bincode::deserialize::<Envelope>(&[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }
}
