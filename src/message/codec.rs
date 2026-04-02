//! Binary codec for message envelopes: bincode serialization + zstd compression.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compress;

/// Wire-format envelope for network transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageEnvelope {
    pub id: Uuid,
    pub sender: String,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Encode a `MessageEnvelope` to bytes (bincode + zstd).
pub fn encode(envelope: &MessageEnvelope) -> Result<Vec<u8>> {
    let bin = bincode::serialize(envelope)?;
    compress::compress(&bin)
}

/// Decode bytes back into a `MessageEnvelope` (zstd + bincode).
pub fn decode(data: &[u8]) -> Result<MessageEnvelope> {
    let bin = compress::decompress(data)?;
    Ok(bincode::deserialize(&bin)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> MessageEnvelope {
        MessageEnvelope {
            id: Uuid::new_v4(),
            sender: "alice@example.com".into(),
            recipient: "bob@example.com".into(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: vec![1, 2, 3, 4, 5],
            created_at: Utc::now(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let envelope = sample_envelope();
        let encoded = encode(&envelope).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn encoded_is_compressed() {
        // A large payload should compress well.
        let mut envelope = sample_envelope();
        envelope.payload = vec![0xAA; 10_000];
        let encoded = encode(&envelope).unwrap();
        let raw = bincode::serialize(&envelope).unwrap();
        assert!(encoded.len() < raw.len(), "encoded should be smaller than raw bincode");
    }

    #[test]
    fn decode_garbage_fails() {
        let result = decode(&[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }
}
