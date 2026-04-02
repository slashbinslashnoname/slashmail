//! Binary codec for message envelopes: bincode serialization + zstd compression.

use anyhow::Result;

use crate::compress;
use crate::types::Envelope;

/// Encode an [`Envelope`] to bytes (bincode + zstd).
pub fn encode(envelope: &Envelope) -> Result<Vec<u8>> {
    let bin = bincode::serialize(envelope)?;
    compress::compress(&bin)
}

/// Decode bytes back into an [`Envelope`] (zstd + bincode).
pub fn decode(data: &[u8]) -> Result<Envelope> {
    let bin = compress::decompress(data)?;
    Ok(bincode::deserialize(&bin)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_envelope() -> Envelope {
        Envelope {
            id: Uuid::new_v4(),
            sender_pubkey: [0xAA; 32],
            swarm_id: "test-swarm".into(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            timestamp: Utc::now(),
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
