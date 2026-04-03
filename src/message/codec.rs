//! Binary codec for message envelopes: bincode serialization + zstd compression.
//! Encode signs the payload; decode preserves the signature for caller verification.
//!
//! Wire format: `[version_byte | compressed_bincode...]`
//! Version 1 is the current format.

use anyhow::{bail, Result};

use crate::compress;
use crate::crypto::signing::{self, Keypair};
use crate::types::Envelope;

/// Current codec version. Bumped on breaking bincode layout changes.
pub const CODEC_VERSION: u8 = 1;

/// Encode an [`Envelope`] to bytes (sign payload, bincode, zstd, version prefix).
///
/// Signs the payload with the given keypair and stores the 64-byte Ed25519
/// signature in the envelope before serialization.
pub fn encode(envelope: &Envelope, keypair: &Keypair) -> Result<Vec<u8>> {
    let mut signed = envelope.clone();
    let sig = signing::sign(keypair, &signed.payload);
    signed.signature = sig.to_bytes().to_vec();
    let bin = bincode::serialize(&signed)?;
    let compressed = compress::compress(&bin)?;
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(CODEC_VERSION);
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Decode bytes back into an [`Envelope`] (version check, zstd, bincode).
///
/// The returned envelope carries the signature for the caller to verify.
pub fn decode(data: &[u8]) -> Result<Envelope> {
    if data.is_empty() {
        bail!("empty codec payload");
    }
    let version = data[0];
    if version != CODEC_VERSION {
        bail!(
            "unsupported codec version {version}, expected {CODEC_VERSION}"
        );
    }
    let bin = compress::decompress(&data[1..])?;
    Ok(bincode::deserialize(&bin)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::{self as sign, generate_keypair};
    use chrono::Utc;
    use ed25519_dalek::Signature;
    use libp2p::PeerId;
    use uuid::Uuid;

    fn sample_envelope() -> Envelope {
        Envelope {
            id: Uuid::new_v4(),
            sender_pubkey: [0xAA; 32],
            recipient: None,
            swarm_id: "test-swarm".into(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: Vec::new(),
            timestamp: Utc::now(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.signature.len(), 64);
        assert_eq!(decoded.id, envelope.id);
        assert_eq!(decoded.sender_pubkey, envelope.sender_pubkey);
        assert_eq!(decoded.swarm_id, envelope.swarm_id);
        assert_eq!(decoded.payload, envelope.payload);
        assert_eq!(decoded.recipient, None);
        assert!(decoded.tags.is_empty());
    }

    #[test]
    fn roundtrip_with_recipient_and_tags() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();
        envelope.recipient = Some(PeerId::random());
        envelope.tags = vec!["inbox".into(), "ZW5jcnlwdGVk".into()];

        let encoded = encode(&envelope, &kp).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.recipient, envelope.recipient);
        assert_eq!(decoded.tags, envelope.tags);
    }

    #[test]
    fn signature_is_valid_after_encode() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let decoded = decode(&encoded).unwrap();

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.payload, &sig).is_ok());
    }

    #[test]
    fn signature_rejects_tampered_payload() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.payload = vec![0xFF; 4]; // tamper

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.payload, &sig).is_err());
    }

    #[test]
    fn encoded_starts_with_version_byte() {
        let kp = generate_keypair();
        let envelope = sample_envelope();
        let encoded = encode(&envelope, &kp).unwrap();
        assert_eq!(encoded[0], CODEC_VERSION);
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let kp = generate_keypair();
        let envelope = sample_envelope();
        let mut encoded = encode(&envelope, &kp).unwrap();
        encoded[0] = 0xFF; // bogus version
        let err = decode(&encoded).unwrap_err();
        assert!(err.to_string().contains("unsupported codec version"));
    }

    #[test]
    fn decode_rejects_empty_input() {
        let err = decode(&[]).unwrap_err();
        assert!(err.to_string().contains("empty codec payload"));
    }

    #[test]
    fn encoded_is_compressed() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.payload = vec![0xAA; 10_000];
        let encoded = encode(&envelope, &kp).unwrap();
        // Manually serialize with signature to compare sizes fairly.
        let mut with_sig = envelope.clone();
        with_sig.signature = vec![0; 64];
        let raw = bincode::serialize(&with_sig).unwrap();
        assert!(encoded.len() < raw.len(), "encoded should be smaller than raw bincode");
    }

    #[test]
    fn decode_garbage_fails() {
        // version byte + garbage
        let result = decode(&[CODEC_VERSION, 0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }
}
