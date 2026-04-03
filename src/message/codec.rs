//! Binary codec for message envelopes: bincode serialization + zstd compression.
//! Encode signs the full envelope (all fields except signature); decode preserves
//! the signature for caller verification.
//!
//! Wire format: `[version_byte | compressed_bincode...]`
//! Version 1 is the current format.

use anyhow::{bail, Result};

use crate::compress;
use crate::crypto::signing::{self, Keypair};
use crate::types::Envelope;

/// Current codec version. Bumped on breaking bincode layout changes.
pub const CODEC_VERSION: u8 = 1;

/// Encode an [`Envelope`] to bytes (sign full envelope, bincode, zstd, version prefix).
///
/// Signs all envelope fields (via [`Envelope::signable_bytes`]) with the given
/// keypair and stores the 64-byte Ed25519 signature before serialization.
pub fn encode(envelope: &Envelope, keypair: &Keypair) -> Result<Vec<u8>> {
    let mut signed = envelope.clone();
    let sig = signing::sign(keypair, &signed.signable_bytes());
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
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_ok());
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
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_recipient() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.recipient = Some(PeerId::random()); // tamper metadata

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_swarm_id() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.swarm_id = "evil-swarm".into(); // tamper metadata

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_timestamp() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.timestamp = Utc::now() + chrono::Duration::hours(1); // tamper metadata

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_tags() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();
        envelope.tags = vec!["original".into()];

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.tags = vec!["injected".into()]; // tamper metadata

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_id() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        decoded.id = Uuid::new_v4(); // tamper metadata

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_sender_pubkey() {
        let kp = generate_keypair();
        let mut envelope = sample_envelope();
        envelope.sender_pubkey = kp.verifying_key().to_bytes();

        let encoded = encode(&envelope, &kp).unwrap();
        let mut decoded = decode(&encoded).unwrap();
        let other_kp = generate_keypair();
        decoded.sender_pubkey = other_kp.verifying_key().to_bytes(); // spoof sender

        let sig = Signature::from_slice(&decoded.signature).unwrap();
        // verify against the spoofed key — must fail (wrong key AND wrong signed bytes)
        assert!(sign::verify(&other_kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
        // verify against original key also fails because signed bytes changed
        assert!(sign::verify(&kp.verifying_key(), &decoded.signable_bytes(), &sig).is_err());
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
    fn decode_rejects_old_version_zero() {
        let kp = generate_keypair();
        let envelope = sample_envelope();
        let mut encoded = encode(&envelope, &kp).unwrap();
        encoded[0] = 0; // hypothetical old version
        let err = decode(&encoded).unwrap_err();
        assert!(err.to_string().contains("unsupported codec version 0"));
    }

    #[test]
    fn decode_rejects_future_version() {
        let kp = generate_keypair();
        let envelope = sample_envelope();
        let mut encoded = encode(&envelope, &kp).unwrap();
        encoded[0] = CODEC_VERSION + 1; // future version
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

    #[test]
    fn decode_rejects_version_only_payload() {
        // Just the version byte with no compressed body — should not panic, must error.
        let result = decode(&[CODEC_VERSION]);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::Signature;
    use libp2p::PeerId;
    use proptest::prelude::*;
    use uuid::Uuid;

    /// Strategy for arbitrary tag strings (printable ASCII, 0..64 chars).
    fn arb_tag() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{0,64}"
    }

    /// Strategy for arbitrary tag lists (0..8 tags).
    fn arb_tags() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(arb_tag(), 0..8)
    }

    /// Strategy for arbitrary payloads (0..4096 bytes).
    fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..4096)
    }

    /// Strategy for an optional PeerId.
    fn arb_recipient() -> impl Strategy<Value = Option<PeerId>> {
        prop::option::of(any::<[u8; 32]>().prop_map(|bytes| {
            // Derive a deterministic PeerId from random bytes via an ed25519 keypair.
            let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(bytes.to_vec())
                .expect("32 bytes is a valid ed25519 secret");
            let kp = libp2p::identity::ed25519::Keypair::from(secret);
            let pub_key = libp2p::identity::PublicKey::from(kp.public());
            PeerId::from_public_key(&pub_key)
        }))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn roundtrip_preserves_payload(payload in arb_payload()) {
            let kp = generate_keypair();
            let mut env = crate::types::Envelope::new(
                kp.verifying_key().to_bytes(),
                "proptest-swarm".into(),
                payload.clone(),
            );
            env.signature = Vec::new();

            let encoded = encode(&env, &kp).unwrap();
            let decoded = decode(&encoded).unwrap();

            prop_assert_eq!(&decoded.payload, &payload);
            prop_assert_eq!(decoded.id, env.id);
            prop_assert_eq!(decoded.swarm_id, env.swarm_id);
        }

        #[test]
        fn roundtrip_preserves_tags(tags in arb_tags()) {
            let kp = generate_keypair();
            let mut env = crate::types::Envelope::new(
                kp.verifying_key().to_bytes(),
                "proptest-swarm".into(),
                vec![1, 2, 3],
            );
            env.tags = tags.clone();

            let encoded = encode(&env, &kp).unwrap();
            let decoded = decode(&encoded).unwrap();

            prop_assert_eq!(&decoded.tags, &tags);
        }

        #[test]
        fn roundtrip_preserves_all_fields(
            payload in arb_payload(),
            tags in arb_tags(),
            recipient in arb_recipient(),
            swarm_id in "[a-z0-9-]{1,32}",
            _sender_key_seed in any::<[u8; 32]>(),
            ts_secs in 0i64..4_000_000_000i64,
        ) {
            let kp = generate_keypair();
            let ts = Utc.timestamp_opt(ts_secs, 0).single()
                .unwrap_or_else(|| Utc::now());

            let env = crate::types::Envelope {
                id: Uuid::new_v4(),
                sender_pubkey: kp.verifying_key().to_bytes(),
                recipient,
                swarm_id,
                payload,
                signature: Vec::new(),
                timestamp: ts,
                tags,
            };

            let encoded = encode(&env, &kp).unwrap();
            let decoded = decode(&encoded).unwrap();

            // All fields except signature must roundtrip exactly.
            prop_assert_eq!(decoded.id, env.id);
            prop_assert_eq!(decoded.sender_pubkey, env.sender_pubkey);
            prop_assert_eq!(decoded.recipient, env.recipient);
            prop_assert_eq!(&decoded.swarm_id, &env.swarm_id);
            prop_assert_eq!(&decoded.payload, &env.payload);
            prop_assert_eq!(decoded.timestamp, env.timestamp);
            prop_assert_eq!(&decoded.tags, &env.tags);

            // Signature must be valid.
            prop_assert_eq!(decoded.signature.len(), 64);
            let sig = Signature::from_slice(&decoded.signature).unwrap();
            prop_assert!(
                crate::crypto::signing::verify(
                    &kp.verifying_key(),
                    &decoded.signable_bytes(),
                    &sig,
                ).is_ok()
            );
        }
    }
}
