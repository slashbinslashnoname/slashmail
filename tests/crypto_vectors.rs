//! Validate Ed25519→X25519 key derivation against published libsodium test vectors.
//!
//! These tests use curve25519-dalek / ed25519-dalek primitives directly to verify
//! that the derivation logic matches libsodium's `crypto_sign_ed25519_sk_to_curve25519`
//! and `crypto_sign_ed25519_pk_to_curve25519`.
//!
//! Reference: <https://github.com/jedisct1/libsodium/blob/master/test/default/ed25519_convert.c>

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Helper: decode a hex string to a fixed-size byte array.
fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "hex string length mismatch");
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Libsodium ed25519_convert test vector.
///
/// Source: libsodium test/default/ed25519_convert.c + ed25519_convert.exp
/// Seed:       421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee
/// Expected X25519 sk: 8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166
/// Expected X25519 pk: f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50
const LIBSODIUM_SEED_HEX: &str = "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee";
const LIBSODIUM_X25519_SK_HEX: &str =
    "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166";
const LIBSODIUM_X25519_PK_HEX: &str =
    "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50";

/// Apply RFC 7748 clamping to raw scalar bytes, matching libsodium's output format.
///
/// `to_scalar_bytes()` returns the raw SHA-512(seed)[0..32] before clamping.
/// libsodium's `crypto_sign_ed25519_sk_to_curve25519` returns the clamped form.
/// `StaticSecret::from()` applies clamping internally, so the derivation is
/// correct either way — this function just normalises for comparison.
fn clamp(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// Verify that `SigningKey::to_scalar_bytes()` (after clamping) produces the same
/// X25519 secret key as libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
#[test]
fn ed25519_sk_to_x25519_sk_matches_libsodium() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED_HEX);
    let signing_key = SigningKey::from_bytes(&seed);

    let scalar_bytes = clamp(signing_key.to_scalar_bytes());
    let expected_sk: [u8; 32] = hex_to_bytes(LIBSODIUM_X25519_SK_HEX);

    assert_eq!(
        scalar_bytes, expected_sk,
        "X25519 secret key derivation does not match libsodium vector\n\
         got:      {}\n\
         expected: {}",
        hex::encode(scalar_bytes),
        LIBSODIUM_X25519_SK_HEX,
    );
}

/// Verify that `VerifyingKey::to_montgomery()` produces the same X25519 public key
/// as libsodium's `crypto_sign_ed25519_pk_to_curve25519`.
#[test]
fn ed25519_pk_to_x25519_pk_matches_libsodium() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED_HEX);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let montgomery = verifying_key.to_montgomery();
    let expected_pk: [u8; 32] = hex_to_bytes(LIBSODIUM_X25519_PK_HEX);

    assert_eq!(
        montgomery.to_bytes(),
        expected_pk,
        "X25519 public key derivation does not match libsodium vector\n\
         got:      {}\n\
         expected: {}",
        hex::encode(montgomery.to_bytes()),
        LIBSODIUM_X25519_PK_HEX,
    );
}

/// Verify internal consistency: the X25519 public key derived from the Ed25519
/// public key (Edwards→Montgomery) matches the X25519 public key computed from
/// the derived X25519 secret key (scalar × basepoint).
///
/// This is the same check libsodium's ed25519_convert test performs in its loop.
#[test]
fn x25519_pk_from_sk_matches_pk_from_ed25519_pk() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED_HEX);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Derive X25519 secret from Ed25519 secret
    let scalar_bytes = signing_key.to_scalar_bytes();
    let x25519_secret = StaticSecret::from(scalar_bytes);

    // Derive X25519 public from Ed25519 public (Edwards→Montgomery)
    let x25519_pk_from_ed = verifying_key.to_montgomery();

    // Derive X25519 public from X25519 secret (scalar × basepoint)
    let x25519_pk_from_sk = X25519PublicKey::from(&x25519_secret);

    assert_eq!(
        x25519_pk_from_ed.to_bytes(),
        x25519_pk_from_sk.to_bytes(),
        "X25519 public keys derived via different paths do not match"
    );
}

/// Verify consistency across multiple random keypairs — the two derivation paths
/// (Edwards→Montgomery vs scalar×basepoint) must always agree.
///
/// Mirrors libsodium's 500-iteration random-keypair consistency check.
#[test]
fn derivation_consistency_random_keypairs() {
    use rand::rngs::OsRng;

    for _ in 0..500 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let scalar_bytes = signing_key.to_scalar_bytes();
        let x25519_secret = StaticSecret::from(scalar_bytes);

        let pk_from_ed = verifying_key.to_montgomery();
        let pk_from_sk = X25519PublicKey::from(&x25519_secret);

        assert_eq!(
            pk_from_ed.to_bytes(),
            pk_from_sk.to_bytes(),
            "Derivation mismatch for ed25519 seed: {}",
            hex::encode(signing_key.to_bytes()),
        );
    }
}

/// Verify that ECDH shared secret is symmetric — same result regardless of
/// which side is "ours" vs "theirs", using the libsodium seed as one party.
#[test]
fn ecdh_symmetry_with_libsodium_vector() {
    let seed_a: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED_HEX);
    let key_a = SigningKey::from_bytes(&seed_a);

    let key_b = SigningKey::generate(&mut rand::rngs::OsRng);

    // Derive X25519 keys
    let secret_a = StaticSecret::from(key_a.to_scalar_bytes());
    let secret_b = StaticSecret::from(key_b.to_scalar_bytes());
    let pub_a = X25519PublicKey::from(key_a.verifying_key().to_montgomery().to_bytes());
    let pub_b = X25519PublicKey::from(key_b.verifying_key().to_montgomery().to_bytes());

    let shared_ab = secret_a.diffie_hellman(&pub_b);
    let shared_ba = secret_b.diffie_hellman(&pub_a);

    assert_eq!(
        shared_ab.as_bytes(),
        shared_ba.as_bytes(),
        "ECDH shared secret is not symmetric"
    );
}

/// Simple hex encoder for error messages (avoids adding hex crate dependency).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
