//! Validate Ed25519→X25519 key derivation against published libsodium test vectors
//! and verify ECDH shared-secret symmetry.
//!
//! These tests use curve25519-dalek / ed25519-dalek primitives directly to verify
//! that the derivation logic matches libsodium's `crypto_sign_ed25519_sk_to_curve25519`
//! and `crypto_sign_ed25519_pk_to_curve25519`.
//!
//! The ECDH pipeline tested here mirrors `src/crypto/ecdh.rs`:
//!   1. Ed25519 seed → SigningKey → to_scalar_bytes() → StaticSecret (X25519)
//!   2. VerifyingKey → to_montgomery() → X25519 public key
//!   3. DH(our_secret, their_pub) → SHA-256 → 32-byte shared secret
//!
//! Reference: <https://github.com/jedisct1/libsodium/blob/master/test/default/ed25519_convert.c>

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
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

/// Mirror the project's `derive_shared_secret` pipeline:
/// Ed25519→X25519 conversion + raw DH + SHA-256 post-hash.
fn derive_shared_secret_mirror(our_key: &SigningKey, their_key: &SigningKey) -> [u8; 32] {
    let our_secret = StaticSecret::from(our_key.to_scalar_bytes());
    let their_pub =
        X25519PublicKey::from(their_key.verifying_key().to_montgomery().to_bytes());
    let raw_shared = our_secret.diffie_hellman(&their_pub);
    let mut hasher = Sha256::new();
    hasher.update(raw_shared.as_bytes());
    hasher.finalize().into()
}

/// Encrypt with XChaCha20-Poly1305 (mirrors `src/crypto/encryption.rs`).
fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes: [u8; 24] = rand::random();
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext).expect("encryption failed");
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt with XChaCha20-Poly1305 (mirrors `src/crypto/encryption.rs`).
fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    if data.len() < 24 {
        return Err("too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce, ciphertext).map_err(|_| "decryption failed")
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

/// Libsodium ed25519_convert primary test vector.
///
/// Source: libsodium test/default/ed25519_convert.c + ed25519_convert.exp
const LIBSODIUM_SEED: &str =
    "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee";
const LIBSODIUM_X25519_SK: &str =
    "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166";
const LIBSODIUM_X25519_PK: &str =
    "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50";

/// Additional deterministic seeds for cross-validation.
const SEED_ZERO: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const SEED_UNIT: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";
const SEED_AA: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SEED_FF: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SEED_DEADBEEF: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const SEED_CAFE: &str =
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";

// ---------------------------------------------------------------------------
// Tests: Ed25519 → X25519 key derivation against libsodium
// ---------------------------------------------------------------------------

/// Verify that `SigningKey::to_scalar_bytes()` (after clamping) produces the same
/// X25519 secret key as libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
#[test]
fn ed25519_sk_to_x25519_sk_matches_libsodium() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED);
    let signing_key = SigningKey::from_bytes(&seed);

    let scalar_bytes = clamp(signing_key.to_scalar_bytes());
    let expected_sk: [u8; 32] = hex_to_bytes(LIBSODIUM_X25519_SK);

    assert_eq!(
        scalar_bytes, expected_sk,
        "X25519 secret key derivation mismatch\n\
         got:      {}\n\
         expected: {}",
        hex::encode(scalar_bytes),
        LIBSODIUM_X25519_SK,
    );
}

/// Verify that `VerifyingKey::to_montgomery()` produces the same X25519 public key
/// as libsodium's `crypto_sign_ed25519_pk_to_curve25519`.
#[test]
fn ed25519_pk_to_x25519_pk_matches_libsodium() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let montgomery = verifying_key.to_montgomery();
    let expected_pk: [u8; 32] = hex_to_bytes(LIBSODIUM_X25519_PK);

    assert_eq!(
        montgomery.to_bytes(),
        expected_pk,
        "X25519 public key derivation mismatch\n\
         got:      {}\n\
         expected: {}",
        hex::encode(montgomery.to_bytes()),
        LIBSODIUM_X25519_PK,
    );
}

// ---------------------------------------------------------------------------
// Tests: Derivation path consistency (Edwards→Montgomery vs scalar×basepoint)
// ---------------------------------------------------------------------------

/// Verify internal consistency: X25519 public key derived from Ed25519 public
/// (Edwards→Montgomery) must match the one computed from the X25519 secret
/// (scalar × basepoint).
#[test]
fn x25519_pk_from_sk_matches_pk_from_ed25519_pk() {
    let seed: [u8; 32] = hex_to_bytes(LIBSODIUM_SEED);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());
    let pk_from_ed = verifying_key.to_montgomery();
    let pk_from_sk = X25519PublicKey::from(&x25519_secret);

    assert_eq!(
        pk_from_ed.to_bytes(),
        pk_from_sk.to_bytes(),
        "X25519 public keys derived via different paths do not match"
    );
}

/// Verify derivation consistency for multiple well-known seeds.
#[test]
fn derivation_consistency_known_seeds() {
    let seeds = [
        LIBSODIUM_SEED,
        SEED_ZERO,
        SEED_UNIT,
        SEED_AA,
        SEED_FF,
        SEED_DEADBEEF,
        SEED_CAFE,
    ];

    for seed_hex in &seeds {
        let seed: [u8; 32] = hex_to_bytes(seed_hex);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());
        let pk_from_ed = verifying_key.to_montgomery();
        let pk_from_sk = X25519PublicKey::from(&x25519_secret);

        assert_eq!(
            pk_from_ed.to_bytes(),
            pk_from_sk.to_bytes(),
            "Derivation mismatch for seed: {seed_hex}",
        );
    }
}

/// Verify consistency across 500 random keypairs — mirrors libsodium's random
/// keypair consistency check in ed25519_convert.c.
#[test]
fn derivation_consistency_random_keypairs() {
    use rand::rngs::OsRng;

    for _ in 0..500 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());
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

// ---------------------------------------------------------------------------
// Tests: ECDH symmetry — raw X25519 level
// ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub)
// ---------------------------------------------------------------------------

/// Verify raw ECDH symmetry across deterministic seed pairs.
#[test]
fn ecdh_symmetry_deterministic_raw() {
    let pairs: &[(&str, &str)] = &[
        (LIBSODIUM_SEED, SEED_ZERO),
        (LIBSODIUM_SEED, SEED_UNIT),
        (SEED_ZERO, SEED_UNIT),
        (SEED_AA, SEED_FF),
        (SEED_DEADBEEF, SEED_CAFE),
    ];

    for (seed_a_hex, seed_b_hex) in pairs {
        let key_a = SigningKey::from_bytes(&hex_to_bytes(seed_a_hex));
        let key_b = SigningKey::from_bytes(&hex_to_bytes(seed_b_hex));

        let secret_a = StaticSecret::from(key_a.to_scalar_bytes());
        let secret_b = StaticSecret::from(key_b.to_scalar_bytes());
        let pub_a = X25519PublicKey::from(key_a.verifying_key().to_montgomery().to_bytes());
        let pub_b = X25519PublicKey::from(key_b.verifying_key().to_montgomery().to_bytes());

        let shared_ab = secret_a.diffie_hellman(&pub_b);
        let shared_ba = secret_b.diffie_hellman(&pub_a);

        assert_eq!(
            shared_ab.as_bytes(),
            shared_ba.as_bytes(),
            "Raw ECDH not symmetric for seeds ({seed_a_hex}, {seed_b_hex})"
        );

        // Shared secret must not be all zeros
        assert_ne!(
            shared_ab.as_bytes(),
            &[0u8; 32],
            "ECDH shared secret is all zeros for seeds ({seed_a_hex}, {seed_b_hex})"
        );
    }
}

/// Verify raw ECDH symmetry with the libsodium seed and a random peer.
#[test]
fn ecdh_symmetry_with_libsodium_vector() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::generate(&mut rand::rngs::OsRng);

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

/// Verify ECDH symmetry across 100 random keypair combinations.
#[test]
fn ecdh_symmetry_random_keypairs() {
    use rand::rngs::OsRng;

    for _ in 0..100 {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        let secret_a = StaticSecret::from(key_a.to_scalar_bytes());
        let secret_b = StaticSecret::from(key_b.to_scalar_bytes());
        let pub_a = X25519PublicKey::from(key_a.verifying_key().to_montgomery().to_bytes());
        let pub_b = X25519PublicKey::from(key_b.verifying_key().to_montgomery().to_bytes());

        let shared_ab = secret_a.diffie_hellman(&pub_b);
        let shared_ba = secret_b.diffie_hellman(&pub_a);

        assert_eq!(
            shared_ab.as_bytes(),
            shared_ba.as_bytes(),
            "ECDH not symmetric for seeds ({}, {})",
            hex::encode(key_a.to_bytes()),
            hex::encode(key_b.to_bytes()),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: ECDH symmetry — through the project's derive_shared_secret pipeline
// (Ed25519→X25519 + DH + SHA-256 post-hash)
// ---------------------------------------------------------------------------

/// Verify that the full derivation pipeline (mirroring src/crypto/ecdh.rs)
/// is symmetric: derive(a, B) == derive(b, A).
#[test]
fn derive_shared_secret_symmetry_deterministic() {
    let pairs: &[(&str, &str)] = &[
        (LIBSODIUM_SEED, SEED_ZERO),
        (LIBSODIUM_SEED, SEED_UNIT),
        (SEED_DEADBEEF, SEED_CAFE),
        (SEED_AA, SEED_FF),
        (SEED_ZERO, SEED_FF),
    ];

    for (seed_a_hex, seed_b_hex) in pairs {
        let key_a = SigningKey::from_bytes(&hex_to_bytes(seed_a_hex));
        let key_b = SigningKey::from_bytes(&hex_to_bytes(seed_b_hex));

        let secret_ab = derive_shared_secret_mirror(&key_a, &key_b);
        let secret_ba = derive_shared_secret_mirror(&key_b, &key_a);

        assert_eq!(
            secret_ab, secret_ba,
            "derive_shared_secret not symmetric for seeds ({seed_a_hex}, {seed_b_hex})"
        );

        assert_ne!(
            secret_ab,
            [0u8; 32],
            "derived shared secret is all zeros"
        );
    }
}

/// Verify that different peer pairs produce different shared secrets.
#[test]
fn derive_shared_secret_differs_per_peer() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::from_bytes(&hex_to_bytes(SEED_ZERO));
    let key_c = SigningKey::from_bytes(&hex_to_bytes(SEED_UNIT));

    let ab = derive_shared_secret_mirror(&key_a, &key_b);
    let ac = derive_shared_secret_mirror(&key_a, &key_c);
    let bc = derive_shared_secret_mirror(&key_b, &key_c);

    assert_ne!(ab, ac, "a↔b should differ from a↔c");
    assert_ne!(ab, bc, "a↔b should differ from b↔c");
    assert_ne!(ac, bc, "a↔c should differ from b↔c");
}

/// Verify that derive_shared_secret is deterministic — same inputs always
/// produce the same output.
#[test]
fn derive_shared_secret_is_deterministic() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::from_bytes(&hex_to_bytes(SEED_ZERO));

    let first = derive_shared_secret_mirror(&key_a, &key_b);
    let second = derive_shared_secret_mirror(&key_a, &key_b);

    assert_eq!(first, second);
}

/// Verify that self-DH (a↔a) works and produces a non-zero, deterministic result.
#[test]
fn derive_shared_secret_self_agreement() {
    let key = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));

    let self_secret = derive_shared_secret_mirror(&key, &key);
    assert_ne!(self_secret, [0u8; 32], "Self-DH should not be zero");

    let again = derive_shared_secret_mirror(&key, &key);
    assert_eq!(self_secret, again, "Self-DH should be deterministic");
}

// ---------------------------------------------------------------------------
// Tests: Full seal/open roundtrip (ECDH + XChaCha20-Poly1305)
// ---------------------------------------------------------------------------

/// Verify that seal/open roundtrip works with ECDH-derived keys,
/// confirming the full pipeline end-to-end.
#[test]
fn seal_open_roundtrip_deterministic_keys() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::from_bytes(&hex_to_bytes(SEED_ZERO));

    let plaintext = b"crypto vectors test message";

    // A encrypts for B
    let shared_ab = derive_shared_secret_mirror(&key_a, &key_b);
    let ciphertext = seal(&shared_ab, plaintext);

    // B decrypts from A
    let shared_ba = derive_shared_secret_mirror(&key_b, &key_a);
    let recovered = open(&shared_ba, &ciphertext).expect("decryption should succeed");
    assert_eq!(recovered, plaintext);

    // Reverse direction: B encrypts for A
    let ciphertext2 = seal(&shared_ba, plaintext);
    let recovered2 = open(&shared_ab, &ciphertext2).expect("decryption should succeed");
    assert_eq!(recovered2, plaintext);
}

/// Verify that a third party cannot decrypt messages between two peers.
#[test]
fn seal_open_wrong_peer_fails() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::from_bytes(&hex_to_bytes(SEED_ZERO));
    let key_c = SigningKey::from_bytes(&hex_to_bytes(SEED_UNIT));

    let shared_ab = derive_shared_secret_mirror(&key_a, &key_b);
    let ciphertext = seal(&shared_ab, b"secret");

    // C cannot decrypt (wrong key)
    let shared_ac = derive_shared_secret_mirror(&key_a, &key_c);
    assert!(open(&shared_ac, &ciphertext).is_err());

    let shared_bc = derive_shared_secret_mirror(&key_b, &key_c);
    assert!(open(&shared_bc, &ciphertext).is_err());
}

// ---------------------------------------------------------------------------
// Tests: Pinned regression vector
// ---------------------------------------------------------------------------

/// Pin the derived shared-secret value for two known seeds.
///
/// If the derivation pipeline changes (scalar extraction, clamping, DH,
/// SHA-256 post-hash), this test catches the regression. The expected value
/// was computed by running the current implementation once.
#[test]
fn derive_shared_secret_pinned_regression() {
    let key_a = SigningKey::from_bytes(&hex_to_bytes(LIBSODIUM_SEED));
    let key_b = SigningKey::from_bytes(&hex_to_bytes(SEED_ZERO));

    let shared = derive_shared_secret_mirror(&key_a, &key_b);
    let shared_hex = hex::encode(shared);

    // Verify basic properties
    assert_eq!(shared_hex.len(), 64, "should be 32 bytes / 64 hex chars");
    assert_ne!(shared, [0u8; 32], "should not be all zeros");

    // Symmetry must hold
    let shared_rev = derive_shared_secret_mirror(&key_b, &key_a);
    assert_eq!(shared, shared_rev);

    // Pinned expected value (update if the pipeline legitimately changes)
    let expected = "ba7d3ad43a6e64764a8a75571c130a5ee13e0655fbf166478caaec5c062910d1";
    assert_eq!(
        shared_hex, expected,
        "derive_shared_secret output changed — if intentional, update the pinned vector"
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
