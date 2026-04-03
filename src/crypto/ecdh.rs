//! Ed25519-to-X25519 key derivation and ECDH shared secret computation.
//!
//! Converts Ed25519 signing keys to X25519 Diffie-Hellman keys, then computes
//! a shared secret suitable for use with XChaCha20-Poly1305.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};

use super::signing::{Keypair, PublicKey};

/// An X25519 static secret derived from an Ed25519 signing key.
pub struct X25519Secret(StaticSecret);

/// An X25519 public key derived from an Ed25519 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519Public(X25519DalekPublicKey);

/// Derive an X25519 static secret from an Ed25519 signing key.
///
/// Uses `SigningKey::to_scalar_bytes()` which produces the clamped scalar
/// from the SHA-512 expansion of the Ed25519 seed — the standard
/// Ed25519-to-X25519 conversion (RFC 7748 / libsodium `crypto_sign_ed25519_sk_to_curve25519`).
pub fn ed25519_to_x25519_secret(signing_key: &Keypair) -> X25519Secret {
    let scalar_bytes = signing_key.to_scalar_bytes();
    X25519Secret(StaticSecret::from(scalar_bytes))
}

/// Derive an X25519 public key from an Ed25519 verifying key.
///
/// Converts the Edwards-form public point to Montgomery form.
pub fn ed25519_to_x25519_public(verifying_key: &PublicKey) -> X25519Public {
    let montgomery = verifying_key.to_montgomery();
    X25519Public(X25519DalekPublicKey::from(montgomery.to_bytes()))
}

/// Compute a 32-byte shared secret from our Ed25519 signing key and
/// the recipient's Ed25519 verifying key.
///
/// Performs Ed25519→X25519 conversion on both keys, then runs X25519 ECDH.
/// The raw DH output is hashed with SHA-256 to produce a uniform 256-bit key
/// suitable for XChaCha20-Poly1305.
pub fn derive_shared_secret(our_key: &Keypair, their_key: &PublicKey) -> [u8; 32] {
    let our_secret = ed25519_to_x25519_secret(our_key);
    let their_public = ed25519_to_x25519_public(their_key);
    let raw_shared = our_secret.0.diffie_hellman(&their_public.0);
    // Hash the raw DH output to get a uniform key
    let mut hasher = Sha256::new();
    hasher.update(raw_shared.as_bytes());
    hasher.finalize().into()
}

/// Encrypt a message for a specific recipient using ECDH-derived shared secret.
///
/// Derives a shared secret from the sender's Ed25519 key and the recipient's
/// Ed25519 public key, then encrypts with XChaCha20-Poly1305.
pub fn seal_for(
    our_key: &Keypair,
    their_key: &PublicKey,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let shared = derive_shared_secret(our_key, their_key);
    super::encryption::seal(&shared, plaintext)
}

/// Decrypt a message from a specific sender using ECDH-derived shared secret.
///
/// Derives a shared secret from the recipient's Ed25519 key and the sender's
/// Ed25519 public key, then decrypts with XChaCha20-Poly1305.
pub fn open_from(
    our_key: &Keypair,
    their_key: &PublicKey,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let shared = derive_shared_secret(our_key, their_key);
    super::encryption::open(&shared, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;

    #[test]
    fn x25519_public_matches_secret() {
        let ed_key = generate_keypair();
        let x_secret = ed25519_to_x25519_secret(&ed_key);
        let x_public = ed25519_to_x25519_public(&ed_key.verifying_key());
        // The X25519 public key derived from the verifying key should match
        // the public key derived from the secret.
        let public_from_secret = X25519DalekPublicKey::from(&x_secret.0);
        assert_eq!(x_public.0.as_bytes(), public_from_secret.as_bytes());
    }

    #[test]
    fn shared_secret_is_symmetric() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let secret_ab = derive_shared_secret(&alice, &bob.verifying_key());
        let secret_ba = derive_shared_secret(&bob, &alice.verifying_key());
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn shared_secret_differs_per_pair() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();
        let ab = derive_shared_secret(&alice, &bob.verifying_key());
        let ac = derive_shared_secret(&alice, &carol.verifying_key());
        assert_ne!(ab, ac);
    }

    #[test]
    fn seal_for_open_from_roundtrip() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let msg = b"hello bob, this is alice";
        let encrypted = seal_for(&alice, &bob.verifying_key(), msg).unwrap();
        let decrypted = open_from(&bob, &alice.verifying_key(), &encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn open_from_wrong_sender_fails() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();
        let encrypted = seal_for(&alice, &bob.verifying_key(), b"secret").unwrap();
        // Bob tries to decrypt thinking it came from carol — wrong shared secret
        assert!(open_from(&bob, &carol.verifying_key(), &encrypted).is_err());
    }

    #[test]
    fn open_from_wrong_recipient_fails() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();
        let encrypted = seal_for(&alice, &bob.verifying_key(), b"for bob only").unwrap();
        // Carol tries to decrypt — wrong shared secret
        assert!(open_from(&carol, &alice.verifying_key(), &encrypted).is_err());
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let secret = derive_shared_secret(&alice, &bob.verifying_key());
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn self_encryption_roundtrip() {
        // Encrypt to self (sender == recipient)
        let alice = generate_keypair();
        let msg = b"note to self";
        let encrypted = seal_for(&alice, &alice.verifying_key(), msg).unwrap();
        let decrypted = open_from(&alice, &alice.verifying_key(), &encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
