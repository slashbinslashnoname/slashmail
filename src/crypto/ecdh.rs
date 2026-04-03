//! Ed25519-to-X25519 key derivation and ECDH shared secret computation.
//!
//! Converts Ed25519 signing keys to X25519 Diffie-Hellman keys, then computes
//! a shared secret suitable for use with XChaCha20-Poly1305.
//!
//! All types holding key material derive [`Zeroize`] and [`ZeroizeOnDrop`] so
//! secrets are scrubbed from memory when they go out of scope.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::signing::{Keypair, PublicKey};

/// An X25519 static secret derived from an Ed25519 signing key.
///
/// The inner `StaticSecret` implements `Zeroize + ZeroizeOnDrop` via
/// the x25519-dalek `zeroize` feature; we derive the same on the wrapper.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(StaticSecret);

/// An X25519 public key derived from an Ed25519 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519Public(X25519DalekPublicKey);

/// A 32-byte shared secret derived from ECDH, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

/// Derive an X25519 static secret from an Ed25519 signing key.
///
/// Uses `SigningKey::to_scalar_bytes()` which produces the clamped scalar
/// from the SHA-512 expansion of the Ed25519 seed — the standard
/// Ed25519-to-X25519 conversion (RFC 7748 / libsodium `crypto_sign_ed25519_sk_to_curve25519`).
pub fn ed25519_to_x25519_secret(signing_key: &Keypair) -> X25519Secret {
    let scalar_bytes = Zeroizing::new(signing_key.to_scalar_bytes());
    X25519Secret(StaticSecret::from(*scalar_bytes))
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
///
/// Returns a [`SharedSecret`] that is zeroized when dropped.
pub fn derive_shared_secret(our_key: &Keypair, their_key: &PublicKey) -> SharedSecret {
    let our_secret = ed25519_to_x25519_secret(our_key);
    let their_public = ed25519_to_x25519_public(their_key);
    let raw_shared = our_secret.0.diffie_hellman(&their_public.0);
    // Hash the raw DH output to get a uniform key
    let mut hasher = Sha256::new();
    hasher.update(raw_shared.as_bytes());
    SharedSecret(hasher.finalize().into())
}

impl SharedSecret {
    /// Access the raw 32-byte key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
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
    super::encryption::seal(shared.as_bytes(), plaintext)
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
    super::encryption::open(shared.as_bytes(), data)
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
        assert_eq!(secret_ab.as_bytes(), secret_ba.as_bytes());
    }

    #[test]
    fn shared_secret_differs_per_pair() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();
        let ab = derive_shared_secret(&alice, &bob.verifying_key());
        let ac = derive_shared_secret(&alice, &carol.verifying_key());
        assert_ne!(ab.as_bytes(), ac.as_bytes());
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
        assert_eq!(secret.as_bytes().len(), 32);
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

    #[test]
    fn x25519_secret_is_zeroize_on_drop() {
        // Compile-time proof: X25519Secret derives Zeroize + ZeroizeOnDrop.
        // If the derives were removed, this test would fail to compile.
        fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize::<X25519Secret>();
    }

    #[test]
    fn shared_secret_is_zeroize_on_drop() {
        fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize::<SharedSecret>();
    }

    /// Verify Ed25519→X25519 secret-key derivation against libsodium's
    /// `crypto_sign_ed25519_sk_to_curve25519` test vector.
    #[test]
    fn ed25519_to_x25519_known_vector() {
        // Libsodium primary test vector (ed25519_convert.c / ed25519_convert.exp)
        let seed_hex = "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee";
        let expected_x25519_pk_hex =
            "f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50";

        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let mut expected_pk = [0u8; 32];
        for (i, byte) in expected_pk.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&expected_x25519_pk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }

        let signing_key = Keypair::from_bytes(&seed);
        let x25519_pub = ed25519_to_x25519_public(&signing_key.verifying_key());
        assert_eq!(
            x25519_pub.0.as_bytes(),
            &expected_pk,
            "X25519 public key does not match libsodium test vector"
        );
    }

    /// Encrypt individual tags with ECDH-derived shared secret and decrypt them,
    /// mimicking the engine's private-message tag handling.
    #[test]
    fn tag_encrypt_decrypt_roundtrip() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let shared = derive_shared_secret(&alice, &bob.verifying_key());
        let tags = vec!["inbox", "urgent", "étiquette"];

        for tag in &tags {
            let ciphertext =
                super::super::encryption::seal(shared.as_bytes(), tag.as_bytes()).unwrap();
            // Ciphertext must differ from plaintext
            assert_ne!(&ciphertext, tag.as_bytes());
            // Recipient derives same shared secret and decrypts
            let shared_bob = derive_shared_secret(&bob, &alice.verifying_key());
            let plaintext =
                super::super::encryption::open(shared_bob.as_bytes(), &ciphertext).unwrap();
            assert_eq!(plaintext, tag.as_bytes());
        }
    }

    /// Tag decryption with wrong key must fail.
    #[test]
    fn tag_decrypt_wrong_key_fails() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();
        let shared_ab = derive_shared_secret(&alice, &bob.verifying_key());
        let ciphertext =
            super::super::encryption::seal(shared_ab.as_bytes(), b"secret-tag").unwrap();
        // Carol cannot decrypt a tag encrypted with Alice↔Bob shared secret
        let shared_carol = derive_shared_secret(&carol, &alice.verifying_key());
        assert!(
            super::super::encryption::open(shared_carol.as_bytes(), &ciphertext).is_err()
        );
    }

    /// Runtime check: SharedSecret memory is zeroed after drop.
    ///
    /// We allocate on the heap via Box, capture the pointer, drop the value,
    /// then verify the backing memory has been overwritten to all zeros.
    #[test]
    fn zeroize_shared_secret_overwrites_buffer() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let secret = Box::new(derive_shared_secret(&alice, &bob.verifying_key()));
        // Verify it's non-zero before drop
        let non_zero = secret.as_bytes().iter().any(|&b| b != 0);
        assert!(non_zero, "shared secret should be non-zero");
        let ptr = secret.as_bytes().as_ptr();
        drop(secret);
        // SAFETY: We just dropped the Box; the allocator hasn't reused this memory yet.
        // We read 32 bytes that were formerly the SharedSecret inner buffer.
        let after_drop: [u8; 32] = unsafe { std::ptr::read(ptr as *const [u8; 32]) };
        assert_eq!(
            after_drop,
            [0u8; 32],
            "SharedSecret buffer was not zeroed on drop"
        );
    }
}
