//! Identity management: keypair generation, keyring storage, and identity loading.

use crate::crypto::signing::{self, Keypair, PublicKey};
use crate::error::AppError;
use crate::keystore;
use base64::Engine;

const KEYRING_ACCOUNT: &str = "identity-signing-key";

/// A user identity backed by an Ed25519 keypair.
#[derive(Debug)]
pub struct Identity {
    /// The Ed25519 signing keypair (private + public).
    keypair: Keypair,
}

impl Identity {
    /// Create an identity from an existing keypair.
    pub fn from_keypair(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Generate a fresh identity with a new random keypair.
    pub fn generate() -> Self {
        Self {
            keypair: signing::generate_keypair(),
        }
    }

    /// Store the private key in the OS keyring.
    pub fn store_in_keyring(&self) -> Result<(), AppError> {
        let secret_bytes = self.keypair.to_bytes();
        keystore::set_secret(KEYRING_ACCOUNT, &secret_bytes)
            .map_err(|e| AppError::Other(format!("failed to store key in keyring: {e}")))
    }

    /// Load an identity from the OS keyring.
    pub fn load_from_keyring() -> Result<Self, AppError> {
        let secret_bytes = keystore::get_secret(KEYRING_ACCOUNT)
            .map_err(|e| AppError::Other(format!("failed to load key from keyring: {e}")))?;

        let bytes: [u8; 32] = secret_bytes.try_into().map_err(|_| {
            AppError::Crypto("invalid key length in keyring (expected 32 bytes)".to_string())
        })?;

        let keypair = Keypair::from_bytes(&bytes);
        Ok(Self { keypair })
    }

    /// Delete the private key from the OS keyring.
    pub fn delete_from_keyring() -> Result<(), AppError> {
        keystore::delete_secret(KEYRING_ACCOUNT)
            .map_err(|e| AppError::Other(format!("failed to delete key from keyring: {e}")))
    }

    /// Return a reference to the signing keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Return the public key.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.verifying_key()
    }

    /// Return the public key encoded as base64.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_key().as_bytes())
    }

    /// Parse a base64-encoded public key.
    pub fn parse_public_key(b64: &str) -> Result<PublicKey, AppError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| AppError::Crypto(format!("invalid base64 public key: {e}")))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            AppError::Crypto("invalid public key length (expected 32 bytes)".to_string())
        })?;
        PublicKey::from_bytes(&bytes)
            .map_err(|e| AppError::Crypto(format!("invalid ed25519 public key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_identity() {
        let id = Identity::generate();
        let pk = id.public_key();
        // Public key should be 32 bytes
        assert_eq!(pk.as_bytes().len(), 32);
    }

    #[test]
    fn public_key_base64_roundtrip() {
        let id = Identity::generate();
        let b64 = id.public_key_base64();
        let parsed = Identity::parse_public_key(&b64).unwrap();
        assert_eq!(parsed, id.public_key());
    }

    #[test]
    fn parse_invalid_base64_returns_error() {
        let result = Identity::parse_public_key("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_wrong_length_returns_error() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
        let result = Identity::parse_public_key(&b64);
        assert!(result.is_err());
    }

    #[test]
    fn from_keypair_preserves_key() {
        let kp = signing::generate_keypair();
        let expected_pk = kp.verifying_key();
        let id = Identity::from_keypair(kp);
        assert_eq!(id.public_key(), expected_pk);
    }

    #[test]
    fn keypair_bytes_roundtrip() {
        let id = Identity::generate();
        let bytes = id.keypair().to_bytes();
        let restored = Keypair::from_bytes(&bytes);
        assert_eq!(restored.verifying_key(), id.public_key());
    }
}
