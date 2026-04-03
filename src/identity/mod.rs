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
        keystore::set_secret(KEYRING_ACCOUNT, &secret_bytes).map_err(|e| {
            match e.downcast::<keyring::Error>() {
                Ok(ke) => AppError::Keyring(ke),
                Err(e) => AppError::Crypto(format!("failed to store key in keyring: {e}")),
            }
        })
    }

    /// Load an identity from the OS keyring, falling back to the `SLASHMAIL_KEY`
    /// environment variable (base64-encoded 32-byte secret) when the keyring is
    /// unavailable (e.g. headless CI, Docker).
    pub fn load_from_keyring() -> Result<Self, AppError> {
        match keystore::get_secret(KEYRING_ACCOUNT) {
            Ok(secret_bytes) => Self::identity_from_secret_bytes(secret_bytes),
            Err(keyring_err) => {
                // Fall back to SLASHMAIL_KEY env var when keyring is unavailable.
                if let Some(result) = Self::try_load_from_env_var() {
                    return result;
                }
                match keyring_err.downcast::<keyring::Error>() {
                    Ok(ke) => Err(AppError::Keyring(ke)),
                    Err(e) => Err(AppError::Crypto(format!(
                        "failed to load key from keyring: {e}"
                    ))),
                }
            }
        }
    }

    /// Try to load an identity from the `SLASHMAIL_KEY` environment variable.
    /// Returns `None` if the variable is not set, or `Some(Err(...))` on parse failure.
    fn try_load_from_env_var() -> Option<Result<Self, AppError>> {
        std::env::var("SLASHMAIL_KEY").ok().map(|b64| {
            let secret_bytes = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| {
                    AppError::Crypto(format!("SLASHMAIL_KEY contains invalid base64: {e}"))
                })?;
            Self::identity_from_secret_bytes(secret_bytes)
        })
    }

    /// Build an identity from raw secret bytes (expected 32 bytes).
    fn identity_from_secret_bytes(secret_bytes: Vec<u8>) -> Result<Self, AppError> {
        let bytes: [u8; 32] = secret_bytes.try_into().map_err(|_| {
            AppError::Crypto("invalid key length (expected 32 bytes)".to_string())
        })?;
        let keypair = Keypair::from_bytes(&bytes);
        Ok(Self { keypair })
    }

    /// Delete the private key from the OS keyring.
    pub fn delete_from_keyring() -> Result<(), AppError> {
        keystore::delete_secret(KEYRING_ACCOUNT).map_err(|e| {
            match e.downcast::<keyring::Error>() {
                Ok(ke) => AppError::Keyring(ke),
                Err(e) => AppError::Crypto(format!("failed to delete key from keyring: {e}")),
            }
        })
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

    #[test]
    fn identity_from_secret_bytes_valid() {
        let id = Identity::generate();
        let bytes = id.keypair().to_bytes().to_vec();
        let restored = Identity::identity_from_secret_bytes(bytes).unwrap();
        assert_eq!(restored.public_key(), id.public_key());
    }

    #[test]
    fn identity_from_secret_bytes_wrong_length() {
        let result = Identity::identity_from_secret_bytes(vec![0u8; 16]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, AppError::Crypto(_)),
            "expected Crypto error, got: {err:?}"
        );
    }

    // Serialise env-var mutations across test threads.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn try_load_from_env_var_valid() {
        let id = Identity::generate();
        let b64 = base64::engine::general_purpose::STANDARD.encode(id.keypair().to_bytes());

        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SLASHMAIL_KEY", &b64);
        let result = Identity::try_load_from_env_var();
        std::env::remove_var("SLASHMAIL_KEY");

        let loaded = result
            .expect("try_load_from_env_var should return Some")
            .expect("identity should parse successfully");
        assert_eq!(
            loaded.public_key(),
            id.public_key(),
            "loaded identity must match the encoded key"
        );
    }

    #[test]
    fn try_load_from_env_var_not_set() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("SLASHMAIL_KEY");
        assert!(
            Identity::try_load_from_env_var().is_none(),
            "should return None when env var is absent"
        );
    }

    #[test]
    fn try_load_from_env_var_invalid_base64() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SLASHMAIL_KEY", "not-valid-base64!!!");
        let result = Identity::try_load_from_env_var();
        std::env::remove_var("SLASHMAIL_KEY");

        let err = result
            .expect("should return Some for set env var")
            .unwrap_err();
        assert!(
            matches!(err, AppError::Crypto(_)),
            "expected Crypto error for bad base64, got: {err:?}"
        );
    }

    #[test]
    fn try_load_from_env_var_wrong_length() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SLASHMAIL_KEY", &b64);
        let result = Identity::try_load_from_env_var();
        std::env::remove_var("SLASHMAIL_KEY");

        let err = result
            .expect("should return Some for set env var")
            .unwrap_err();
        assert!(
            matches!(err, AppError::Crypto(_)),
            "expected Crypto error for wrong key length, got: {err:?}"
        );
    }

    #[test]
    fn load_from_keyring_falls_back_to_env_var() {
        // Integration smoke-test: with SLASHMAIL_KEY set, load_from_keyring
        // must not return an error (either keyring or env var provides a valid identity).
        let id = Identity::generate();
        let b64 = base64::engine::general_purpose::STANDARD.encode(id.keypair().to_bytes());

        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SLASHMAIL_KEY", &b64);
        let result = Identity::load_from_keyring();
        std::env::remove_var("SLASHMAIL_KEY");

        result.expect("load_from_keyring should succeed when SLASHMAIL_KEY is set");
    }
}
