use anyhow::Result;
use ed25519_dalek::{self as ed25519, Signer, Verifier};
use rand::rngs::OsRng;

pub type Keypair = ed25519::SigningKey;
pub type PublicKey = ed25519::VerifyingKey;
pub type Signature = ed25519::Signature;

/// Generate a new Ed25519 signing keypair.
pub fn generate_keypair() -> Keypair {
    Keypair::generate(&mut OsRng)
}

/// Sign a message.
pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

/// Verify a signature.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    public_key
        .verify(message, signature)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"hello slashmail";
        let sig = sign(&kp, msg);
        assert!(verify(&kp.verifying_key(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kp = generate_keypair();
        let sig = sign(&kp, b"original");
        assert!(verify(&kp.verifying_key(), b"tampered", &sig).is_err());
    }
}
