use anyhow::{Result, anyhow};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` with a 256-bit `key`.
/// Returns nonce || ciphertext.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `data` (nonce || ciphertext) with a 256-bit `key`.
pub fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let msg = b"secret slashmail message";
        let encrypted = seal(&key, msg).unwrap();
        let decrypted = open(&key, &encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn open_rejects_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x00u8; 32];
        let encrypted = seal(&key, b"secret").unwrap();
        assert!(open(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn open_rejects_short_data() {
        let key = [0x42u8; 32];
        assert!(open(&key, &[0u8; 5]).is_err());
    }
}
