//! OS keyring integration for secret storage.

use anyhow::Result;

const SERVICE: &str = "slashmail";

/// Store a secret in the OS keyring.
pub fn set_secret(account: &str, secret: &[u8]) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret);
    entry.set_password(&encoded)?;
    Ok(())
}

/// Retrieve a secret from the OS keyring.
pub fn get_secret(account: &str) -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    let encoded = entry.get_password()?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded)?;
    Ok(bytes)
}

/// Delete a secret from the OS keyring.
pub fn delete_secret(account: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    entry.delete_credential()?;
    Ok(())
}

// --- Swarm key helpers ------------------------------------------------

/// Build the namespaced account name for a swarm's symmetric key.
fn swarm_account(swarm_id: &str) -> String {
    format!("swarm-{swarm_id}")
}

/// Store a 32-byte symmetric key for `swarm_id` in the OS keyring.
pub fn set_swarm_key(swarm_id: &str, key: &[u8; 32]) -> Result<()> {
    set_secret(&swarm_account(swarm_id), key)
}

/// Retrieve the 32-byte symmetric key for `swarm_id` from the OS keyring.
pub fn get_swarm_key(swarm_id: &str) -> Result<[u8; 32]> {
    let bytes = get_secret(&swarm_account(swarm_id))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32-byte swarm key, got {} bytes", v.len()))?;
    Ok(key)
}

/// Delete the symmetric key for `swarm_id` from the OS keyring.
pub fn delete_swarm_key(swarm_id: &str) -> Result<()> {
    delete_secret(&swarm_account(swarm_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swarm_account_format() {
        assert_eq!(swarm_account("pub_general"), "swarm-pub_general");
        assert_eq!(swarm_account("prv_alice_bob"), "swarm-prv_alice_bob");
    }

    #[test]
    #[ignore] // requires OS keyring access
    fn roundtrip_swarm_key() {
        let swarm_id = "test_roundtrip_swarm_key";
        let key: [u8; 32] = [0xAB; 32];

        // Clean up in case a previous run left state.
        let _ = delete_swarm_key(swarm_id);

        set_swarm_key(swarm_id, &key).expect("set_swarm_key should succeed");
        let retrieved = get_swarm_key(swarm_id).expect("get_swarm_key should succeed");
        assert_eq!(retrieved, key);

        delete_swarm_key(swarm_id).expect("delete_swarm_key should succeed");
        assert!(get_swarm_key(swarm_id).is_err(), "key should be gone after delete");
    }

    #[test]
    #[ignore] // requires OS keyring access
    fn get_missing_swarm_key_errors() {
        assert!(get_swarm_key("nonexistent_swarm_key_test").is_err());
    }
}
