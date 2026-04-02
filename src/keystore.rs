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
