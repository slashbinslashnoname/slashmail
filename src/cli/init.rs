//! `slashmail init` — generate a new identity and persist it.

use anyhow::Result;

use crate::identity::Identity;
use crate::storage::Config;

/// Run the init command: generate an Ed25519 keypair, store the private key
/// in the OS keyring, and write the public key to config.toml.
pub async fn run() -> Result<()> {
    // Check if an identity already exists in config
    let config = Config::load()?;
    if config.public_key.is_some() {
        let path = Config::config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "~/.slashmail/config.toml".to_string());
        anyhow::bail!(
            "identity already initialised — to reinitialise, remove the `public_key` field from {path}"
        );
    }

    // Generate a new identity
    let identity = Identity::generate();

    // Store the private key in the OS keyring
    identity.store_in_keyring()?;

    // Write the public key into config.toml
    let mut config = config;
    config.public_key = Some(identity.public_key_base64());
    config.save()?;

    println!("Identity initialised.");
    println!("Public key: {}", identity.public_key_base64());

    Ok(())
}

/// Run the whoami command: load identity and display it.
pub async fn whoami() -> Result<()> {
    let config = Config::load()?;
    match config.public_key {
        Some(ref pk) => {
            // Verify the keyring has the matching private key
            let identity = Identity::load_from_keyring()?;
            let stored_pk = identity.public_key_base64();
            if stored_pk != *pk {
                anyhow::bail!(
                    "keyring public key ({stored_pk}) does not match config ({pk}) — identity may be corrupted"
                );
            }
            if let Some(ref name) = config.display_name {
                println!("Name:       {name}");
            }
            println!("Public key: {pk}");
        }
        None => {
            println!("No identity found. Run `slashmail init` to create one.");
        }
    }
    Ok(())
}
