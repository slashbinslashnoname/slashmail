//! `slashmail init` — generate a new identity and persist it.

use anyhow::Result;
use libp2p::PeerId;

use super::{DaemonStatus, InitResult, StatusResult};
use crate::cli::output::OutputContext;
use crate::ctl::{self, CtlRequest, CtlResponse};
use crate::error::AppError;
use crate::identity::Identity;
use crate::net;
use crate::storage::Config;

/// Run the init command: generate an Ed25519 keypair, store the private key
/// in the OS keyring, and write the public key to config.toml.
pub async fn run(ctx: &OutputContext) -> Result<()> {
    // Check if an identity already exists in config
    let config = Config::load()?;
    if config.public_key.is_some() {
        let path = Config::config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "~/.slashmail/config.toml".to_string());
        Err(AppError::InvalidInput(format!(
            "identity already initialised — to reinitialise, remove the `public_key` field from {path}"
        )))?;
    }

    // Generate a new identity
    let identity = Identity::generate();

    // Store the private key in the OS keyring
    identity.store_in_keyring()?;

    // Write the public key into config.toml
    let mut config = config;
    let pk = identity.public_key_base64();
    config.public_key = Some(pk.clone());
    config.save()?;

    let result = InitResult { public_key: pk.clone() };
    ctx.print_success(&result, || {
        println!("Identity initialised.");
        println!("Public key: {pk}");
    });

    Ok(())
}

/// Show node status: identity info (always available) + daemon info (if running).
pub async fn status(ctx: &OutputContext) -> Result<()> {
    let config = Config::load()?;
    match config.public_key {
        Some(ref pk) => {
            // Verify the keyring has the matching private key.
            let identity = Identity::load_from_keyring()?;
            let stored_pk = identity.public_key_base64();
            if stored_pk != *pk {
                Err(AppError::Crypto(format!(
                    "keyring public key ({stored_pk}) does not match config ({pk}) — identity may be corrupted"
                )))?;
            }

            // Derive PeerId from the identity keypair.
            let libp2p_keypair = net::convert_keypair(&identity)?;
            let peer_id = PeerId::from(libp2p_keypair.public());

            // Try to reach the daemon for live info.
            let daemon = match ctl::send_request(&CtlRequest::Status).await {
                Ok(CtlResponse::Status(info)) => DaemonStatus {
                    running: true,
                    num_peers: Some(info.num_peers),
                    listen_addrs: Some(info.listen_addrs.clone()),
                    external_addrs: Some(info.external_addrs.clone()),
                },
                _ => DaemonStatus {
                    running: false,
                    num_peers: None,
                    listen_addrs: None,
                    external_addrs: None,
                },
            };

            let result = StatusResult {
                display_name: config.display_name.clone(),
                public_key: Some(pk.clone()),
                peer_id: Some(peer_id.to_string()),
                listen_addr: config.listen_addr.clone(),
                daemon,
            };

            ctx.print_success(&result, || {
                if let Some(ref name) = result.display_name {
                    println!("Name:       {name}");
                }
                println!("Public key: {pk}");
                println!("Peer ID:    {peer_id}");
                println!("Listen:     {}", config.listen_addr);
                if result.daemon.running {
                    let np = result.daemon.num_peers.unwrap_or(0);
                    println!("Daemon:     running ({np} peer(s) connected)");
                    if let Some(ref addrs) = result.daemon.listen_addrs {
                        for addr in addrs {
                            println!("  listen:   {addr}");
                        }
                    }
                    if let Some(ref addrs) = result.daemon.external_addrs {
                        for addr in addrs {
                            println!("  external: {addr}");
                        }
                    }
                } else {
                    println!("Daemon:     not running");
                }
            });
        }
        None => {
            let result = StatusResult {
                display_name: None,
                public_key: None,
                peer_id: None,
                listen_addr: config.listen_addr.clone(),
                daemon: DaemonStatus {
                    running: false,
                    num_peers: None,
                    listen_addrs: None,
                    external_addrs: None,
                },
            };
            ctx.print_success(&result, || {
                println!("No identity found. Run `slashmail init` to create one.");
            });
        }
    }
    Ok(())
}
