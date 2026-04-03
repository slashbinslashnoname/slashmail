mod init;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tabled::{Table, Tabled};

use crate::ctl::{self, CtlRequest, CtlResponse};
use crate::error::AppError;
use crate::storage::config::Config;
use crate::storage::db::ReadOnlyMessageStore;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(name = "slashmail", about = "Peer-to-peer encrypted mail")]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new identity
    Init,
    /// Show identity and node status
    Status,
    /// Send a message to a peer
    Send {
        /// Recipient public key (base64)
        #[arg(short, long)]
        to: String,
        /// Tags to attach to the message
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// List messages, optionally filtered by tag
    List {
        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,
    },
    /// Search messages
    Search {
        /// Search query
        query: String,
    },
    /// Add a peer by multiaddress
    AddPeer {
        /// Multiaddress of the peer to dial (e.g. /ip4/1.2.3.4/tcp/4001)
        addr: String,
    },
    /// List known peers
    Peers,
    /// Start the P2P daemon
    Daemon {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },
}

/// Row type for the peers table output.
#[derive(Tabled)]
struct PeerRow {
    #[tabled(rename = "Peer ID")]
    peer_id: String,
    #[tabled(rename = "Addresses")]
    addrs: String,
    #[tabled(rename = "Connected Since")]
    connected_since: String,
    #[tabled(rename = "Protocols")]
    protocols: String,
    #[tabled(rename = "RTT (ms)")]
    rtt: String,
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Init => {
            tracing::info!("initializing identity");
            init::run().await
        }
        Command::Status => {
            tracing::info!("showing status");
            init::status().await
        }
        Command::Send { .. } => {
            // Write operations must route through the daemon command channel
            // to avoid SQLITE_BUSY contention in WAL mode.
            Err(AppError::DaemonRequired.into())
        }
        Command::List { tag } => {
            tracing::info!(?tag, "listing messages");
            let db_path = Config::db_path()?;
            if !db_path.exists() {
                println!("No messages yet. Run `slashmail init` first.");
                return Ok(());
            }
            let store = ReadOnlyMessageStore::open(&db_path)?;
            let messages = match tag {
                Some(ref t) => store.messages_by_tag(t)?,
                None => store.list_messages(50)?,
            };
            if messages.is_empty() {
                println!("No messages found.");
            } else {
                for msg in &messages {
                    println!(
                        "{} | {} → {} | {}",
                        msg.created_at.format("%Y-%m-%d %H:%M"),
                        msg.sender,
                        msg.recipient,
                        msg.subject,
                    );
                }
            }
            Ok(())
        }
        Command::Search { ref query } => {
            tracing::info!(%query, "searching messages");
            let db_path = Config::db_path()?;
            if !db_path.exists() {
                println!("No messages yet. Run `slashmail init` first.");
                return Ok(());
            }
            let store = ReadOnlyMessageStore::open(&db_path)?;
            let results = store.search_messages(query)?;
            if results.is_empty() {
                println!("No messages match \"{}\".", query);
            } else {
                for msg in &results {
                    println!(
                        "{} | {} → {} | {}",
                        msg.created_at.format("%Y-%m-%d %H:%M"),
                        msg.sender,
                        msg.recipient,
                        msg.subject,
                    );
                }
            }
            Ok(())
        }
        Command::AddPeer { addr } => {
            tracing::info!(%addr, "adding peer");
            let resp = ctl::send_request(&CtlRequest::AddPeer { addr: addr.clone() }).await?;
            match resp {
                CtlResponse::AddPeer { ok: true, .. } => {
                    println!("Dialing {addr}");
                    Ok(())
                }
                CtlResponse::AddPeer {
                    ok: false,
                    error,
                } => {
                    let msg = error.unwrap_or_else(|| "unknown error".into());
                    anyhow::bail!("failed to add peer: {msg}");
                }
                CtlResponse::Error { message } => {
                    anyhow::bail!("daemon error: {message}");
                }
                _ => {
                    anyhow::bail!("unexpected response from daemon");
                }
            }
        }
        Command::Peers => {
            tracing::info!("listing peers");
            let resp = ctl::send_request(&CtlRequest::Peers).await?;
            match resp {
                CtlResponse::Peers { peers } => {
                    if peers.is_empty() {
                        println!("No connected peers.");
                    } else {
                        let rows: Vec<PeerRow> = peers
                            .into_iter()
                            .map(|p| {
                                // Truncate PeerId for display (keep first 16 chars + ...)
                                let short_id = if p.peer_id.len() > 16 {
                                    format!("{}...", &p.peer_id[..16])
                                } else {
                                    p.peer_id
                                };
                                PeerRow {
                                    peer_id: short_id,
                                    addrs: if p.addrs.is_empty() {
                                        "-".into()
                                    } else {
                                        p.addrs.join(", ")
                                    },
                                    connected_since: p.connected_since,
                                    protocols: if p.protocols.is_empty() {
                                        "-".into()
                                    } else {
                                        p.protocols.join(", ")
                                    },
                                    rtt: p
                                        .rtt_ms
                                        .map(|ms| format!("{ms:.1}"))
                                        .unwrap_or_else(|| "-".into()),
                                }
                            })
                            .collect();
                        println!("{}", Table::new(rows));
                    }
                    Ok(())
                }
                CtlResponse::Error { message } => {
                    anyhow::bail!("daemon error: {message}");
                }
                _ => {
                    anyhow::bail!("unexpected response from daemon");
                }
            }
        }
        Command::Daemon { listen } => {
            tracing::info!(%listen, "starting daemon");
            run_daemon(listen).await
        }
    }
}

/// Start the P2P daemon: load identity, build swarm, open control socket, run event loop.
async fn run_daemon(listen: String) -> Result<()> {
    use crate::engine;
    use crate::identity::Identity;
    use crate::net;
    use crate::storage::db::MessageStore;
    use libp2p::Multiaddr;
    use tokio::sync::mpsc;

    let identity = Identity::load_from_keyring()?;
    let (mut swarm, peer_id) = net::build_swarm(&identity).await?;

    let listen_addr: Multiaddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;
    swarm
        .listen_on(listen_addr)
        .map_err(|e| anyhow::anyhow!("failed to listen: {e}"))?;

    println!("PeerId:  {peer_id}");
    println!("Daemon running. Press Ctrl-C to stop.");

    let (cmd_tx, cmd_rx) = mpsc::channel(64);

    // Start the control socket.
    let sock_path = ctl::socket_path()?;
    ctl::serve(&sock_path, cmd_tx).await?;

    // Open message store.
    Config::ensure_dir()?;
    let db_path = Config::db_path()?;
    let store = MessageStore::open(&db_path)?;

    // Prepare WAL flush callback.
    let db_path_clone = db_path.clone();
    let wal_flush: Box<dyn FnOnce() + Send> = Box::new(move || {
        if let Ok(conn) = rusqlite::Connection::open(&db_path_clone) {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    });

    let keypair = identity.keypair().clone();
    let reason = engine::run_loop(swarm, cmd_rx, Some(store), Some(wal_flush), Some(&keypair)).await;

    // Clean up the socket file.
    let _ = std::fs::remove_file(&sock_path);

    tracing::info!(?reason, "daemon stopped");
    Ok(())
}
