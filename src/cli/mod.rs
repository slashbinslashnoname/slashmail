mod init;
pub mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use tabled::{Table, Tabled};

use crate::ctl::{self, CtlRequest, CtlResponse};
use crate::error::AppError;
use crate::storage::config::Config;
use crate::storage::db::ReadOnlyMessageStore;

pub use output::OutputContext;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(name = "slashmail", about = "Peer-to-peer encrypted mail")]
pub struct Args {
    /// Output JSON instead of human-readable text.
    /// Auto-enabled when stdout is not a TTY.
    #[arg(long, global = true)]
    pub json: bool,

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
    /// Manage the P2P daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonCommand,
    },
}

#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Start the P2P daemon
    Start {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },
    /// Stop the running daemon
    Stop,
    /// Restart the daemon (stop + start)
    Restart {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },
}

/// Row type for the message table output (list / search).
#[derive(Tabled)]
struct MessageRow {
    #[tabled(rename = "From")]
    sender: String,
    #[tabled(rename = "Subject")]
    subject: String,
    #[tabled(rename = "Tags")]
    tags: String,
    #[tabled(rename = "Date")]
    timestamp: String,
    #[tabled(rename = "Preview")]
    preview: String,
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

/// Truncate a string to at most `max_chars` characters, appending `…` if truncated.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

/// Convert a slice of messages into table rows for display.
fn message_rows(messages: &[crate::storage::db::Message]) -> Vec<MessageRow> {
    messages
        .iter()
        .map(|msg| {
            // Truncate sender for display
            let sender = truncate_chars(&msg.sender, 19);
            // Truncate subject
            let subject = truncate_chars(&msg.subject, 29);
            // Tags: replace spaces with ", " for readability
            let tags = if msg.tags.is_empty() {
                "-".into()
            } else {
                msg.tags.split_whitespace().collect::<Vec<_>>().join(", ")
            };
            // Preview: first 40 chars of body
            let preview = if msg.body.is_empty() {
                "-".into()
            } else {
                truncate_chars(&msg.body, 39)
            };
            MessageRow {
                sender,
                subject,
                tags,
                timestamp: msg.created_at.format("%Y-%m-%d %H:%M").to_string(),
                preview,
            }
        })
        .collect()
}

/// Print a formatted table of messages, or a "no messages" notice.
fn print_message_table(messages: &[crate::storage::db::Message], empty_msg: &str) {
    if messages.is_empty() {
        println!("{empty_msg}");
    } else {
        let rows = message_rows(messages);
        println!("{}", Table::new(rows));
    }
}

// ---------------------------------------------------------------------------
// Serializable data types for JSON output
// ---------------------------------------------------------------------------

/// JSON-serializable message summary (used by list/search commands).
#[derive(Debug, Serialize)]
struct MessageJson {
    id: String,
    sender: String,
    recipient: String,
    subject: String,
    body: String,
    tags: Vec<String>,
    created_at: String,
    read: bool,
}

impl From<&crate::storage::db::Message> for MessageJson {
    fn from(msg: &crate::storage::db::Message) -> Self {
        Self {
            id: msg.id.to_string(),
            sender: msg.sender.clone(),
            recipient: msg.recipient.clone(),
            subject: msg.subject.clone(),
            body: msg.body.clone(),
            tags: if msg.tags.is_empty() {
                vec![]
            } else {
                msg.tags.split_whitespace().map(String::from).collect()
            },
            created_at: msg.created_at.to_rfc3339(),
            read: msg.read,
        }
    }
}

/// JSON payload for init command.
#[derive(Debug, Serialize)]
struct InitResult {
    public_key: String,
}

/// JSON payload for status command.
#[derive(Debug, Serialize)]
struct StatusResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    listen_addr: String,
    daemon: DaemonStatus,
}

/// Daemon status sub-payload.
#[derive(Debug, Serialize)]
struct DaemonStatus {
    running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_peers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_addrs: Option<Vec<String>>,
}

/// JSON payload for add-peer command.
#[derive(Debug, Serialize)]
struct AddPeerResult {
    addr: String,
}

/// JSON payload for messages list/search.
#[derive(Debug, Serialize)]
struct MessagesResult {
    messages: Vec<MessageJson>,
    count: usize,
}

pub async fn run(args: Args) -> Result<()> {
    let ctx = OutputContext::new(args.json);

    match args.command {
        Command::Init => {
            tracing::info!("initializing identity");
            init::run(&ctx).await
        }
        Command::Status => {
            tracing::info!("showing status");
            init::status(&ctx).await
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
                let empty: Vec<MessageJson> = vec![];
                let result = MessagesResult { messages: empty, count: 0 };
                ctx.print_success(&result, || {
                    println!("No messages yet. Run `slashmail init` first.");
                });
                return Ok(());
            }
            let store = ReadOnlyMessageStore::open(&db_path)?;
            let messages = match tag {
                Some(ref t) => store.messages_by_tag(t)?,
                None => store.list_messages(50)?,
            };
            let json_msgs: Vec<MessageJson> = messages.iter().map(MessageJson::from).collect();
            let result = MessagesResult { count: json_msgs.len(), messages: json_msgs };
            ctx.print_success(&result, || {
                print_message_table(&messages, "No messages found.");
            });
            Ok(())
        }
        Command::Search { ref query } => {
            tracing::info!(%query, "searching messages");
            let db_path = Config::db_path()?;
            if !db_path.exists() {
                let empty: Vec<MessageJson> = vec![];
                let result = MessagesResult { messages: empty, count: 0 };
                ctx.print_success(&result, || {
                    println!("No messages yet. Run `slashmail init` first.");
                });
                return Ok(());
            }
            let store = ReadOnlyMessageStore::open(&db_path)?;
            let results = store.search_messages(query)?;
            let json_msgs: Vec<MessageJson> = results.iter().map(MessageJson::from).collect();
            let result = MessagesResult { count: json_msgs.len(), messages: json_msgs };
            ctx.print_success(&result, || {
                print_message_table(&results, &format!("No messages match \"{query}\"."));
            });
            Ok(())
        }
        Command::AddPeer { addr } => {
            tracing::info!(%addr, "adding peer");
            let resp = ctl::send_request(&CtlRequest::AddPeer { addr: addr.clone() }).await?;
            match resp {
                CtlResponse::AddPeer { ok: true, .. } => {
                    let result = AddPeerResult { addr: addr.clone() };
                    ctx.print_success(&result, || {
                        println!("Dialing {addr}");
                    });
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
                    ctx.print_success(&peers, || {
                        if peers.is_empty() {
                            println!("No connected peers.");
                        } else {
                            let rows: Vec<PeerRow> = peers
                                .iter()
                                .map(|p| {
                                    let short_id = truncate_chars(&p.peer_id, 16);
                                    PeerRow {
                                        peer_id: short_id,
                                        addrs: if p.addrs.is_empty() {
                                            "-".into()
                                        } else {
                                            p.addrs.join(", ")
                                        },
                                        connected_since: p.connected_since.clone(),
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
                    });
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
        Command::Daemon { action } => match action {
            DaemonCommand::Start { listen } => {
                tracing::info!(%listen, "starting daemon");
                run_daemon_start(listen).await
            }
            DaemonCommand::Stop => {
                tracing::info!("stopping daemon");
                run_daemon_stop().await
            }
            DaemonCommand::Restart { listen } => {
                tracing::info!(%listen, "restarting daemon");
                run_daemon_stop().await.ok(); // ignore error if not running
                run_daemon_start(listen).await
            }
        },
    }
}

// ---------------------------------------------------------------------------
// PID file management
// ---------------------------------------------------------------------------

/// Read the PID from the daemon PID file. Returns `None` if the file doesn't
/// exist or can't be parsed.
fn read_pid_file() -> Result<Option<u32>> {
    let pid_path = Config::pid_path()?;
    if !pid_path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&pid_path)
        .map_err(|e| AppError::io(&pid_path, e))?;
    match contents.trim().parse::<u32>() {
        Ok(pid) => Ok(Some(pid)),
        Err(_) => Ok(None),
    }
}

/// Write the current process PID to the daemon PID file.
fn write_pid_file() -> Result<()> {
    let pid_path = Config::pid_path()?;
    Config::ensure_dir()?;
    std::fs::write(&pid_path, std::process::id().to_string())
        .map_err(|e| AppError::io(&pid_path, e))?;
    Ok(())
}

/// Remove the daemon PID file.
fn remove_pid_file() {
    if let Ok(pid_path) = Config::pid_path() {
        let _ = std::fs::remove_file(pid_path);
    }
}

/// Check whether a process with the given PID is alive.
#[cfg(unix)]
fn is_pid_alive(pid: u32) -> bool {
    use nix::sys::signal;
    use nix::unistd::Pid;
    // Signal 0 doesn't send a signal but checks if the process exists.
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

/// Stop a running daemon by sending SIGTERM to the PID in the PID file.
#[cfg(unix)]
async fn run_daemon_stop() -> Result<()> {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;

    let pid = read_pid_file()?.ok_or_else(|| {
        anyhow::anyhow!("no PID file found — daemon is not running")
    })?;

    if !is_pid_alive(pid) {
        remove_pid_file();
        anyhow::bail!("daemon is not running (stale PID file for pid {pid})");
    }

    signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .map_err(|e| anyhow::anyhow!("failed to send SIGTERM to pid {pid}: {e}"))?;

    // Wait briefly for the process to exit, then clean up the PID file.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if !is_pid_alive(pid) {
            break;
        }
    }
    remove_pid_file();
    println!("Daemon stopped (pid {pid}).");
    Ok(())
}

/// Start the P2P daemon: load identity, build swarm, open control socket, run event loop.
async fn run_daemon_start(listen: String) -> Result<()> {
    use crate::engine;
    use crate::identity::Identity;
    use crate::net;
    use crate::storage::db::MessageStore;
    use libp2p::Multiaddr;
    use tokio::sync::mpsc;

    // Check for an already-running daemon via PID file.
    if let Some(pid) = read_pid_file()? {
        if is_pid_alive(pid) {
            anyhow::bail!("daemon is already running (pid {pid})");
        }
        // Stale PID file — clean it up.
        remove_pid_file();
    }

    let identity = Identity::load_from_keyring()?;
    let config = Config::load()?;
    let (mut swarm, peer_id) = net::build_swarm(&identity).await?;

    let listen_addr: Multiaddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;
    swarm
        .listen_on(listen_addr)
        .map_err(|e| anyhow::anyhow!("failed to listen: {e}"))?;

    // When relay_addr is configured, listen through the relay so that
    // dcutr can hole-punch connections for NATed peers.
    if let Some(ref relay) = config.relay_addr {
        let relay_addr: Multiaddr = relay
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid relay_addr in config: {e}"))?;
        let relay_listen = relay_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
        swarm
            .listen_on(relay_listen)
            .map_err(|e| anyhow::anyhow!("failed to listen on relay: {e}"))?;
        println!("Relay:   {relay}");
    }

    // Write PID file before announcing readiness.
    write_pid_file()?;

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

    // Clean up PID file and socket.
    remove_pid_file();
    let _ = std::fs::remove_file(&sock_path);

    tracing::info!(?reason, "daemon stopped");
    Ok(())
}
