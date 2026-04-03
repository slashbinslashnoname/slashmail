mod init;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// List known peers
    Peers,
    /// Start the P2P daemon
    Daemon {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Init => {
            tracing::info!("initializing identity");
            init::run().await
        }
        Command::Status => {
            tracing::info!("showing status");
            init::whoami().await
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
        Command::Peers => {
            // Peer listing requires daemon access for live peer state.
            Err(AppError::DaemonRequired.into())
        }
        Command::Daemon { listen } => {
            tracing::info!(%listen, "starting daemon");
            todo!("daemon command")
        }
    }
}
