mod init;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        Command::Send { to, tags } => {
            tracing::info!(%to, ?tags, "sending message");
            todo!("send command")
        }
        Command::List { tag } => {
            tracing::info!(?tag, "listing messages");
            todo!("list command")
        }
        Command::Search { ref query } => {
            tracing::info!(%query, "searching messages");
            todo!("search command")
        }
        Command::Peers => {
            tracing::info!("listing peers");
            todo!("peers command")
        }
        Command::Daemon { listen } => {
            tracing::info!(%listen, "starting daemon");
            todo!("daemon command")
        }
    }
}
