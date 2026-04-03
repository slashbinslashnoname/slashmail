mod init;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Send a message
    Send {
        /// Recipient public key (base64)
        #[arg(short, long)]
        to: String,
        /// Message body
        #[arg(short, long)]
        body: String,
    },
    /// Read inbox
    Inbox,
    /// Start the P2P daemon
    Daemon {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },
    /// Show own identity
    Whoami,
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Init => {
            tracing::info!("initializing identity");
            init::run().await
        }
        Command::Send { to, body } => {
            tracing::info!(%to, "sending message");
            let _ = body;
            todo!("send command")
        }
        Command::Inbox => {
            tracing::info!("reading inbox");
            todo!("inbox command")
        }
        Command::Daemon { listen } => {
            tracing::info!(%listen, "starting daemon");
            todo!("daemon command")
        }
        Command::Whoami => {
            tracing::info!("showing identity");
            init::whoami().await
        }
    }
}
