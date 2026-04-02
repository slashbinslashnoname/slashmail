mod cli;
mod crypto;
mod db;
mod keystore;
mod net;
mod compress;
mod ui;
mod types;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = cli::Args::parse();
    cli::run(args).await
}
