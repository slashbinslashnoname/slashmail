mod cli;
mod compress;
mod crypto;
mod ctl;
mod db;
mod engine;
mod error;
mod identity;
mod keystore;
mod message;
mod net;
mod storage;
mod swarm;
mod types;
mod ui;

use clap::Parser;

use cli::output::{ExitCode, OutputContext};
use error::AppError;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = cli::Args::parse();
    let ctx = OutputContext::new(args.json);

    if let Err(err) = cli::run(args).await {
        // Try to downcast to AppError for structured output.
        let exit_code = match err.downcast_ref::<AppError>() {
            Some(app_err) => {
                let code = ctx.print_error(app_err);
                if !ctx.is_json() {
                    eprintln!("Error: {err:#}");
                }
                code
            }
            None => {
                // Not an AppError — wrap as general error for JSON output.
                if ctx.is_json() {
                    let app_err = AppError::Other(err.to_string());
                    ctx.print_error(&app_err);
                } else {
                    eprintln!("Error: {err:#}");
                }
                ExitCode::GeneralError
            }
        };
        std::process::exit(exit_code.as_i32());
    }
}
