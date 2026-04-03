//! Application-wide error types.
//!
//! Every `AppError` variant carries enough information to produce a structured
//! JSON error envelope (`{error: {code, message, suggestions}}`) and a
//! meaningful process exit code without external mapping tables.

use std::path::PathBuf;
use thiserror::Error;

/// Unified error type for slashmail operations.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config at {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("failed to serialize config: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("this operation requires a running daemon (start with `slashmail daemon start`)")]
    DaemonRequired,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),
}

impl AppError {
    /// Create an IO error with the associated path.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Actionable suggestions for this error class.
    pub fn suggestions(&self) -> Vec<String> {
        match self {
            AppError::DaemonRequired => {
                vec!["Start the daemon with `slashmail daemon start`".into()]
            }
            AppError::ConfigParse { path, .. } => {
                vec![format!("Check TOML syntax in {}", path.display())]
            }
            AppError::Keyring(_) => {
                vec!["Run `slashmail init` to create an identity".into()]
            }
            AppError::NotFound(_) => {
                vec!["Check the identifier and try again".into()]
            }
            AppError::InvalidInput(_) => {
                vec!["Run `slashmail <command> --help` for usage information".into()]
            }
            AppError::Network(_) => {
                vec![
                    "Check that the daemon is running with `slashmail status`".into(),
                    "Verify network connectivity".into(),
                ]
            }
            _ => vec![],
        }
    }
}
