//! Application-wide error types.

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

    #[error("this operation requires a running daemon (start with `slashmail daemon`)")]
    DaemonRequired,

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
}
