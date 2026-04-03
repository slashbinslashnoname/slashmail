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
                vec![
                    "Run `slashmail init` to create an identity".into(),
                    "In headless environments (CI, Docker), set SLASHMAIL_KEY env var (base64-encoded 32-byte secret key)".into(),
                ]
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
            AppError::Io { path, .. } => {
                vec![
                    format!("Check that {} exists and is accessible", path.display()),
                    "Verify file permissions and disk space".into(),
                ]
            }
            AppError::Database(_) => {
                vec![
                    "The database may be corrupted — try removing ~/.slashmail/messages.db and re-syncing".into(),
                    "Ensure SQLite was compiled with FTS5 support".into(),
                ]
            }
            AppError::Crypto(_) => {
                vec![
                    "Run `slashmail init` to regenerate your identity".into(),
                    "If using SLASHMAIL_KEY, verify it is a valid base64-encoded 32-byte key".into(),
                ]
            }
            AppError::ConfigSerialize(_) => {
                vec!["Check ~/.slashmail/config.toml for syntax errors".into()]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_error_suggests_env_var() {
        let err = AppError::Keyring(keyring::Error::NoEntry);
        let suggestions = err.suggestions();
        assert!(
            suggestions.iter().any(|s| s.contains("SLASHMAIL_KEY")),
            "keyring error should suggest SLASHMAIL_KEY env var, got: {suggestions:?}"
        );
        assert!(
            suggestions.iter().any(|s| s.contains("slashmail init")),
            "keyring error should suggest slashmail init, got: {suggestions:?}"
        );
    }

    #[test]
    fn io_error_suggests_path_check() {
        let err = AppError::Io {
            path: PathBuf::from("/tmp/missing"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
        };
        let s = err.suggestions();
        assert!(!s.is_empty(), "Io error should have suggestions");
        assert!(s.iter().any(|s| s.contains("/tmp/missing")));
    }

    #[test]
    fn database_error_suggests_rebuild() {
        let err = AppError::Database(rusqlite::Error::QueryReturnedNoRows);
        let s = err.suggestions();
        assert!(!s.is_empty(), "Database error should have suggestions");
        assert!(s.iter().any(|s| s.contains("messages.db")));
    }

    #[test]
    fn crypto_error_suggests_init() {
        let err = AppError::Crypto("bad key".into());
        let s = err.suggestions();
        assert!(!s.is_empty(), "Crypto error should have suggestions");
        assert!(s.iter().any(|s| s.contains("slashmail init")));
        assert!(s.iter().any(|s| s.contains("SLASHMAIL_KEY")));
    }

    #[test]
    fn config_serialize_error_suggests_check() {
        let err = AppError::ConfigSerialize(toml::to_string(&()).unwrap_err());
        let s = err.suggestions();
        assert!(!s.is_empty(), "ConfigSerialize should have suggestions");
        assert!(s.iter().any(|s| s.contains("config.toml")));
    }
}
