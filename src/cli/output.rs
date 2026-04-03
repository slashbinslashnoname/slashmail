//! Robot-mode CLI output interface.
//!
//! This module defines the contract for machine-readable CLI output:
//!
//! # OutputContext
//! Determines how commands render their results. Constructed once at startup
//! from the `--json` flag and TTY detection.
//!
//! # JSON envelope
//! All JSON output uses a consistent envelope:
//! ```json
//! {"ok": true, "data": <command-specific payload>}
//! {"ok": false, "error": {"code": "...", "message": "...", "suggestions": [...]}}
//! ```
//!
//! # TTY detection strategy
//! Uses [`std::io::IsTerminal`] (stable since Rust 1.70) on stdout.
//! No external crate required. When stdout is not a TTY and `--json` was not
//! explicitly passed, the output defaults to JSON automatically. This lets
//! piped commands (`slashmail list | jq .`) work without extra flags.
//!
//! # Exit codes
//! | Code | Meaning          |
//! |------|------------------|
//! |  0   | Success          |
//! |  1   | General error    |
//! |  2   | Invalid input    |
//! |  3   | Database error   |
//! |  4   | I/O error        |
//! |  5   | Network error    |
//! |  6   | Daemon required  |
//! |  7   | Crypto error     |

use serde::Serialize;
use std::io::IsTerminal;

use crate::error::AppError;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Process exit codes for machine consumers.
///
/// Codes 0-5 align with the `sm` (slashmem) CLI convention.
/// Codes 6-7 are slashmail-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    InvalidInput = 2,
    DatabaseError = 3,
    IoError = 4,
    NetworkError = 5,
    DaemonRequired = 6,
    CryptoError = 7,
}

impl ExitCode {
    /// Convert to the raw integer used with [`std::process::exit`].
    pub fn as_i32(self) -> i32 {
        (self as u8) as i32
    }
}

impl From<&AppError> for ExitCode {
    fn from(err: &AppError) -> Self {
        match err {
            AppError::Io { .. } => ExitCode::IoError,
            AppError::ConfigParse { .. } | AppError::ConfigSerialize(_) => ExitCode::InvalidInput,
            AppError::Database(_) => ExitCode::DatabaseError,
            AppError::Crypto(_) => ExitCode::CryptoError,
            AppError::Keyring(_) => ExitCode::IoError,
            AppError::Network(_) => ExitCode::NetworkError,
            AppError::DaemonRequired => ExitCode::DaemonRequired,
            AppError::Other(_) => ExitCode::GeneralError,
        }
    }
}

// ---------------------------------------------------------------------------
// Error codes (machine-readable string tags)
// ---------------------------------------------------------------------------

/// Machine-readable error code strings.
///
/// Each variant serializes to a lowercase snake_case tag that agents can
/// match on without parsing human-readable messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    IoError,
    ConfigParse,
    ConfigSerialize,
    DatabaseError,
    CryptoError,
    KeyringError,
    NetworkError,
    DaemonRequired,
    GeneralError,
}

impl From<&AppError> for ErrorCode {
    fn from(err: &AppError) -> Self {
        match err {
            AppError::Io { .. } => ErrorCode::IoError,
            AppError::ConfigParse { .. } => ErrorCode::ConfigParse,
            AppError::ConfigSerialize(_) => ErrorCode::ConfigSerialize,
            AppError::Database(_) => ErrorCode::DatabaseError,
            AppError::Crypto(_) => ErrorCode::CryptoError,
            AppError::Keyring(_) => ErrorCode::KeyringError,
            AppError::Network(_) => ErrorCode::NetworkError,
            AppError::DaemonRequired => ErrorCode::DaemonRequired,
            AppError::Other(_) => ErrorCode::GeneralError,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON envelope types
// ---------------------------------------------------------------------------

/// Top-level JSON envelope for successful responses.
#[derive(Debug, Serialize)]
pub struct JsonSuccess<T: Serialize> {
    pub ok: bool,
    pub data: T,
}

impl<T: Serialize> JsonSuccess<T> {
    pub fn new(data: T) -> Self {
        Self { ok: true, data }
    }
}

/// Structured error payload inside the JSON envelope.
#[derive(Debug, Serialize)]
pub struct JsonErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<String>,
    pub exit_code: u8,
}

/// Top-level JSON envelope for error responses.
#[derive(Debug, Serialize)]
pub struct JsonError {
    pub ok: bool,
    pub error: JsonErrorBody,
}

impl JsonError {
    /// Build from an [`AppError`], including contextual suggestions.
    pub fn from_app_error(err: &AppError) -> Self {
        let code = ErrorCode::from(err);
        let exit_code = ExitCode::from(err) as u8;
        let message = err.to_string();
        let suggestions = suggestions_for(err);

        Self {
            ok: false,
            error: JsonErrorBody {
                code,
                message,
                suggestions,
                exit_code,
            },
        }
    }
}

/// Return actionable suggestions for known error classes.
fn suggestions_for(err: &AppError) -> Vec<String> {
    match err {
        AppError::DaemonRequired => {
            vec!["Start the daemon with `slashmail daemon`".into()]
        }
        AppError::ConfigParse { path, .. } => {
            vec![format!("Check TOML syntax in {}", path.display())]
        }
        AppError::Keyring(_) => {
            vec!["Run `slashmail init` to create an identity".into()]
        }
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// OutputContext
// ---------------------------------------------------------------------------

/// Controls how CLI commands render output (human vs machine).
///
/// Constructed once at startup from the `--json` flag and stdout TTY state.
///
/// # Resolution order
/// 1. If `--json` is passed → JSON mode.
/// 2. Else if stdout is **not** a TTY → JSON mode (auto-detect).
/// 3. Else → human (table/text) mode.
#[derive(Debug, Clone)]
pub struct OutputContext {
    /// True when output should be JSON.
    json: bool,
}

impl OutputContext {
    /// Create from the explicit `--json` flag value.
    ///
    /// When `json_flag` is false, TTY detection on stdout decides the mode.
    pub fn new(json_flag: bool) -> Self {
        let json = if json_flag {
            true
        } else {
            // Auto-detect: non-TTY stdout → JSON for piped consumers.
            !std::io::stdout().is_terminal()
        };
        Self { json }
    }

    /// Force a specific mode (useful in tests).
    #[cfg(test)]
    pub fn forced(json: bool) -> Self {
        Self { json }
    }

    /// Whether output should be JSON.
    pub fn is_json(&self) -> bool {
        self.json
    }

    /// Print a successful result.
    ///
    /// In JSON mode, wraps `data` in the success envelope and prints one line.
    /// In human mode, calls the provided closure to render text output.
    pub fn print_success<T, F>(&self, data: &T, human: F)
    where
        T: Serialize,
        F: FnOnce(),
    {
        if self.json {
            let envelope = JsonSuccess::new(data);
            // Unwrap is safe: we control the types and they are all Serialize.
            println!("{}", serde_json::to_string(&envelope).expect("json serialize"));
        } else {
            human();
        }
    }

    /// Print an error.
    ///
    /// In JSON mode, prints the structured error envelope to **stderr**.
    /// In human mode, returns the error for anyhow's default rendering.
    /// Returns the appropriate [`ExitCode`].
    pub fn print_error(&self, err: &AppError) -> ExitCode {
        let exit = ExitCode::from(err);
        if self.json {
            let envelope = JsonError::from_app_error(err);
            eprintln!("{}", serde_json::to_string(&envelope).expect("json serialize"));
        }
        // In human mode the caller propagates the anyhow error as usual.
        exit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -- ExitCode mapping --------------------------------------------------

    #[test]
    fn exit_code_from_io_error() {
        let err = AppError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
        };
        assert_eq!(ExitCode::from(&err), ExitCode::IoError);
        assert_eq!(ExitCode::IoError.as_i32(), 4);
    }

    #[test]
    fn exit_code_from_daemon_required() {
        assert_eq!(ExitCode::from(&AppError::DaemonRequired), ExitCode::DaemonRequired);
        assert_eq!(ExitCode::DaemonRequired.as_i32(), 6);
    }

    #[test]
    fn exit_code_from_database_error() {
        let err = AppError::Database(rusqlite::Error::QueryReturnedNoRows);
        assert_eq!(ExitCode::from(&err), ExitCode::DatabaseError);
        assert_eq!(ExitCode::DatabaseError.as_i32(), 3);
    }

    #[test]
    fn exit_code_from_network_error() {
        let err = AppError::Network("timeout".into());
        assert_eq!(ExitCode::from(&err), ExitCode::NetworkError);
        assert_eq!(ExitCode::NetworkError.as_i32(), 5);
    }

    #[test]
    fn exit_code_from_crypto_error() {
        let err = AppError::Crypto("bad key".into());
        assert_eq!(ExitCode::from(&err), ExitCode::CryptoError);
        assert_eq!(ExitCode::CryptoError.as_i32(), 7);
    }

    #[test]
    fn exit_code_from_other_error() {
        let err = AppError::Other("oops".into());
        assert_eq!(ExitCode::from(&err), ExitCode::GeneralError);
        assert_eq!(ExitCode::GeneralError.as_i32(), 1);
    }

    #[test]
    fn exit_code_success_is_zero() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
    }

    #[test]
    fn exit_code_from_config_parse() {
        let err = AppError::ConfigParse {
            path: PathBuf::from("/etc/slashmail.toml"),
            source: toml::from_str::<toml::Value>("= bad").unwrap_err(),
        };
        assert_eq!(ExitCode::from(&err), ExitCode::InvalidInput);
        assert_eq!(ExitCode::InvalidInput.as_i32(), 2);
    }

    #[test]
    fn exit_code_from_config_serialize() {
        let err = AppError::ConfigSerialize(toml::to_string(&()).unwrap_err());
        assert_eq!(ExitCode::from(&err), ExitCode::InvalidInput);
    }

    #[test]
    fn exit_code_from_keyring_error() {
        let err = AppError::Keyring(keyring::Error::NoEntry);
        assert_eq!(ExitCode::from(&err), ExitCode::IoError);
    }

    // -- ErrorCode mapping -------------------------------------------------

    #[test]
    fn error_code_from_app_errors() {
        assert_eq!(ErrorCode::from(&AppError::DaemonRequired), ErrorCode::DaemonRequired);
        assert_eq!(ErrorCode::from(&AppError::Network("x".into())), ErrorCode::NetworkError);
        assert_eq!(ErrorCode::from(&AppError::Crypto("x".into())), ErrorCode::CryptoError);
        assert_eq!(ErrorCode::from(&AppError::Other("x".into())), ErrorCode::GeneralError);
        assert_eq!(
            ErrorCode::from(&AppError::Io {
                path: PathBuf::from("/x"),
                source: std::io::Error::new(std::io::ErrorKind::Other, "e"),
            }),
            ErrorCode::IoError,
        );
        assert_eq!(
            ErrorCode::from(&AppError::Keyring(keyring::Error::NoEntry)),
            ErrorCode::KeyringError,
        );
        assert_eq!(
            ErrorCode::from(&AppError::ConfigSerialize(toml::to_string(&()).unwrap_err())),
            ErrorCode::ConfigSerialize,
        );
    }

    // -- JSON envelope serialization ---------------------------------------

    #[test]
    fn json_success_envelope() {
        let data = vec!["hello", "world"];
        let envelope = JsonSuccess::new(&data);
        let json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["data"], serde_json::json!(["hello", "world"]));
    }

    #[test]
    fn json_error_envelope_daemon_required() {
        let err = AppError::DaemonRequired;
        let envelope = JsonError::from_app_error(&err);
        let json: serde_json::Value = serde_json::to_value(&envelope).unwrap();

        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["code"], "daemon_required");
        assert_eq!(json["error"]["exit_code"], 6);
        assert!(json["error"]["message"].as_str().unwrap().contains("daemon"));
        assert!(!json["error"]["suggestions"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn json_error_envelope_no_suggestions() {
        let err = AppError::Other("something broke".into());
        let envelope = JsonError::from_app_error(&err);
        let json: serde_json::Value = serde_json::to_value(&envelope).unwrap();

        assert_eq!(json["error"]["code"], "general_error");
        // suggestions should be omitted (skip_serializing_if = empty)
        assert!(json["error"].get("suggestions").is_none());
    }

    // -- OutputContext ------------------------------------------------------

    #[test]
    fn output_context_forced_json() {
        let ctx = OutputContext::forced(true);
        assert!(ctx.is_json());
    }

    #[test]
    fn output_context_forced_human() {
        let ctx = OutputContext::forced(false);
        assert!(!ctx.is_json());
    }

    #[test]
    fn output_context_json_flag_overrides_tty() {
        // --json always wins regardless of terminal state
        let ctx = OutputContext::new(true);
        assert!(ctx.is_json());
    }

    #[test]
    fn print_error_returns_correct_exit_code() {
        let ctx = OutputContext::forced(false);
        let err = AppError::DaemonRequired;
        let code = ctx.print_error(&err);
        assert_eq!(code, ExitCode::DaemonRequired);
    }

    // -- ErrorCode serde ---------------------------------------------------

    #[test]
    fn error_code_serializes_snake_case() {
        let code = ErrorCode::DaemonRequired;
        let s = serde_json::to_string(&code).unwrap();
        assert_eq!(s, "\"daemon_required\"");
    }

    #[test]
    fn error_code_io_serializes() {
        let s = serde_json::to_string(&ErrorCode::IoError).unwrap();
        assert_eq!(s, "\"io_error\"");
    }

    #[test]
    fn error_code_config_parse_serializes() {
        let s = serde_json::to_string(&ErrorCode::ConfigParse).unwrap();
        assert_eq!(s, "\"config_parse\"");
    }
}
