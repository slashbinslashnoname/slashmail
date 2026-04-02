//! Configuration storage: ~/.slashmail/ directory and config.toml management.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Application configuration persisted to `~/.slashmail/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Display name for the user.
    #[serde(default)]
    pub display_name: Option<String>,

    /// Base64-encoded Ed25519 public key.
    #[serde(default)]
    pub public_key: Option<String>,

    /// Listen address for the P2P daemon.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Enable mDNS peer discovery on the local network.
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/tcp/0".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            display_name: None,
            public_key: None,
            listen_addr: default_listen_addr(),
            mdns_enabled: true,
        }
    }
}

impl Config {
    /// Return the slashmail data directory (`~/.slashmail/`).
    pub fn data_dir() -> Result<PathBuf, AppError> {
        let home = dirs_home().ok_or_else(|| {
            AppError::Other("could not determine home directory".to_string())
        })?;
        Ok(home.join(".slashmail"))
    }

    /// Return the path to `config.toml` inside the data directory.
    pub fn config_path() -> Result<PathBuf, AppError> {
        Ok(Self::data_dir()?.join("config.toml"))
    }

    /// Ensure the `~/.slashmail/` directory exists. Creates it if missing.
    pub fn ensure_dir() -> Result<PathBuf, AppError> {
        let dir = Self::data_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| AppError::io(&dir, e))?;
        Ok(dir)
    }

    /// Load configuration from `config.toml`. Returns defaults if the file
    /// does not exist yet.
    pub fn load() -> Result<Self, AppError> {
        let path = Self::config_path()?;
        Self::load_from(&path)
    }

    /// Load configuration from an arbitrary path. Returns defaults if the
    /// file does not exist.
    pub fn load_from(path: &Path) -> Result<Self, AppError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| AppError::io(path, e))?;
        toml::from_str(&contents).map_err(|e| AppError::ConfigParse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Save configuration to `config.toml`, creating the directory if needed.
    pub fn save(&self) -> Result<(), AppError> {
        Self::ensure_dir()?;
        let path = Self::config_path()?;
        self.save_to(&path)
    }

    /// Save configuration to an arbitrary path.
    pub fn save_to(&self, path: &Path) -> Result<(), AppError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AppError::io(parent, e))?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content).map_err(|e| AppError::io(path, e))?;
        Ok(())
    }
}

/// Resolve the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = Config::default();
        assert_eq!(cfg.display_name, None);
        assert_eq!(cfg.public_key, None);
        assert_eq!(cfg.listen_addr, "/ip4/0.0.0.0/tcp/0");
        assert!(cfg.mdns_enabled);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let cfg = Config {
            display_name: Some("Alice".to_string()),
            public_key: Some("dGVzdGtleQ==".to_string()),
            listen_addr: "/ip4/127.0.0.1/tcp/4001".to_string(),
            mdns_enabled: false,
        };

        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(cfg, loaded);
    }

    #[test]
    fn load_missing_file_returns_default() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn load_partial_config_fills_defaults() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "display_name = \"Bob\"\n").unwrap();

        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.display_name, Some("Bob".to_string()));
        assert_eq!(cfg.listen_addr, "/ip4/0.0.0.0/tcp/0");
        assert!(cfg.mdns_enabled);
    }

    #[test]
    fn load_invalid_toml_returns_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "not valid {{toml").unwrap();

        let err = Config::load_from(&path).unwrap_err();
        assert!(matches!(err, AppError::ConfigParse { .. }));
    }

    #[test]
    fn save_creates_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("deep").join("nested").join("config.toml");

        Config::default().save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn saved_file_is_valid_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let cfg = Config {
            display_name: Some("Test".to_string()),
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: toml::Value = toml::from_str(&raw).unwrap();
        assert_eq!(
            parsed.get("display_name").and_then(|v| v.as_str()),
            Some("Test")
        );
    }
}
