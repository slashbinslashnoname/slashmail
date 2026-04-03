//! Configuration storage: ~/.slashmail/ directory and config.toml management.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Channel topology stored in the swarms config table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    /// One-to-one direct message channel.
    Direct,
    /// Multi-party group channel.
    Group,
}

/// An entry in the swarms table inside `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwarmEntry {
    /// Human-readable name for this swarm.
    pub name: String,

    /// Whether this is a direct or group channel.
    pub kind: ChannelKind,

    /// Optional base64-encoded symmetric key used for group encryption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symmetric_key: Option<String>,
}

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

    /// Optional relay node multiaddress for dcutr NAT hole-punching.
    ///
    /// When set, the daemon will listen through this relay so that peers
    /// behind NAT can reach it via dcutr. Without a relay, dcutr
    /// hole-punching is inactive — direct connections (LAN, public IP,
    /// `add-peer`) still work normally.
    ///
    /// Example: `/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_addr: Option<String>,

    /// Known swarms, keyed by swarm ID.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub swarms: HashMap<String, SwarmEntry>,
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
            relay_addr: None,
            swarms: HashMap::new(),
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

    /// Return the path to the messages database inside the data directory.
    pub fn db_path() -> Result<PathBuf, AppError> {
        Ok(Self::data_dir()?.join("messages.db"))
    }

    /// Return the path to the daemon PID file (`~/.slashmail/daemon.pid`).
    pub fn pid_path() -> Result<PathBuf, AppError> {
        Ok(Self::data_dir()?.join("daemon.pid"))
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
        assert_eq!(cfg.relay_addr, None);
        assert!(cfg.swarms.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let mut swarms = HashMap::new();
        swarms.insert(
            "swarm-abc".to_string(),
            SwarmEntry {
                name: "Dev Chat".to_string(),
                kind: ChannelKind::Group,
                symmetric_key: Some("c2VjcmV0a2V5".to_string()),
            },
        );
        swarms.insert(
            "swarm-dm1".to_string(),
            SwarmEntry {
                name: "Alice DM".to_string(),
                kind: ChannelKind::Direct,
                symmetric_key: None,
            },
        );

        let cfg = Config {
            display_name: Some("Alice".to_string()),
            public_key: Some("dGVzdGtleQ==".to_string()),
            listen_addr: "/ip4/127.0.0.1/tcp/4001".to_string(),
            mdns_enabled: false,
            relay_addr: None,
            swarms,
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

    #[test]
    fn empty_swarms_not_serialized() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        Config::default().save_to(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("[swarms]"), "empty swarms should be omitted from TOML");
    }

    #[test]
    fn swarms_roundtrip_with_symmetric_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let mut swarms = HashMap::new();
        swarms.insert(
            "grp-123".to_string(),
            SwarmEntry {
                name: "Team".to_string(),
                kind: ChannelKind::Group,
                symmetric_key: Some("a2V5ZGF0YQ==".to_string()),
            },
        );

        let cfg = Config {
            swarms,
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();

        assert_eq!(loaded.swarms.len(), 1);
        let entry = &loaded.swarms["grp-123"];
        assert_eq!(entry.name, "Team");
        assert_eq!(entry.kind, ChannelKind::Group);
        assert_eq!(entry.symmetric_key.as_deref(), Some("a2V5ZGF0YQ=="));
    }

    #[test]
    fn swarms_roundtrip_without_symmetric_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let mut swarms = HashMap::new();
        swarms.insert(
            "dm-456".to_string(),
            SwarmEntry {
                name: "Bob DM".to_string(),
                kind: ChannelKind::Direct,
                symmetric_key: None,
            },
        );

        let cfg = Config {
            swarms,
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();

        // Verify symmetric_key is not present in serialized output
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("symmetric_key"), "None symmetric_key should be omitted");

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.swarms["dm-456"].symmetric_key, None);
    }

    #[test]
    fn load_config_with_swarms_from_raw_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
display_name = "Eve"

[swarms.my-group]
name = "My Group"
kind = "group"
symmetric_key = "c29tZWtleQ=="

[swarms.my-dm]
name = "My DM"
kind = "direct"
"#,
        )
        .unwrap();

        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.display_name, Some("Eve".to_string()));
        assert_eq!(cfg.swarms.len(), 2);

        let group = &cfg.swarms["my-group"];
        assert_eq!(group.kind, ChannelKind::Group);
        assert_eq!(group.symmetric_key.as_deref(), Some("c29tZWtleQ=="));

        let dm = &cfg.swarms["my-dm"];
        assert_eq!(dm.kind, ChannelKind::Direct);
        assert_eq!(dm.symmetric_key, None);
    }

    #[test]
    fn legacy_config_without_swarms_loads_with_empty_map() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            "display_name = \"Legacy\"\nlisten_addr = \"/ip4/0.0.0.0/tcp/4001\"\n",
        )
        .unwrap();

        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.display_name, Some("Legacy".to_string()));
        assert!(cfg.swarms.is_empty());
    }

    #[test]
    fn relay_addr_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        let cfg = Config {
            relay_addr: Some(
                "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
                    .to_string(),
            ),
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(cfg.relay_addr, loaded.relay_addr);
    }

    #[test]
    fn relay_addr_none_not_serialized() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");

        Config::default().save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("relay_addr"),
            "None relay_addr should be omitted from TOML"
        );
    }

    #[test]
    fn config_without_relay_addr_defaults_to_none() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "display_name = \"NoRelay\"\n").unwrap();

        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.relay_addr, None);
    }

    #[test]
    fn config_with_relay_addr_from_raw_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
relay_addr = "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
"#,
        )
        .unwrap();

        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(
            cfg.relay_addr.as_deref(),
            Some("/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
        );
    }
}
