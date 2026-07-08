//! On-disk configuration and path layout for the `ucb` daemon.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use ucb_crypto::{FileKeyStore, KeyStore, KeyringStore};

/// Default TCP port the daemon listens and advertises on.
pub const DEFAULT_PORT: u16 = 48521;

/// Which secret backend holds the device private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Keystore {
    /// OS keyring (default).
    Keyring,
    /// Plaintext `0600` file under the config dir (headless fallback).
    File,
}

/// Persisted daemon configuration (`config.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub listen_port: u16,
    pub keystore: Keystore,
    /// Manually configured always-present peers (DISC-3), each `"ip:port"`.
    /// Defaults to empty for configs written before this field existed.
    #[serde(default)]
    pub static_peers: Vec<String>,
    /// Reject inbound file offers larger than this many bytes (FILE-6 policy).
    /// `None` (the default) accepts any size.
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
}

impl Config {
    /// Load `config.json`, erroring if it does not exist (run `ucb init` first).
    pub fn load(paths: &Paths) -> Result<Self> {
        let bytes = std::fs::read(&paths.config_file).with_context(|| {
            format!(
                "reading {} (run `ucb init` first)",
                paths.config_file.display()
            )
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Write `config.json`, creating the config directory if needed.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        std::fs::create_dir_all(&paths.config_dir)?;
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&paths.config_file, json)?;
        Ok(())
    }
}

/// Resolved filesystem locations for the daemon's state.
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub trusted_file: PathBuf,
    pub keys_dir: PathBuf,
    /// Encrypted history database (HIST-1).
    pub history_file: PathBuf,
    /// Destination directory for inbound file transfers (FILE-6).
    pub received_dir: PathBuf,
    /// Unix socket the running daemon serves for status/send IPC (UX-1).
    pub socket_file: PathBuf,
}

impl Paths {
    /// Resolve the daemon's filesystem layout.
    ///
    /// With `override_dir = Some(dir)` every file lives directly under `dir`
    /// (the global `--config-dir` flag; makes the daemon fully sandboxable for
    /// tests and the Docker harness). With `None` it falls back to the platform
    /// config directory for `ProjectDirs("dev", "ucb", "universal-clipboard")`.
    pub fn resolve(override_dir: Option<PathBuf>) -> Result<Self> {
        let config_dir = match override_dir {
            Some(dir) => dir,
            None => {
                let dirs = ProjectDirs::from("dev", "ucb", "universal-clipboard").ok_or_else(
                    || anyhow!("could not determine a config directory for this platform"),
                )?;
                dirs.config_dir().to_path_buf()
            }
        };
        Ok(Self {
            config_file: config_dir.join("config.json"),
            trusted_file: config_dir.join("trusted.json"),
            keys_dir: config_dir.join("keys"),
            history_file: config_dir.join("history.db"),
            received_dir: config_dir.join("received"),
            socket_file: config_dir.join("daemon.sock"),
            config_dir,
        })
    }
}

/// Build the key store selected by `config`.
pub fn build_keystore(config: &Config, paths: &Paths) -> Box<dyn KeyStore> {
    match config.keystore {
        Keystore::Keyring => Box::new(KeyringStore::new()),
        Keystore::File => Box::new(FileKeyStore::new(paths.keys_dir.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ucb-daemon-cfg-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn config_round_trips_static_peers() {
        let dir = temp_dir("roundtrip");
        let paths = Paths::resolve(Some(dir)).unwrap();
        let config = Config {
            name: "Test".into(),
            listen_port: DEFAULT_PORT,
            keystore: Keystore::File,
            static_peers: vec!["10.0.0.7:48521".into(), "192.168.1.5:9000".into()],
            max_file_bytes: Some(1024),
        };
        config.save(&paths).unwrap();
        let loaded = Config::load(&paths).unwrap();
        assert_eq!(loaded.static_peers, config.static_peers);
        assert_eq!(loaded.name, "Test");
        assert_eq!(loaded.max_file_bytes, Some(1024));
    }

    #[test]
    fn config_without_static_peers_defaults_empty() {
        let dir = temp_dir("legacy");
        let paths = Paths::resolve(Some(dir)).unwrap();
        // Simulate a config written before `static_peers` existed.
        std::fs::write(
            &paths.config_file,
            br#"{"name":"Old","listen_port":48521,"keystore":"keyring"}"#,
        )
        .unwrap();
        let loaded = Config::load(&paths).unwrap();
        assert!(loaded.static_peers.is_empty());
    }
}
