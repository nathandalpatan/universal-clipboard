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
}

impl Paths {
    /// Resolve the platform config directory for
    /// `ProjectDirs("dev", "ucb", "universal-clipboard")`.
    pub fn resolve() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "ucb", "universal-clipboard")
            .ok_or_else(|| anyhow!("could not determine a config directory for this platform"))?;
        let config_dir = dirs.config_dir().to_path_buf();
        Ok(Self {
            config_file: config_dir.join("config.json"),
            trusted_file: config_dir.join("trusted.json"),
            keys_dir: config_dir.join("keys"),
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
