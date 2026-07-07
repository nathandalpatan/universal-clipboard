//! Persistent trust store (PAIR-4/5/6).
//!
//! The allowlist maps a trusted peer's [`DeviceId`] to its display name, static
//! public key and the time it was added. It is persisted as JSON at a
//! caller-supplied path (conventionally `trusted.json` in the config dir),
//! keyed by the lowercase hex device id:
//!
//! ```json
//! {
//!   "<device-id-hex>": {
//!     "name": "Laptop",
//!     "static_pubkey": "<32-byte-key-hex>",
//!     "added_ts_ms": 1710000000000
//!   }
//! }
//! ```
//!
//! Writes are atomic: the new content is written to a sibling temp file which is
//! then renamed over the target, so a crash mid-write never truncates the store.
//! The group is capped at [`ucb_core::MAX_DEVICES`] *including this device*, so
//! at most `MAX_DEVICES - 1` remote entries may be stored (PAIR-5).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ucb_core::{DeviceId, MAX_DEVICES};

use crate::error::{Error, Result};

/// One persisted allowlist entry, as stored on disk (hex-encoded key material).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    name: String,
    /// Lowercase hex of the 32-byte X25519 static public key.
    static_pubkey: String,
    added_ts_ms: u64,
}

/// A decoded, in-memory view of a trusted device (returned by [`Allowlist::list`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    pub device_id: DeviceId,
    pub name: String,
    pub static_pubkey: [u8; 32],
    pub added_ts_ms: u64,
}

/// The persistent allowlist. Load with [`Allowlist::load`]; mutations persist
/// atomically to the backing file as they happen.
#[derive(Debug)]
pub struct Allowlist {
    path: PathBuf,
    /// device-id-hex -> entry. A `BTreeMap` gives deterministic file ordering.
    map: BTreeMap<String, StoredEntry>,
}

impl Allowlist {
    /// Load the allowlist from `path`, or start empty if the file does not
    /// exist. A malformed file is an error (rather than silently discarding
    /// trust).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let map = match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(Self { path, map })
    }

    /// True if `id` is a trusted peer.
    pub fn is_trusted(&self, id: &DeviceId) -> bool {
        self.map.contains_key(&id.to_string())
    }

    /// The stored static public key for `id`, if trusted and well-formed.
    pub fn pubkey_of(&self, id: &DeviceId) -> Option<[u8; 32]> {
        let entry = self.map.get(&id.to_string())?;
        decode_pubkey(&entry.static_pubkey)
    }

    /// The stored display name for `id`, if trusted.
    pub fn name_of(&self, id: &DeviceId) -> Option<String> {
        self.map.get(&id.to_string()).map(|e| e.name.clone())
    }

    /// Add (or update) a trusted device, persisting the change.
    ///
    /// Adding a *new* device when the group is already full returns
    /// [`Error::DeviceLimit`] (PAIR-5). Re-adding an already-trusted device
    /// updates its record and never counts against the cap.
    pub fn add(
        &mut self,
        id: DeviceId,
        name: impl Into<String>,
        static_pubkey: &[u8; 32],
        added_ts_ms: u64,
    ) -> Result<()> {
        let key = id.to_string();
        let is_new = !self.map.contains_key(&key);
        // MAX_DEVICES counts this device, so remote entries are capped one below.
        if is_new && self.map.len() >= MAX_DEVICES - 1 {
            return Err(Error::DeviceLimit(MAX_DEVICES));
        }
        self.map.insert(
            key,
            StoredEntry {
                name: name.into(),
                static_pubkey: hex::encode(static_pubkey),
                added_ts_ms,
            },
        );
        self.save()
    }

    /// Remove a trusted device (PAIR-6). Returns whether it was present. The
    /// change is persisted (best-effort; a write failure is logged, not
    /// returned, so the in-memory removal always takes effect).
    pub fn remove(&mut self, id: &DeviceId) -> bool {
        let existed = self.map.remove(&id.to_string()).is_some();
        if existed {
            if let Err(e) = self.save() {
                tracing::error!(error = %e, "failed to persist allowlist after removal");
            }
        }
        existed
    }

    /// Resolve a device-id hex *prefix* to the full id, if exactly one entry
    /// matches. Convenience for the `revoke` CLI (PAIR-6).
    pub fn resolve_prefix(&self, prefix: &str) -> Option<DeviceId> {
        let prefix = prefix.to_lowercase();
        let mut matches = self.map.keys().filter(|k| k.starts_with(&prefix));
        let first = matches.next()?;
        if matches.next().is_some() {
            return None; // ambiguous
        }
        decode_device_id(first)
    }

    /// All trusted devices, decoded.
    pub fn list(&self) -> Vec<TrustedDevice> {
        self.map
            .iter()
            .filter_map(|(k, v)| {
                Some(TrustedDevice {
                    device_id: decode_device_id(k)?,
                    name: v.name.clone(),
                    static_pubkey: decode_pubkey(&v.static_pubkey)?,
                    added_ts_ms: v.added_ts_ms,
                })
            })
            .collect()
    }

    /// Number of trusted remote devices.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if no devices are trusted yet.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The path this allowlist persists to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically write the current state to disk (temp file + rename).
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_vec_pretty(&self.map)?;

        // Unique-ish temp sibling so concurrent writers don't collide.
        let tmp = self.path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Decode a 64-char hex string into a [`DeviceId`].
fn decode_device_id(hex_str: &str) -> Option<DeviceId> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(DeviceId(arr))
}

/// Decode a 64-char hex string into a 32-byte public key.
fn decode_pubkey(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}
