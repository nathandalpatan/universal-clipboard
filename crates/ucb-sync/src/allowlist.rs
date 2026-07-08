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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ucb_core::{DeviceId, MAX_DEVICES};

use crate::error::{Error, Result};

/// File name (sibling of `trusted.json`) holding the revocation tombstone list
/// (PAIR-7).
const TOMBSTONE_FILE: &str = "revoked.json";

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
///
/// Alongside the trust map the allowlist owns a revocation *tombstone* set
/// (PAIR-7), persisted to a sibling `revoked.json`. A tombstoned device may not
/// be re-added ([`Allowlist::add`] fails) until it is [`forget`](Allowlist::forget).
#[derive(Debug)]
pub struct Allowlist {
    path: PathBuf,
    /// Sibling `revoked.json` path.
    tombstone_path: PathBuf,
    /// device-id-hex -> entry. A `BTreeMap` gives deterministic file ordering.
    map: BTreeMap<String, StoredEntry>,
    /// Revoked device ids (hex). A `BTreeSet` gives deterministic file ordering.
    tombstones: BTreeSet<String>,
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
        let tombstone_path = path.with_file_name(TOMBSTONE_FILE);
        let tombstones = match std::fs::read(&tombstone_path) {
            Ok(bytes) if bytes.is_empty() => BTreeSet::new(),
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(Self {
            path,
            tombstone_path,
            map,
            tombstones,
        })
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
        // PAIR-7: a revoked device may never be re-added while tombstoned.
        if self.tombstones.contains(&key) {
            return Err(Error::Tombstoned(id));
        }
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

    // --- revocation / tombstones (PAIR-7) ---------------------------------

    /// True if `id` has been revoked (tombstoned) and may not be re-added.
    pub fn is_tombstoned(&self, id: &DeviceId) -> bool {
        self.tombstones.contains(&id.to_string())
    }

    /// Revoke `id`: remove it from the allowlist (if present) and record a
    /// tombstone. Both files are persisted atomically. Returns `true` iff the
    /// tombstone was *newly* added (i.e. the device was not already revoked);
    /// this makes the operation idempotent so remote `Revoke` messages never
    /// loop.
    ///
    /// Used both by the `ucb revoke` CLI (local revocation) and by the engine
    /// when it receives a `Revoke` from a trusted peer.
    pub fn revoke(&mut self, id: DeviceId) -> Result<bool> {
        let key = id.to_string();
        let removed_entry = self.map.remove(&key).is_some();
        let newly = self.tombstones.insert(key);
        if removed_entry {
            self.save()?;
        }
        if newly {
            self.save_tombstones()?;
        }
        Ok(newly)
    }

    /// Clear a tombstone (`ucb revoke --forget`), allowing the device to be
    /// paired again in the future. Returns whether a tombstone was present.
    pub fn forget(&mut self, id: &DeviceId) -> Result<bool> {
        let removed = self.tombstones.remove(&id.to_string());
        if removed {
            self.save_tombstones()?;
        }
        Ok(removed)
    }

    /// All tombstoned device ids, decoded. Used by the engine to broadcast
    /// `Revoke` for each at session start / on the periodic re-check.
    pub fn tombstones(&self) -> Vec<DeviceId> {
        self.tombstones
            .iter()
            .filter_map(|k| decode_device_id(k))
            .collect()
    }

    /// Resolve a device-id hex *prefix* against the tombstone list (used by
    /// `ucb revoke --forget`).
    pub fn resolve_tombstone_prefix(&self, prefix: &str) -> Option<DeviceId> {
        let prefix = prefix.to_lowercase();
        let mut matches = self.tombstones.iter().filter(|k| k.starts_with(&prefix));
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

    /// Atomically write the tombstone set to `revoked.json` (temp + rename).
    fn save_tombstones(&self) -> Result<()> {
        if let Some(parent) = self.tombstone_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_vec_pretty(&self.tombstones)?;
        let tmp = self
            .tombstone_path
            .with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.tombstone_path)?;
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
