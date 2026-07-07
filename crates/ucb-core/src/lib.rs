//! ucb-core — shared types and wire protocol for Universal Clipboard.
//!
//! This crate is the contract between all other crates. It has no async,
//! no IO, and no crypto — just data types, serialization, and hashing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Wire protocol version (SYNC-6). Bump on breaking protocol changes.
pub const PROTOCOL_VERSION: u16 = 1;

/// mDNS service type used for LAN discovery (DISC-1).
pub const MDNS_SERVICE_TYPE: &str = "_ucb._tcp.local.";

/// Maximum devices in a sync group, including this one (PAIR-5).
pub const MAX_DEVICES: usize = 3;

/// Stable device identifier: BLAKE3 hash of the device's static Noise
/// (X25519) public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    pub fn from_public_key(static_pubkey: &[u8]) -> Self {
        DeviceId(*blake3::hash(static_pubkey).as_bytes())
    }

    /// Short human-readable form (first 8 hex chars), for logs and UI.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
    Android,
    Ios,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        return Platform::MacOs;
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Platform::Linux;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub platform: Platform,
}

/// Clipboard content. Text-only for the MVP (SYNC-1); the enum leaves room
/// for SYNC-4 (HTML/image) without a wire-format break.
///
/// NOTE (SEC-2): `Debug` is implemented manually and never prints content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardPayload {
    Text(String),
}

impl ClipboardPayload {
    pub fn content_hash(&self) -> [u8; 32] {
        match self {
            ClipboardPayload::Text(s) => *blake3::hash(s.as_bytes()).as_bytes(),
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            ClipboardPayload::Text(s) => s.len(),
        }
    }
}

impl fmt::Debug for ClipboardPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipboardPayload::Text(s) => write!(f, "ClipboardPayload::Text(<{} bytes redacted>)", s.len()),
        }
    }
}

/// One clipboard event as it travels between devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardItem {
    pub payload: ClipboardPayload,
    /// Milliseconds since UNIX epoch, from the originating device's clock.
    pub ts_ms: u64,
    /// Device that produced this clipboard content (not just relayed it).
    pub origin: DeviceId,
}

impl ClipboardItem {
    pub fn content_hash(&self) -> [u8; 32] {
        self.payload.content_hash()
    }

    /// Conflict resolution (SYNC-3): newer timestamp wins; ties broken by
    /// device ID ordering so all devices converge on the same winner.
    pub fn wins_over(&self, other: &ClipboardItem) -> bool {
        (self.ts_ms, &self.origin) > (other.ts_ms, &other.origin)
    }
}

/// Plaintext messages exchanged after the Noise handshake completes.
/// Each is bincode-serialized, then AEAD-encrypted as one transport frame.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMessage {
    /// First message from each side after handshake (SYNC-6 version check).
    Hello { version: u16, device: DeviceInfo },
    /// Version or policy rejection; connection closes after sending.
    Reject { reason: String },
    /// A clipboard update. `seq` is per-session, monotonic (CRYPTO-2).
    Clip { seq: u64, item: ClipboardItem },
    Ping,
    Pong,
}

impl WireMessage {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        bincode::serialize(self).map_err(|e| Error::Codec(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(bytes).map_err(|e| Error::Codec(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("codec error: {0}")]
    Codec(String),
    #[error("protocol version mismatch: local {local}, remote {remote}")]
    VersionMismatch { local: u16, remote: u16 },
    #[error("peer not in allowlist: {0}")]
    UntrustedPeer(String),
    #[error("device limit reached (max {0})")]
    DeviceLimit(usize),
    #[error("replay or out-of-order message rejected (seq {got}, expected > {expected})")]
    Replay { got: u64, expected: u64 },
    #[error("clock skew beyond tolerance: {skew_ms} ms")]
    ClockSkew { skew_ms: i64 },
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(ts: u64, id_byte: u8, text: &str) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Text(text.into()),
            ts_ms: ts,
            origin: DeviceId([id_byte; 32]),
        }
    }

    #[test]
    fn wire_roundtrip() {
        let msg = WireMessage::Clip { seq: 7, item: item(1000, 1, "hello") };
        let bytes = msg.encode().unwrap();
        match WireMessage::decode(&bytes).unwrap() {
            WireMessage::Clip { seq, item } => {
                assert_eq!(seq, 7);
                assert_eq!(item.payload, ClipboardPayload::Text("hello".into()));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn conflict_resolution_timestamp_then_device_id() {
        assert!(item(2000, 1, "a").wins_over(&item(1000, 2, "b")));
        assert!(item(1000, 2, "a").wins_over(&item(1000, 1, "b")));
        assert!(!item(1000, 1, "a").wins_over(&item(1000, 1, "a")));
    }

    #[test]
    fn debug_never_prints_clipboard_content() {
        let it = item(1, 1, "hunter2-super-secret");
        let dbg = format!("{it:?}");
        assert!(!dbg.contains("hunter2"), "Debug leaked content: {dbg}");
    }
}
