//! Error type for `ucb-sync`.

use thiserror::Error;
use ucb_core::DeviceId;

/// Result alias for the crate's fallible public API.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the allowlist, pairing flow and sync engine.
#[derive(Debug, Error)]
pub enum Error {
    /// Transport / filesystem IO failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Error bubbled up from `ucb-crypto` (handshake, key storage, channel).
    #[error("crypto error: {0}")]
    Crypto(#[from] ucb_crypto::Error),

    /// Error bubbled up from `ucb-core` (wire codec, protocol variants).
    #[error("core error: {0}")]
    Core(#[from] ucb_core::Error),

    /// Failure serializing / deserializing the allowlist JSON.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The clipboard service worker has stopped.
    #[error("clipboard error: {0}")]
    Clipboard(#[from] ucb_clipboard::Error),

    /// Adding this device would exceed the sync-group cap (PAIR-5).
    #[error("device limit reached (max {0} devices including self)")]
    DeviceLimit(usize),

    /// The remote peer is not present in the local allowlist.
    #[error("peer not trusted: {0}")]
    UntrustedPeer(DeviceId),

    /// Protocol version mismatch during the Hello exchange (SYNC-6).
    #[error("protocol version mismatch: local {local}, remote {remote}")]
    VersionMismatch { local: u16, remote: u16 },

    /// The remote peer sent a `Reject` message.
    #[error("peer rejected the connection: {0}")]
    Rejected(String),

    /// The user declined the pairing code confirmation.
    #[error("pairing declined by user")]
    PairingDeclined,

    /// A message arrived out of the expected order during setup.
    #[error("unexpected message during handshake exchange")]
    UnexpectedMessage,

    /// Catch-all for otherwise-unclassified failures.
    #[error("{0}")]
    Other(String),
}
