//! Error type for `ucb-crypto` operations.
//!
//! Application-layer checks (`ReplayGuard`, `check_clock_skew`) return
//! [`ucb_core::Error`] directly, since those variants live in the shared
//! contract. Everything else (IO, Noise, key storage) uses [`Error`].

use thiserror::Error;

/// Errors produced by identity, key storage, handshake and channel code.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying transport IO failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Noise protocol failure from the `snow` crate.
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),

    /// OS keyring failure from the `keyring` crate.
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),

    /// Error bubbled up from `ucb-core` (e.g. `WireMessage` codec).
    #[error("core error: {0}")]
    Core(#[from] ucb_core::Error),

    /// A frame exceeded the 16 MiB protocol maximum.
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    /// A received frame was structurally malformed (bad chunk framing).
    #[error("malformed frame: {0}")]
    MalformedFrame(String),

    /// Key material stored on disk / in the keyring was invalid.
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// The XX handshake completed but no remote static key was revealed.
    #[error("handshake did not yield a remote static key")]
    MissingRemoteStatic,
}

/// Convenience alias used throughout the crate's fallible public API.
pub type Result<T> = std::result::Result<T, Error>;
