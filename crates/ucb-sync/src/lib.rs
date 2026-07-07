//! ucb-sync — see ARCHITECTURE.md for the contract this crate implements.
//!
//! The sync engine ties the other crates together: it owns the transport,
//! the trust allowlist, session management, conflict resolution and rate
//! limiting (SYNC-1/3/6, PAIR-4/5/6, SEC-3, DISC-4 reconnect).
//!
//! * [`Allowlist`] — persistent trust store (PAIR-4/5/6).
//! * [`SyncEngine`] — the running engine ([`SyncEngine::start`]).
//! * [`pair_listen`] / [`pair_dial`] — the interactive pairing flow (PAIR-2).
//! * [`TokenBucketLimiter`] — per-IP handshake rate limiting (SEC-3).

mod allowlist;
mod engine;
mod error;
mod pairing;
mod rate_limit;

pub use allowlist::{Allowlist, TrustedDevice};
pub use engine::{EngineConfig, PeerStatus, SyncEngine};
pub use error::{Error, Result};
pub use pairing::{pair_dial, pair_listen, ConfirmPairing};
pub use rate_limit::TokenBucketLimiter;

/// Milliseconds since the UNIX epoch, saturating to 0 before 1970.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
