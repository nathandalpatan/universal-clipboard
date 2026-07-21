//! Application-layer anti-replay and clock-skew checks (CRYPTO-2, CRYPTO-3).

/// Clock-skew tolerance in milliseconds (±2 minutes).
pub const CLOCK_SKEW_TOLERANCE_MS: i64 = 120_000;

/// Rejects out-of-order or replayed sequence numbers within one session.
///
/// The receiver accepts a `seq` only if it is strictly greater than every
/// previously accepted value (CRYPTO-2). This guards the application layer;
/// Noise nonces already prevent transport-level replay.
#[derive(Debug, Default, Clone)]
pub struct ReplayGuard {
    last: Option<u64>,
}

impl ReplayGuard {
    /// Create a guard that has seen no messages yet.
    pub fn new() -> Self {
        Self { last: None }
    }

    /// Accept `seq` if it advances the sequence, otherwise reject it as a
    /// replay/out-of-order message.
    pub fn check(&mut self, seq: u64) -> Result<(), ucb_core::Error> {
        match self.last {
            Some(last) if seq <= last => Err(ucb_core::Error::Replay { got: seq, expected: last }),
            _ => {
                self.last = Some(seq);
                Ok(())
            }
        }
    }
}

/// Reject a timestamp that differs from `now_ms` by more than
/// [`CLOCK_SKEW_TOLERANCE_MS`] (CRYPTO-3).
pub fn check_clock_skew(ts_ms: u64, now_ms: u64) -> Result<(), ucb_core::Error> {
    // Compute as i64 so a future timestamp yields a negative skew.
    let skew_ms = (now_ms as i64) - (ts_ms as i64);
    if skew_ms.abs() > CLOCK_SKEW_TOLERANCE_MS {
        Err(ucb_core::Error::ClockSkew { skew_ms })
    } else {
        Ok(())
    }
}
