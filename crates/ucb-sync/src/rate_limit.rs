//! Per-source-IP token-bucket rate limiter for inbound handshakes (SEC-3).
//!
//! Each source IP gets a bucket that starts full and refills continuously. The
//! default policy (max 5 handshakes per minute per IP) is a capacity of 5 with
//! a refill rate of `5 / 60` tokens per second. A handshake is admitted only if
//! a whole token is available, which it then consumes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// A refilling token bucket per source IP.
#[derive(Debug)]
pub struct TokenBucketLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: HashMap<IpAddr, Bucket>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucketLimiter {
    /// Allow `max` events per `per_secs` window (per IP). For SEC-3 use
    /// `new(5.0, 60.0)`.
    pub fn new(max: f64, per_secs: f64) -> Self {
        debug_assert!(max > 0.0 && per_secs > 0.0);
        Self {
            capacity: max,
            refill_per_sec: max / per_secs,
            buckets: HashMap::new(),
        }
    }

    /// The SEC-3 default: 5 handshakes per minute per IP.
    pub fn per_minute_5() -> Self {
        Self::new(5.0, 60.0)
    }

    /// Admit one event from `ip` now, consuming a token if available.
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Testable core of [`allow`](Self::allow) with an explicit clock.
    pub fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        let capacity = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * refill).min(capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip() -> IpAddr {
        "10.0.0.5".parse().unwrap()
    }

    #[test]
    fn allows_burst_up_to_capacity_then_blocks() {
        let mut rl = TokenBucketLimiter::per_minute_5();
        let t0 = Instant::now();
        for i in 0..5 {
            assert!(rl.allow_at(ip(), t0), "handshake {i} should be allowed");
        }
        // 6th within the same instant is blocked.
        assert!(!rl.allow_at(ip(), t0), "6th handshake must be rate-limited");
    }

    #[test]
    fn refills_over_time() {
        let mut rl = TokenBucketLimiter::per_minute_5();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(rl.allow_at(ip(), t0));
        }
        assert!(!rl.allow_at(ip(), t0));
        // One token accrues every 12s at 5/min.
        assert!(rl.allow_at(ip(), t0 + Duration::from_secs(12)));
        // ...but not two in a row.
        assert!(!rl.allow_at(ip(), t0 + Duration::from_secs(12)));
    }

    #[test]
    fn buckets_are_per_ip() {
        let mut rl = TokenBucketLimiter::per_minute_5();
        let t0 = Instant::now();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.allow_at(a, t0));
        }
        assert!(!rl.allow_at(a, t0));
        // A different IP is unaffected.
        assert!(rl.allow_at(b, t0));
    }
}
