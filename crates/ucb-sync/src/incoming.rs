//! Bounded, recent log of *rejected* untrusted inbound connection attempts
//! (NAT-60).
//!
//! The engine rejects any inbound peer that is not in the allowlist (SEC-1),
//! dropping the connection right after the Noise handshake and before any
//! application data is exchanged. That is correct, but it leaves the user blind:
//! a device politely trying to reach them looks identical to nothing happening.
//!
//! This store remembers the last few such attempts so the GUI can show *who*
//! tried to reach this device and offer to start pairing. It is purely
//! informational: recording an attempt grants no trust, accepts no peer, and
//! moves no clipboard or file data. The peer's authenticated [`DeviceId`] is
//! genuine (the handshake proves it), so repeat attempts coalesce on it; the
//! display name — when present — comes from discovery (mDNS), never from an
//! untrusted peer's own claim, since a rejected peer sends no `Hello`.

use std::net::IpAddr;

use ucb_core::DeviceId;

use crate::now_ms;

/// How many distinct recent attempts to retain. A small cap keeps this an
/// at-a-glance surface (and bounds memory against a noisy scanner); once full,
/// the least-recently-seen attempt is evicted.
pub(crate) const MAX_INCOMING_ATTEMPTS: usize = 32;

/// One recent, *rejected* untrusted inbound attempt. Additive read surface for
/// the GUI — mirrors [`DiscoveredPeer`](crate::DiscoveredPeer) in spirit.
///
/// Recording one confers no trust: it only records that a peer with this
/// authenticated id reached us from `addr` and was turned away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingAttempt {
    /// The peer's authenticated device id (from the Noise handshake). Repeat
    /// attempts from the same peer coalesce on this.
    pub device_id: DeviceId,
    /// Display name if discovery already knows this device; `None` when it only
    /// reached us over TCP. Never sourced from the untrusted peer's own claim.
    pub name: Option<String>,
    /// Source address the connection came from.
    pub addr: IpAddr,
    /// Unix-ms of the first time we saw this (device_id, addr) pair.
    pub first_seen_ms: u64,
    /// Unix-ms of the most recent time we saw it.
    pub last_seen_ms: u64,
    /// How many times this peer has tried since the entry was last evicted.
    pub count: u32,
}

/// A bounded, recency-ordered set of [`IncomingAttempt`]s, keyed by
/// `(device_id, addr)` so a retrying peer bumps a count instead of flooding the
/// list. Held behind a `Mutex` in the engine's shared state.
#[derive(Debug)]
pub(crate) struct IncomingAttempts {
    cap: usize,
    items: Vec<IncomingAttempt>,
}

impl IncomingAttempts {
    /// A store holding at most `cap` distinct attempts.
    pub(crate) fn new(cap: usize) -> Self {
        debug_assert!(cap > 0);
        Self {
            cap,
            items: Vec::new(),
        }
    }

    /// Record an attempt now. See [`record_at`](Self::record_at).
    pub(crate) fn record(&mut self, device_id: DeviceId, name: Option<String>, addr: IpAddr) {
        self.record_at(device_id, name, addr, now_ms());
    }

    /// Testable core of [`record`](Self::record) with an explicit clock.
    ///
    /// Coalesces on `(device_id, addr)`: an existing entry has its `count`
    /// bumped and `last_seen_ms` advanced (and gains a `name` if one is now
    /// known). A new `(device_id, addr)` is appended; if that would exceed the
    /// cap, the least-recently-seen entry is evicted first.
    pub(crate) fn record_at(
        &mut self,
        device_id: DeviceId,
        name: Option<String>,
        addr: IpAddr,
        now: u64,
    ) {
        if let Some(a) = self
            .items
            .iter_mut()
            .find(|a| a.device_id == device_id && a.addr == addr)
        {
            a.count = a.count.saturating_add(1);
            a.last_seen_ms = now;
            // Fill in a name that discovery only learned after the first attempt.
            if a.name.is_none() {
                a.name = name;
            }
            return;
        }
        if self.items.len() >= self.cap {
            // Evict the least-recently-seen entry to make room.
            if let Some((idx, _)) = self
                .items
                .iter()
                .enumerate()
                .min_by_key(|(_, a)| a.last_seen_ms)
            {
                self.items.swap_remove(idx);
            }
        }
        self.items.push(IncomingAttempt {
            device_id,
            name,
            addr,
            first_seen_ms: now,
            last_seen_ms: now,
            count: 1,
        });
    }

    /// A snapshot of the current attempts, most-recent first.
    pub(crate) fn snapshot(&self) -> Vec<IncomingAttempt> {
        let mut out = self.items.clone();
        out.sort_by_key(|a| std::cmp::Reverse(a.last_seen_ms));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(b: u8) -> DeviceId {
        DeviceId([b; 32])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn repeat_attempts_coalesce_and_bump_count() {
        let mut store = IncomingAttempts::new(8);
        store.record_at(dev(1), Some("Mac".into()), ip("192.168.1.5"), 100);
        store.record_at(dev(1), Some("Mac".into()), ip("192.168.1.5"), 250);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, 2);
        assert_eq!(snap[0].first_seen_ms, 100);
        assert_eq!(snap[0].last_seen_ms, 250);
    }

    #[test]
    fn distinct_device_or_addr_are_separate_entries() {
        let mut store = IncomingAttempts::new(8);
        store.record_at(dev(1), None, ip("10.0.0.1"), 10);
        store.record_at(dev(2), None, ip("10.0.0.1"), 20); // same addr, other device
        store.record_at(dev(1), None, ip("10.0.0.2"), 30); // same device, other addr
        assert_eq!(store.snapshot().len(), 3);
    }

    #[test]
    fn name_backfills_once_discovery_learns_it() {
        let mut store = IncomingAttempts::new(8);
        store.record_at(dev(1), None, ip("10.0.0.1"), 10);
        store.record_at(dev(1), Some("Laptop".into()), ip("10.0.0.1"), 20);
        assert_eq!(store.snapshot()[0].name.as_deref(), Some("Laptop"));
    }

    #[test]
    fn snapshot_is_most_recent_first() {
        let mut store = IncomingAttempts::new(8);
        store.record_at(dev(1), None, ip("10.0.0.1"), 100);
        store.record_at(dev(2), None, ip("10.0.0.2"), 300);
        store.record_at(dev(3), None, ip("10.0.0.3"), 200);
        let order: Vec<u8> = store.snapshot().iter().map(|a| a.device_id.0[0]).collect();
        assert_eq!(order, vec![2, 3, 1]);
    }

    #[test]
    fn cap_evicts_the_least_recently_seen() {
        let mut store = IncomingAttempts::new(2);
        store.record_at(dev(1), None, ip("10.0.0.1"), 100); // oldest
        store.record_at(dev(2), None, ip("10.0.0.2"), 200);
        store.record_at(dev(3), None, ip("10.0.0.3"), 300); // evicts dev(1)
        let ids: Vec<u8> = store.snapshot().iter().map(|a| a.device_id.0[0]).collect();
        assert_eq!(store.snapshot().len(), 2);
        assert!(ids.contains(&2) && ids.contains(&3));
        assert!(!ids.contains(&1));
    }
}
