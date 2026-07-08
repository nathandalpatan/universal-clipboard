//! Per-peer offline clipboard queue (SYNC-5).
//!
//! When a trusted peer has no live session, clipboard updates destined for it
//! are buffered in a per-peer FIFO. On reconnect the queue is drained in order
//! (as fresh `Clip` messages) before normal live sync resumes.
//!
//! Policy:
//! * cap [`QUEUE_CAP`] items per peer (the oldest is dropped when full);
//! * items older than [`QUEUE_MAX_AGE_MS`] are pruned at enqueue and drain time;
//! * the whole queue is persisted as JSON (`queue.json`, atomic write) next to
//!   the allowlist so a daemon restart does not lose buffered clips.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ucb_core::{ClipboardItem, DeviceId};

use crate::error::{Error, Result};

/// Maximum buffered items per peer; enqueue past this drops the oldest.
pub const QUEUE_CAP: usize = 20;
/// Maximum item age before it is dropped (24 hours, in milliseconds).
pub const QUEUE_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// Persistent per-peer offline queue. Mutations persist atomically.
#[derive(Debug)]
pub struct OfflineQueue {
    path: PathBuf,
    /// device-id-hex -> FIFO of buffered items (front = oldest).
    map: BTreeMap<String, VecDeque<ClipboardItem>>,
}

/// The on-disk shape (a plain map of hex id -> ordered items).
#[derive(Default, Serialize, Deserialize)]
struct Stored {
    #[serde(flatten)]
    map: BTreeMap<String, Vec<ClipboardItem>>,
}

impl OfflineQueue {
    /// Load the queue from `path`, or start empty if it does not exist.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let map = match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
            Ok(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes)?;
                stored
                    .map
                    .into_iter()
                    .map(|(k, v)| (k, VecDeque::from(v)))
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(Self { path, map })
    }

    /// Buffer `item` for `peer`, pruning stale entries and enforcing the cap,
    /// then persist. `now_ms` is the current wall clock (passed in so the age
    /// check is testable).
    pub fn enqueue(&mut self, peer: &DeviceId, item: ClipboardItem, now_ms: u64) -> Result<()> {
        let q = self.map.entry(peer.to_string()).or_default();
        prune_stale(q, now_ms);
        q.push_back(item);
        while q.len() > QUEUE_CAP {
            q.pop_front();
        }
        self.save()
    }

    /// Take and remove every (non-stale) buffered item for `peer`, in FIFO
    /// order, then persist. Returns an empty vec if nothing is queued.
    pub fn drain(&mut self, peer: &DeviceId, now_ms: u64) -> Result<Vec<ClipboardItem>> {
        let key = peer.to_string();
        let items = match self.map.remove(&key) {
            Some(mut q) => {
                prune_stale(&mut q, now_ms);
                q.into_iter().collect()
            }
            None => Vec::new(),
        };
        // Persist the removal (best effort: only if something changed).
        self.save()?;
        Ok(items)
    }

    /// Number of items currently queued for `peer` (without pruning).
    pub fn len_for(&self, peer: &DeviceId) -> usize {
        self.map.get(&peer.to_string()).map_or(0, VecDeque::len)
    }

    /// The path this queue persists to.
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
        let stored = Stored {
            map: self
                .map
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        let tmp = self.path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Drop items older than [`QUEUE_MAX_AGE_MS`] from the front/anywhere of `q`.
fn prune_stale(q: &mut VecDeque<ClipboardItem>, now_ms: u64) {
    q.retain(|item| now_ms.saturating_sub(item.ts_ms) <= QUEUE_MAX_AGE_MS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucb_core::ClipboardPayload;

    fn item(ts: u64, text: &str) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Text(text.into()),
            ts_ms: ts,
            origin: DeviceId([9; 32]),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ucb-queue-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("queue.json")
    }

    #[test]
    fn enqueue_and_drain_in_order() {
        let peer = DeviceId([1; 32]);
        let mut q = OfflineQueue::load(temp_path("order")).unwrap();
        q.enqueue(&peer, item(1000, "a"), 1000).unwrap();
        q.enqueue(&peer, item(1001, "b"), 1001).unwrap();
        q.enqueue(&peer, item(1002, "c"), 1002).unwrap();
        let drained = q.drain(&peer, 1002).unwrap();
        let texts: Vec<_> = drained
            .iter()
            .map(|i| match &i.payload {
                ClipboardPayload::Text(s) => s.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(texts, vec!["a", "b", "c"]);
        // Drained queue is now empty.
        assert!(q.drain(&peer, 1002).unwrap().is_empty());
    }

    #[test]
    fn cap_drops_oldest() {
        let peer = DeviceId([2; 32]);
        let mut q = OfflineQueue::load(temp_path("cap")).unwrap();
        for i in 0..QUEUE_CAP as u64 + 1 {
            q.enqueue(&peer, item(1000 + i, &format!("v{i}")), 1000 + i)
                .unwrap();
        }
        assert_eq!(q.len_for(&peer), QUEUE_CAP);
        let drained = q.drain(&peer, 2000).unwrap();
        // The very first item (v0) was dropped; v1 is now the oldest.
        match &drained[0].payload {
            ClipboardPayload::Text(s) => assert_eq!(s, "v1"),
            _ => unreachable!(),
        }
        assert_eq!(drained.len(), QUEUE_CAP);
    }

    #[test]
    fn stale_items_dropped() {
        let peer = DeviceId([3; 32]);
        let mut q = OfflineQueue::load(temp_path("stale")).unwrap();
        q.enqueue(&peer, item(1000, "old"), 1000).unwrap();
        // Enqueue a fresh item far in the future; the old one is now stale.
        let now = 1000 + QUEUE_MAX_AGE_MS + 1;
        q.enqueue(&peer, item(now, "new"), now).unwrap();
        let drained = q.drain(&peer, now).unwrap();
        assert_eq!(drained.len(), 1);
        match &drained[0].payload {
            ClipboardPayload::Text(s) => assert_eq!(s, "new"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn persistence_round_trip() {
        let peer = DeviceId([4; 32]);
        let path = temp_path("persist");
        {
            let mut q = OfflineQueue::load(&path).unwrap();
            q.enqueue(&peer, item(1000, "a"), 1000).unwrap();
            q.enqueue(&peer, item(1001, "b"), 1001).unwrap();
        }
        let mut reloaded = OfflineQueue::load(&path).unwrap();
        assert_eq!(reloaded.len_for(&peer), 2);
        let drained = reloaded.drain(&peer, 1001).unwrap();
        assert_eq!(drained.len(), 2);
    }
}
