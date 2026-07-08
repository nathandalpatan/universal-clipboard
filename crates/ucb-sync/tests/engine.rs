//! Full-engine integration tests: two engines wired together in-process over
//! real loopback TCP, with mock clipboards and hand-crafted discovery events.
//!
//! No OS keychain (FileKeyStore in temp dirs), no real clipboard (MockClipboard)
//! and no real mDNS (we build the PeerEvent channels ourselves).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use ucb_clipboard::{ClipboardService, MockClipboard, MockClipboardHandle};
use ucb_core::{DeviceId, Platform};
use ucb_crypto::{FileKeyStore, Identity};
use ucb_discovery::{Peer, PeerEvent};
use ucb_history::{History, HistoryQuery};
use ucb_sync::{Allowlist, EngineConfig, SyncEngine};

const TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

/// A unique temp directory for a test's on-disk state.
fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ucb-sync-test-{}-{}-{}-{}",
        tag,
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn loopback() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// Everything needed to keep one running engine (and its inputs) alive.
struct Node {
    engine: SyncEngine,
    handle: MockClipboardHandle,
    disc_tx: mpsc::Sender<PeerEvent>,
}

/// Build a fully wired engine bound to an ephemeral loopback port. Returns the
/// node plus the port it is listening on.
async fn start_node(name: &str, identity: Identity, allowlist_path: PathBuf) -> (Node, u16) {
    start_node_with_static(name, identity, allowlist_path, Vec::new()).await
}

/// Like [`start_node`] but with configured static peers (DISC-3).
async fn start_node_with_static(
    name: &str,
    identity: Identity,
    allowlist_path: PathBuf,
    static_peers: Vec<String>,
) -> (Node, u16) {
    start_node_full(name, identity, allowlist_path, static_peers, None, None).await
}

/// Full constructor exposing the Wave-2 knobs (history, file-size cap). The
/// inbound-file directory is `<allowlist parent>/received`.
async fn start_node_full(
    name: &str,
    identity: Identity,
    allowlist_path: PathBuf,
    static_peers: Vec<String>,
    history: Option<std::sync::Arc<ucb_history::History>>,
    max_file_bytes: Option<u64>,
) -> (Node, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (mock, handle) = MockClipboard::new();
    let (writer, clip_rx) = ClipboardService::start(mock, POLL);
    let (disc_tx, disc_rx) = mpsc::channel(16);

    let received_dir = allowlist_path
        .parent()
        .unwrap()
        .join("received");

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path,
            device_name: name.to_string(),
            platform: Platform::Linux,
            static_peers,
            history,
            received_dir,
            max_file_bytes,
        },
        listener,
        writer,
        clip_rx,
        disc_rx,
    )
    .await
    .unwrap();

    (
        Node {
            engine,
            handle,
            disc_tx,
        },
        port,
    )
}

fn peer_event(id: ucb_core::DeviceId, name: &str, port: u16) -> PeerEvent {
    PeerEvent::Found(Peer {
        device_id: id,
        name: name.to_string(),
        addrs: vec![loopback()],
        port,
        version: ucb_core::PROTOCOL_VERSION,
    })
}

/// Poll `f` until it returns `Some`, or the timeout expires.
async fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// SYNC-1: a copy on A appears on B, and there is no echo loop.
#[tokio::test]
async fn clip_syncs_a_to_b_without_echo() {
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());

    // Trust each other.
    let al_a = dir_a.join("trusted.json");
    let al_b = dir_b.join("trusted.json");
    Allowlist::load(&al_a)
        .unwrap()
        .add(dev_b, "B", &pk_b, now_ms())
        .unwrap();
    Allowlist::load(&al_b)
        .unwrap()
        .add(dev_a, "A", &pk_a, now_ms())
        .unwrap();

    let (node_a, port_a) = start_node("A", id_a, al_a).await;
    let (node_b, port_b) = start_node("B", id_b, al_b).await;

    // Cross-advertise so whichever side has the smaller id dials the other.
    node_a.disc_tx.send(peer_event(dev_b, "B", port_b)).await.unwrap();
    node_b.disc_tx.send(peer_event(dev_a, "A", port_a)).await.unwrap();

    // Wait for the session to come up on both sides.
    let connected = wait_for(|| {
        let a_up = node_a.engine.status().iter().any(|p| p.connected);
        let b_up = node_b.engine.status().iter().any(|p| p.connected);
        (a_up && b_up).then_some(())
    })
    .await;
    assert!(connected.is_some(), "engines did not connect within timeout");

    // Copy on A -> should appear on B.
    node_a.handle.set("hello");
    let got = wait_for(|| {
        node_b
            .handle
            .get()
            .filter(|s| s == "hello")
            .map(|_| ())
    })
    .await;
    assert!(got.is_some(), "clip did not sync A -> B");

    // Echo check: B must not re-broadcast back and A must stay stable.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node_a.handle.get().as_deref(), Some("hello"), "A clipboard changed (echo loop?)");
    assert_eq!(node_b.handle.get().as_deref(), Some("hello"));
}

/// TEST-3: an untrusted peer that connects to A is dropped; A is unaffected.
#[tokio::test]
async fn untrusted_peer_is_rejected() {
    let dir_a = temp_dir("trust-a");
    let dir_c = temp_dir("trust-c");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_c = Identity::load_or_generate(&FileKeyStore::new(dir_c.join("keys"))).unwrap();

    // A trusts nobody. (Empty allowlist.)
    let al_a = dir_a.join("trusted.json");
    let (node_a, port_a) = start_node("A", id_a, al_a).await;

    // C connects directly with the crypto handshake and tries to talk.
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port_a))
        .await
        .unwrap();
    let mut chan = ucb_crypto::handshake_initiator(stream, &id_c)
        .await
        .unwrap();

    // A completes the handshake but then drops us (untrusted). Our Hello send
    // may buffer, but the next recv must fail because A closed the connection.
    use ucb_core::{DeviceInfo, WireMessage, PROTOCOL_VERSION};
    let _ = chan
        .send(&WireMessage::Hello {
            version: PROTOCOL_VERSION,
            device: DeviceInfo {
                id: id_c.device_id(),
                name: "C".into(),
                platform: Platform::Linux,
            },
        })
        .await;

    let result = tokio::time::timeout(TIMEOUT, chan.recv()).await;
    match result {
        Ok(Err(_)) => {} // connection closed by A: expected
        Ok(Ok(msg)) => panic!("untrusted peer should have been dropped, got {msg:?}"),
        Err(_) => panic!("timed out; A neither responded nor closed"),
    }

    // A's clipboard is untouched.
    assert_eq!(node_a.handle.get(), None);
}

/// PAIR-5: adding a third remote device exceeds the cap.
#[tokio::test]
async fn device_cap_rejects_third_remote() {
    let dir = temp_dir("cap");
    let path = dir.join("trusted.json");
    let mut al = Allowlist::load(&path).unwrap();
    al.add(ucb_core::DeviceId([1; 32]), "one", &[1; 32], now_ms())
        .unwrap();
    al.add(ucb_core::DeviceId([2; 32]), "two", &[2; 32], now_ms())
        .unwrap();
    let err = al
        .add(ucb_core::DeviceId([3; 32]), "three", &[3; 32], now_ms())
        .unwrap_err();
    assert!(matches!(err, ucb_sync::Error::DeviceLimit(_)), "expected DeviceLimit, got {err:?}");

    // Re-adding an existing device is allowed (update, not a new slot).
    al.add(ucb_core::DeviceId([1; 32]), "one-renamed", &[1; 32], now_ms())
        .unwrap();
}

/// PAIR-4/6: allowlist persists across reloads and revoke removes an entry.
#[tokio::test]
async fn allowlist_persistence_and_revoke() {
    let dir = temp_dir("persist");
    let path = dir.join("trusted.json");
    let id = ucb_core::DeviceId([7; 32]);

    {
        let mut al = Allowlist::load(&path).unwrap();
        al.add(id, "Phone", &[7; 32], now_ms()).unwrap();
    }

    // Round-trip: a fresh load sees the entry.
    let mut reloaded = Allowlist::load(&path).unwrap();
    assert!(reloaded.is_trusted(&id));
    assert_eq!(reloaded.pubkey_of(&id), Some([7u8; 32]));
    assert_eq!(reloaded.name_of(&id).as_deref(), Some("Phone"));

    // Prefix resolution (used by `revoke`).
    let resolved = reloaded.resolve_prefix(&id.short()).unwrap();
    assert_eq!(resolved, id);

    // Revoke and confirm it is gone after another reload.
    assert!(reloaded.remove(&id));
    assert!(!reloaded.is_trusted(&id));
    let after = Allowlist::load(&path).unwrap();
    assert!(!after.is_trusted(&id));
}

// --- PAIR-7 revocation propagation ---------------------------------------

/// PAIR-7 (handler level): `revoke` removes from the allowlist, records a
/// tombstone, is idempotent (so remote `Revoke` never loops), blocks re-adding,
/// and `forget` clears the tombstone.
#[tokio::test]
async fn revoke_tombstones_blocks_readd_and_forget_clears() {
    let dir = temp_dir("revoke-handler");
    let path = dir.join("trusted.json");
    let id = DeviceId([5; 32]);

    let mut al = Allowlist::load(&path).unwrap();
    al.add(id, "Victim", &[5; 32], now_ms()).unwrap();
    assert!(al.is_trusted(&id));

    // Revoke: removed from allowlist + tombstoned; first call is "newly true".
    assert!(al.revoke(id).unwrap(), "first revoke should be newly-applied");
    assert!(!al.is_trusted(&id));
    assert!(al.is_tombstoned(&id));

    // Idempotent: re-revoking a tombstoned device is a no-op (no loop).
    assert!(!al.revoke(id).unwrap(), "second revoke must be a no-op");

    // Re-adding a tombstoned device fails.
    let err = al.add(id, "Victim", &[5; 32], now_ms()).unwrap_err();
    assert!(matches!(err, ucb_sync::Error::Tombstoned(_)), "got {err:?}");

    // Tombstone persists across reload; revoked.json is written next to it.
    assert!(dir.join("revoked.json").exists());
    let mut reloaded = Allowlist::load(&path).unwrap();
    assert!(reloaded.is_tombstoned(&id));

    // forget clears the tombstone; re-add now succeeds.
    assert!(reloaded.forget(&id).unwrap());
    assert!(!reloaded.is_tombstoned(&id));
    reloaded.add(id, "Victim", &[5; 32], now_ms()).unwrap();
    assert!(reloaded.is_trusted(&id));
}

/// PAIR-7 (engine level, three-device story): A has revoked device X. When A and
/// B connect, A broadcasts `Revoke{X}` at session start; B must remove X from
/// its allowlist and tombstone it — even though X was never online.
#[tokio::test]
async fn revoke_propagates_to_third_device_on_connect() {
    let dir_a = temp_dir("rev-a");
    let dir_b = temp_dir("rev-b");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());

    // X is a third (offline) device both A and B trust.
    let dev_x = DeviceId([0xEE; 32]);
    let pk_x = [0xEE; 32];

    let al_a = dir_a.join("trusted.json");
    let al_b = dir_b.join("trusted.json");
    {
        let mut a = Allowlist::load(&al_a).unwrap();
        a.add(dev_b, "B", &pk_b, now_ms()).unwrap();
        a.add(dev_x, "X", &pk_x, now_ms()).unwrap();
        // A revokes X locally *before* starting.
        assert!(a.revoke(dev_x).unwrap());
    }
    {
        let mut b = Allowlist::load(&al_b).unwrap();
        b.add(dev_a, "A", &pk_a, now_ms()).unwrap();
        b.add(dev_x, "X", &pk_x, now_ms()).unwrap();
    }

    let (node_a, port_a) = start_node("A", id_a, al_a).await;
    let (node_b, port_b) = start_node("B", id_b, al_b.clone()).await;

    node_a.disc_tx.send(peer_event(dev_b, "B", port_b)).await.unwrap();
    node_b.disc_tx.send(peer_event(dev_a, "A", port_a)).await.unwrap();

    // Wait until B has removed X and tombstoned it (learned via A's Revoke).
    let propagated = wait_for(|| {
        let b = Allowlist::load(&al_b).unwrap();
        (!b.is_trusted(&dev_x) && b.is_tombstoned(&dev_x)).then_some(())
    })
    .await;
    assert!(propagated.is_some(), "revocation of X did not propagate to B");

    // B still trusts A (the messenger) — only X was revoked.
    assert!(Allowlist::load(&al_b).unwrap().is_trusted(&dev_a));
}

// --- SYNC-5 offline queue ------------------------------------------------

/// SYNC-5/UX-4: clips copied on A while B is offline are buffered, then drained
/// in order when B connects; B ends up with the last item.
#[tokio::test]
async fn offline_queue_drains_on_connect_in_order() {
    let dir_a = temp_dir("q-a");
    let dir_b = temp_dir("q-b");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());

    let al_a = dir_a.join("trusted.json");
    let al_b = dir_b.join("trusted.json");
    Allowlist::load(&al_a).unwrap().add(dev_b, "B", &pk_b, now_ms()).unwrap();
    Allowlist::load(&al_b).unwrap().add(dev_a, "A", &pk_a, now_ms()).unwrap();

    // Start A only. B is offline, so copies on A are buffered for B.
    let (node_a, port_a) = start_node("A", id_a, al_a).await;

    // Space copies beyond the poll interval so each is observed and enqueued.
    for text in ["q1", "q2", "q3"] {
        node_a.handle.set(text);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // Wait for the queue file to reflect the last buffered item.
    let queue_file = dir_a.join("queue.json");
    let queued = wait_for(|| {
        std::fs::read_to_string(&queue_file)
            .ok()
            .filter(|s| s.contains("q3"))
            .map(|_| ())
    })
    .await;
    assert!(queued.is_some(), "clips were not buffered for offline B");

    // Bring B up and connect; A drains the queue to B in order.
    let (node_b, port_b) = start_node("B", id_b, al_b).await;
    node_a.disc_tx.send(peer_event(dev_b, "B", port_b)).await.unwrap();
    node_b.disc_tx.send(peer_event(dev_a, "A", port_a)).await.unwrap();

    // B's clipboard should end on the LAST buffered item (conflict resolution
    // keeps the newest; drained in FIFO order).
    let got = wait_for(|| node_b.handle.get().filter(|s| s == "q3").map(|_| ())).await;
    assert!(got.is_some(), "offline queue did not drain last item to B");
}

// --- DISC-3 static peers -------------------------------------------------

/// DISC-3: an engine dials a configured static peer with no discovery event at
/// all, and clipboard sync works over that connection.
#[tokio::test]
async fn static_peer_is_dialed_without_discovery() {
    let dir_a = temp_dir("static-a");
    let dir_b = temp_dir("static-b");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());

    let al_a = dir_a.join("trusted.json");
    let al_b = dir_b.join("trusted.json");
    Allowlist::load(&al_a).unwrap().add(dev_b, "B", &pk_b, now_ms()).unwrap();
    Allowlist::load(&al_b).unwrap().add(dev_a, "A", &pk_a, now_ms()).unwrap();

    // Start B first so its port is listening, then start A pointed at it via a
    // static peer. No PeerEvent is ever sent on either side.
    let (node_b, port_b) = start_node("B", id_b, al_b).await;
    let (node_a, _port_a) = start_node_with_static(
        "A",
        id_a,
        al_a,
        vec![format!("127.0.0.1:{port_b}")],
    )
    .await;

    // Session comes up purely from the static-peer connector.
    let connected = wait_for(|| {
        let a_up = node_a.engine.status().iter().any(|p| p.connected);
        let b_up = node_b.engine.status().iter().any(|p| p.connected);
        (a_up && b_up).then_some(())
    })
    .await;
    assert!(connected.is_some(), "static peer was not dialed / did not connect");

    // And clips flow over it.
    node_a.handle.set("via-static");
    let got = wait_for(|| node_b.handle.get().filter(|s| s == "via-static").map(|_| ())).await;
    assert!(got.is_some(), "clip did not sync over the static-peer connection");
}

// --- Wave 2: file transfer + history -------------------------------------

/// Create two mutually-trusted identities with their allowlists populated.
/// Returns each temp dir plus its identity.
async fn trusted_pair(tag: &str) -> (PathBuf, PathBuf, Identity, Identity) {
    let dir_a = temp_dir(&format!("{tag}-a"));
    let dir_b = temp_dir(&format!("{tag}-b"));
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());
    Allowlist::load(dir_a.join("trusted.json"))
        .unwrap()
        .add(dev_b, "B", &pk_b, now_ms())
        .unwrap();
    Allowlist::load(dir_b.join("trusted.json"))
        .unwrap()
        .add(dev_a, "A", &pk_a, now_ms())
        .unwrap();
    (dir_a, dir_b, id_a, id_b)
}

/// Cross-advertise two nodes and wait until both report a live session.
async fn link(node_a: &Node, port_a: u16, dev_a: DeviceId, node_b: &Node, port_b: u16, dev_b: DeviceId) {
    node_a.disc_tx.send(peer_event(dev_b, "B", port_b)).await.unwrap();
    node_b.disc_tx.send(peer_event(dev_a, "A", port_a)).await.unwrap();
    let connected = wait_for(|| {
        let a_up = node_a.engine.status().iter().any(|p| p.connected);
        let b_up = node_b.engine.status().iter().any(|p| p.connected);
        (a_up && b_up).then_some(())
    })
    .await;
    assert!(connected.is_some(), "engines did not connect within timeout");
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// FILE-1/4/6: a ~600 KiB file sent A -> B arrives byte-identical in B's
/// received dir, and B's clipboard holds the delivered file's path (the MVP
/// clipboard-pointer behavior).
#[tokio::test]
async fn file_transfer_end_to_end() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("file").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) =
        start_node_full("A", id_a, dir_a.join("trusted.json"), vec![], None, None).await;
    let (node_b, port_b) =
        start_node_full("B", id_b, dir_b.join("trusted.json"), vec![], None, None).await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    // ~600 KiB (not a chunk multiple) so the transfer spans multiple chunks.
    let bytes = patterned(600 * 1024 + 123);
    let src = dir_a.join("payload.bin");
    tokio::fs::write(&src, &bytes).await.unwrap();

    let report = node_a.engine.send_file(&src, None, None).await.unwrap();
    assert!(report.ok, "transfer should succeed: {report:?}");
    assert_eq!(report.bytes, bytes.len() as u64);

    // B's clipboard should end up holding the received file's path.
    let clip_path = wait_for(|| node_b.handle.get())
        .await
        .expect("B clipboard should hold the received-file path");
    assert!(
        clip_path.ends_with("payload.bin"),
        "clipboard should hold the file path, got {clip_path}"
    );
    assert!(
        clip_path.contains("received"),
        "delivered file should live in the received dir, got {clip_path}"
    );

    // The pointed-to file must be byte-identical to the source.
    let received = std::fs::read(&clip_path).unwrap();
    assert_eq!(received, bytes, "received file must be byte-identical");

    // And it must physically be under B's received dir.
    let received_dir = dir_b.join("received");
    assert!(received_dir.join("payload.bin").exists());
}

/// FILE-6 policy: an offer larger than the receiver's `max_file_bytes` is
/// rejected with `FileReject`; the sender surfaces the rejection and no file
/// lands in the received dir.
#[tokio::test]
async fn oversized_offer_is_rejected() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("reject").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) =
        start_node_full("A", id_a, dir_a.join("trusted.json"), vec![], None, None).await;
    // B caps inbound files at 1 KiB.
    let (node_b, port_b) =
        start_node_full("B", id_b, dir_b.join("trusted.json"), vec![], None, Some(1024)).await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    // A 50 KiB file exceeds B's cap.
    let bytes = patterned(50 * 1024);
    let src = dir_a.join("big.bin");
    tokio::fs::write(&src, &bytes).await.unwrap();

    let report = node_a.engine.send_file(&src, None, None).await.unwrap();
    assert!(!report.ok, "oversized transfer must be rejected: {report:?}");
    assert!(
        report.detail.to_lowercase().contains("too large"),
        "rejection detail should mention the size limit, got {:?}",
        report.detail
    );

    // Nothing should have been written into B's received dir.
    let received_dir = dir_b.join("received");
    if received_dir.exists() {
        let leftovers: Vec<_> = std::fs::read_dir(&received_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != std::ffi::OsStr::new("."))
            .collect();
        assert!(leftovers.is_empty(), "received dir should be empty, has {leftovers:?}");
    }
    // And B's clipboard must be untouched.
    assert_eq!(node_b.handle.get(), None, "B clipboard must not change on reject");
}

/// HIST-1/3: a clip synced A -> B is recorded in *both* engines' history with
/// the originating device as the origin.
#[tokio::test]
async fn history_recorded_on_both_sides() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("hist").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());

    let hist_a = Arc::new(History::open(&dir_a.join("history.db"), &FileKeyStore::new(dir_a.join("hkeys"))).unwrap());
    let hist_b = Arc::new(History::open(&dir_b.join("history.db"), &FileKeyStore::new(dir_b.join("hkeys"))).unwrap());

    let (node_a, port_a) = start_node_full(
        "A",
        id_a,
        dir_a.join("trusted.json"),
        vec![],
        Some(hist_a.clone()),
        None,
    )
    .await;
    let (node_b, port_b) = start_node_full(
        "B",
        id_b,
        dir_b.join("trusted.json"),
        vec![],
        Some(hist_b.clone()),
        None,
    )
    .await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    node_a.handle.set("shared-clip");
    // Wait until B applies it to its clipboard.
    let got = wait_for(|| node_b.handle.get().filter(|s| s == "shared-clip").map(|_| ())).await;
    assert!(got.is_some(), "clip did not sync A -> B");

    let find = |hist: &History| -> Option<ucb_history::HistoryEntry> {
        hist.list(HistoryQuery {
            text_search: Some("shared-clip".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .next()
    };

    // A recorded its own local copy; origin is A.
    let a_entry = wait_for(|| find(&hist_a)).await.expect("A should record the clip");
    assert_eq!(a_entry.content.as_deref(), Some("shared-clip"));
    assert_eq!(a_entry.origin_id, dev_a.to_string(), "A's record origin must be A");

    // B recorded the applied remote clip; origin is still A (the producer).
    let b_entry = wait_for(|| find(&hist_b)).await.expect("B should record the clip");
    assert_eq!(b_entry.content.as_deref(), Some("shared-clip"));
    assert_eq!(b_entry.origin_id, dev_a.to_string(), "B's record origin must be A");
    assert_eq!(b_entry.origin_name, "A", "B records the sender's display name");
}
