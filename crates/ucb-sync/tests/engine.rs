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
use ucb_sync::{Allowlist, EngineConfig, SyncEngine, TransferEvent};

// Upper bound for `wait_for`; healthy runs return the instant the condition
// holds, so this only adds headroom for CI runners saturated by the other
// real-TCP integration tests running in parallel (a 5s bound flaked there).
const TIMEOUT: Duration = Duration::from_secs(20);
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

/// Full constructor exposing the Wave-2 knobs (history, file-size cap). Auto
/// file sync is off (the shipped default). The inbound-file directory is
/// `<allowlist parent>/received`.
async fn start_node_full(
    name: &str,
    identity: Identity,
    allowlist_path: PathBuf,
    static_peers: Vec<String>,
    history: Option<std::sync::Arc<ucb_history::History>>,
    max_file_bytes: Option<u64>,
) -> (Node, u16) {
    start_node_inner(
        name,
        identity,
        allowlist_path,
        static_peers,
        history,
        max_file_bytes,
        false,
        ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES,
    )
    .await
}

/// Like [`start_node_full`] but with automatic file sync (FILE-1) enabled and a
/// specific per-file cap.
async fn start_node_auto(
    name: &str,
    identity: Identity,
    allowlist_path: PathBuf,
    max_auto_file_bytes: u64,
) -> (Node, u16) {
    start_node_inner(
        name,
        identity,
        allowlist_path,
        Vec::new(),
        None,
        None,
        true,
        max_auto_file_bytes,
    )
    .await
}

/// The fullest constructor, exposing every engine knob including FILE-1 auto
/// file sync.
#[allow(clippy::too_many_arguments)]
async fn start_node_inner(
    name: &str,
    identity: Identity,
    allowlist_path: PathBuf,
    static_peers: Vec<String>,
    history: Option<std::sync::Arc<ucb_history::History>>,
    max_file_bytes: Option<u64>,
    auto_file_sync: bool,
    max_auto_file_bytes: u64,
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
            auto_file_sync,
            max_auto_file_bytes,
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

/// Drain a transfer-event receiver until `stop` matches (inclusive), or the
/// timeout elapses between events. Returns everything collected.
async fn collect_until(
    rx: &mut tokio::sync::broadcast::Receiver<TransferEvent>,
    stop: impl Fn(&TransferEvent) -> bool,
) -> Vec<TransferEvent> {
    let mut out = Vec::new();
    // Lagged, closed, or timed-out recv ends the loop with what we have.
    while let Ok(Ok(ev)) = tokio::time::timeout(TIMEOUT, rx.recv()).await {
        let done = stop(&ev);
        out.push(ev);
        if done {
            break;
        }
    }
    out
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
/// received dir, and B's clipboard holds the delivered file as a real OS file
/// reference (FILE-1 clipboard-pointer behavior; was path-as-text pre-FILE-1).
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

    // Subscribe to transfer events on both sides BEFORE sending so nothing is
    // missed (broadcast delivers only post-subscription events).
    let mut rx_recv = node_b.engine.subscribe_transfers();
    let mut rx_send = node_a.engine.subscribe_transfers();

    let report = node_a.engine.send_file(&src, None, None).await.unwrap();
    assert!(report.ok, "transfer should succeed: {report:?}");
    assert_eq!(report.bytes, bytes.len() as u64);

    // Receiver-side ordering: RecvStarted -> RecvProgress(>=1) -> RecvCompleted.
    let recv_events = collect_until(&mut rx_recv, |e| {
        matches!(e, TransferEvent::RecvCompleted { .. })
    })
    .await;
    let total_size = bytes.len() as u64;
    match &recv_events[0] {
        TransferEvent::RecvStarted { name, size, from, .. } => {
            assert!(name.ends_with("payload.bin"), "started name: {name}");
            assert_eq!(*size, total_size, "RecvStarted size must be the file size");
            assert_eq!(*from, dev_a, "RecvStarted must name the sender");
        }
        other => panic!("first receiver event must be RecvStarted, got {other:?}"),
    }
    let progress: Vec<(u64, u64)> = recv_events
        .iter()
        .filter_map(|e| match e {
            TransferEvent::RecvProgress { received, total, .. } => Some((*received, *total)),
            _ => None,
        })
        .collect();
    assert!(!progress.is_empty(), "expected at least one RecvProgress event");
    assert!(
        progress.iter().all(|(_, total)| *total == 3),
        "chunk total must be 3 (600KiB+123 over 256KiB chunks): {progress:?}"
    );
    assert!(
        progress.windows(2).all(|w| w[0].0 <= w[1].0),
        "RecvProgress received counts must be monotonic: {progress:?}"
    );
    match recv_events.last().unwrap() {
        TransferEvent::RecvCompleted { ok, path, .. } => {
            assert!(*ok, "RecvCompleted must be ok");
            assert!(path.ends_with("payload.bin"), "completed path: {path:?}");
        }
        other => panic!("last receiver event must be RecvCompleted, got {other:?}"),
    }

    // Sender-side ordering: SendProgress(>=1) -> SendCompleted. Progress is in
    // chunk counts (same plumbing as the CLI's SendProgress), total == 3 chunks.
    let send_events = collect_until(&mut rx_send, |e| {
        matches!(e, TransferEvent::SendCompleted { .. })
    })
    .await;
    let send_progress: Vec<(u64, u64)> = send_events
        .iter()
        .filter_map(|e| match e {
            TransferEvent::SendProgress { sent, total, .. } => Some((*sent, *total)),
            _ => None,
        })
        .collect();
    assert!(!send_progress.is_empty(), "expected at least one SendProgress event");
    assert!(
        send_progress.iter().all(|(_, total)| *total == 3),
        "SendProgress chunk total must be 3: {send_progress:?}"
    );
    assert!(
        send_progress.windows(2).all(|w| w[0].0 <= w[1].0),
        "SendProgress sent counts must be monotonic: {send_progress:?}"
    );
    match send_events.last().unwrap() {
        TransferEvent::SendCompleted { ok, name, .. } => {
            assert!(*ok, "SendCompleted must be ok");
            assert!(name.ends_with("payload.bin"), "completed name: {name}");
        }
        other => panic!("last sender event must be SendCompleted, got {other:?}"),
    }

    // B's clipboard should end up holding the received file as a file reference.
    let clip_files = wait_for(|| node_b.handle.get_files())
        .await
        .expect("B clipboard should hold the received-file reference");
    assert_eq!(clip_files.len(), 1, "expected exactly one file reference");
    let clip_path = clip_files[0].to_string_lossy().into_owned();
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

// --- FILE-1: automatic file copy/paste sync ------------------------------

/// Count regular files directly inside `dir` (0 if the dir does not exist).
fn count_files(dir: &std::path::Path) -> usize {
    if !dir.exists() {
        return 0;
    }
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .count()
}

/// FILE-1: with `auto_file_sync` enabled, copying a file on A (a Files clipboard
/// event) automatically transfers it to B. B ends up with byte-identical bytes
/// in its received dir and a real file reference on its clipboard. B placing that
/// reference on its own clipboard must NOT bounce the file back to A (echo).
#[tokio::test]
async fn auto_file_sync_end_to_end() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("autofile").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) =
        start_node_auto("A", id_a, dir_a.join("trusted.json"), ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES)
            .await;
    let (node_b, port_b) =
        start_node_auto("B", id_b, dir_b.join("trusted.json"), ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES)
            .await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    // ~300 KiB (spans multiple 256 KiB chunks).
    let bytes = patterned(300 * 1024 + 17);
    let src = dir_a.join("clip.bin");
    tokio::fs::write(&src, &bytes).await.unwrap();

    // Simulate the user copying the file in the OS file manager.
    node_a.handle.set_files(vec![src.clone()]);

    // B receives it into its received dir, byte-identical.
    let received = dir_b.join("received").join("clip.bin");
    let got = wait_for(|| std::fs::read(&received).ok()).await;
    assert_eq!(got.as_deref(), Some(bytes.as_slice()), "B did not receive identical bytes");

    // B's clipboard holds the received file as a real OS file reference.
    let clip_files = wait_for(|| node_b.handle.get_files())
        .await
        .expect("B clipboard should hold a file reference");
    assert_eq!(clip_files.len(), 1, "expected exactly one file reference");
    assert!(
        clip_files[0].ends_with("clip.bin"),
        "clipboard file reference should point at clip.bin, got {:?}",
        clip_files[0]
    );
    assert!(
        clip_files[0].to_string_lossy().contains("received"),
        "delivered file should live in the received dir, got {:?}",
        clip_files[0]
    );

    // Echo / quiescence: B writing the file to its own clipboard must not be
    // re-observed and bounced back to A. A's received dir stays empty.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(count_files(&dir_a.join("received")), 0, "file bounced back to A (echo loop)");
}

/// FILE-1: with the shipped default (`auto_file_sync` off), copying a file on A
/// starts no transfer — B receives nothing.
#[tokio::test]
async fn auto_file_sync_disabled_by_default() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("noauto").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) =
        start_node_full("A", id_a, dir_a.join("trusted.json"), vec![], None, None).await;
    let (node_b, port_b) =
        start_node_full("B", id_b, dir_b.join("trusted.json"), vec![], None, None).await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    let bytes = patterned(50 * 1024);
    let src = dir_a.join("nope.bin");
    tokio::fs::write(&src, &bytes).await.unwrap();
    node_a.handle.set_files(vec![src]);

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count_files(&dir_b.join("received")), 0, "no transfer should occur when auto off");
    assert_eq!(node_b.handle.get_files(), None, "B clipboard must be untouched");
    assert_eq!(node_b.handle.get(), None);
}

/// FILE-1: a locally-copied file larger than `max_auto_file_bytes` is skipped by
/// the sender; nothing is transferred.
#[tokio::test]
async fn auto_file_sync_skips_oversized() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("autobig").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    // A auto-syncs but caps auto files at 1 KiB.
    let (node_a, port_a) = start_node_auto("A", id_a, dir_a.join("trusted.json"), 1024).await;
    let (node_b, port_b) = start_node_auto(
        "B",
        id_b,
        dir_b.join("trusted.json"),
        ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES,
    )
    .await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    let bytes = patterned(50 * 1024); // 50 KiB > 1 KiB cap
    let src = dir_a.join("big.bin");
    tokio::fs::write(&src, &bytes).await.unwrap();
    node_a.handle.set_files(vec![src]);

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count_files(&dir_b.join("received")), 0, "oversized file must be skipped");
    assert_eq!(node_b.handle.get_files(), None);
}

/// FILE-1: a locally-copied directory is skipped (only regular files are
/// auto-sent); nothing is transferred.
#[tokio::test]
async fn auto_file_sync_skips_directory() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("autodir").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) = start_node_auto(
        "A",
        id_a,
        dir_a.join("trusted.json"),
        ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES,
    )
    .await;
    let (node_b, port_b) = start_node_auto(
        "B",
        id_b,
        dir_b.join("trusted.json"),
        ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES,
    )
    .await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    // A folder (with a file inside, to be sure nothing recurses into it).
    let folder = dir_a.join("a_folder");
    tokio::fs::create_dir_all(&folder).await.unwrap();
    tokio::fs::write(folder.join("inner.bin"), b"inner").await.unwrap();
    node_a.handle.set_files(vec![folder]);

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count_files(&dir_b.join("received")), 0, "directory must be skipped");
    assert_eq!(node_b.handle.get_files(), None);
}

// --- HIST-4: cross-device star sync --------------------------------------

/// HIST-4: starring a history entry on A (and broadcasting it) stars the
/// matching content on B; unstarring propagates the same way; and because a
/// received `Star` is never re-broadcast, the group stays quiescent (no loop).
#[tokio::test]
async fn star_syncs_a_to_b_and_does_not_loop() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("star").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());

    let hist_a = Arc::new(
        History::open(&dir_a.join("history.db"), &FileKeyStore::new(dir_a.join("hkeys"))).unwrap(),
    );
    let hist_b = Arc::new(
        History::open(&dir_b.join("history.db"), &FileKeyStore::new(dir_b.join("hkeys"))).unwrap(),
    );

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

    // A copies content that syncs to B, so both stores hold a row for it.
    node_a.handle.set("star-target");
    let got = wait_for(|| node_b.handle.get().filter(|s| s == "star-target").map(|_| ())).await;
    assert!(got.is_some(), "clip did not sync A -> B");

    // Both stores must have recorded the clip before we star it.
    let by_text = |hist: &History| -> Option<ucb_history::HistoryEntry> {
        hist.list(HistoryQuery {
            text_search: Some("star-target".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .next()
    };
    let a_entry = wait_for(|| by_text(&hist_a)).await.expect("A recorded the clip");
    wait_for(|| by_text(&hist_b)).await.expect("B recorded the clip");

    // Star on A (local) then broadcast by content hash.
    assert!(hist_a.set_starred(a_entry.id, true).unwrap());
    let hash = hist_a.starred_hash_of(a_entry.id).unwrap().expect("hash of A's row");
    node_a.engine.broadcast_star(hash, true);

    // B's matching row becomes starred.
    let b_starred = wait_for(|| by_text(&hist_b).filter(|e| e.starred).map(|_| ())).await;
    assert!(b_starred.is_some(), "star did not propagate A -> B");

    // Unstar on A + broadcast -> B unstars too.
    assert!(hist_a.set_starred(a_entry.id, false).unwrap());
    node_a.engine.broadcast_star(hash, false);
    let b_unstarred = wait_for(|| by_text(&hist_b).filter(|e| !e.starred).map(|_| ())).await;
    assert!(b_unstarred.is_some(), "unstar did not propagate A -> B");

    // Quiescence / no-loop: B never re-broadcasts a received star, so A's row
    // (unstarred by the caller above only via its own set) must stay stable and
    // B must not flip back to starred.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!by_text(&hist_b).unwrap().starred, "B star flipped back (loop?)");
    // A was never sent a Star by B, so A's local state is exactly what we set.
    assert!(!by_text(&hist_a).unwrap().starred, "A star changed unexpectedly");
}

// --- Live trust (GUI wave): trust_peer -----------------------------------

/// `trust_peer` makes a not-yet-trusted peer sync *without restarting* either
/// engine: with both engines already running and discovery aware of each other
/// (but neither trusted), calling `trust_peer` on both establishes a session and
/// a clip flows A -> B.
#[tokio::test]
async fn trust_peer_connects_live_without_restart() {
    use ucb_core::DeviceInfo;

    let dir_a = temp_dir("trust-live-a");
    let dir_b = temp_dir("trust-live-b");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_b = Identity::load_or_generate(&FileKeyStore::new(dir_b.join("keys"))).unwrap();
    let (dev_a, pk_a) = (id_a.device_id(), id_a.public_key());
    let (dev_b, pk_b) = (id_b.device_id(), id_b.public_key());

    // Neither side trusts the other yet (empty allowlists).
    let al_a = dir_a.join("trusted.json");
    let al_b = dir_b.join("trusted.json");
    let (node_a, port_a) = start_node("A", id_a, al_a).await;
    let (node_b, port_b) = start_node("B", id_b, al_b).await;

    // Discovery sees both peers, but since neither is trusted no connector starts
    // and no session forms.
    node_a.disc_tx.send(peer_event(dev_b, "B", port_b)).await.unwrap();
    node_b.disc_tx.send(peer_event(dev_a, "A", port_a)).await.unwrap();

    // Give discovery a moment to populate the peer maps, then confirm still
    // disconnected (no trust yet).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !node_a.engine.status().iter().any(|p| p.connected),
        "A must not be connected before trust"
    );

    // Trust each other live — no restart.
    node_a
        .engine
        .trust_peer(
            DeviceInfo { id: dev_b, name: "B".into(), platform: Platform::Linux },
            pk_b,
        )
        .unwrap();
    node_b
        .engine
        .trust_peer(
            DeviceInfo { id: dev_a, name: "A".into(), platform: Platform::Linux },
            pk_a,
        )
        .unwrap();

    // A session establishes on both sides purely from the eager dial.
    let connected = wait_for(|| {
        let a_up = node_a.engine.status().iter().any(|p| p.connected);
        let b_up = node_b.engine.status().iter().any(|p| p.connected);
        (a_up && b_up).then_some(())
    })
    .await;
    assert!(connected.is_some(), "trust_peer did not connect the engines live");

    // And a clip flows over the freshly-formed session.
    node_a.handle.set("live-trust");
    let got = wait_for(|| node_b.handle.get().filter(|s| s == "live-trust").map(|_| ())).await;
    assert!(got.is_some(), "clip did not sync after live trust_peer");
}

// --- Additive engine surface: discovered() -------------------------------

/// `discovered()` lists every peer mDNS has seen — an untrusted `Found` peer
/// with `trusted:false`, and a trusted peer with a live session as
/// `connected:true`.
#[tokio::test]
async fn discovered_lists_untrusted_and_trusted_connected_peers() {
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("disc").await;
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) = start_node("A", id_a, dir_a.join("trusted.json")).await;
    let (node_b, port_b) = start_node("B", id_b, dir_b.join("trusted.json")).await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    // Inject an untrusted discovered peer X into A (never in A's allowlist).
    let dev_x = DeviceId([0x9A; 32]);
    node_a
        .disc_tx
        .send(peer_event(dev_x, "X-device", 40404))
        .await
        .unwrap();

    let ok = wait_for(|| {
        let d = node_a.engine.discovered();
        let x = d.iter().find(|p| p.device_id == dev_x);
        let b = d.iter().find(|p| p.device_id == dev_b);
        match (x, b) {
            (Some(x), Some(b))
                if !x.trusted
                    && !x.connected
                    && x.name == "X-device"
                    && b.trusted
                    && b.connected =>
            {
                Some(())
            }
            _ => None,
        }
    })
    .await;
    assert!(
        ok.is_some(),
        "discovered() must show untrusted X and trusted-connected B: {:?}",
        node_a.engine.discovered()
    );
}
