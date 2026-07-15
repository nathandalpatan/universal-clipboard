//! TEST-3: the four canonical named test cases from the backlog, each an
//! explicitly-named `#[test]` so the scenario shows up by name in the test
//! output:
//!
//!   * `unpaired_device_rejection`      — an untrusted handshake is dropped.
//!   * `transfer_resume_after_interrupt`— a file transfer interrupted mid-flight
//!     resumes from the last flushed chunk (public `ucb-files` API only).
//!   * `conflict_resolution_convergence`— two clips with the same timestamp and
//!     different origins resolve to the *same* winner on both sides.
//!   * `clock_skew_rejection`           — a clip whose `ts_ms` is more than two
//!     minutes off is not applied, yet the session survives.
//!
//! These mirror the setup in `engine.rs`; the shared helpers are duplicated here
//! (each `tests/*.rs` compiles as its own crate, so they cannot be imported)
//! but kept intentionally thin.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use ucb_clipboard::{ClipboardService, MockClipboard, MockClipboardHandle};
use ucb_core::{
    ClipboardItem, ClipboardPayload, DeviceId, DeviceInfo, Platform, WireMessage,
    FILE_CHUNK_BYTES, PROTOCOL_VERSION,
};
use ucb_crypto::{FileKeyStore, Identity};
use ucb_discovery::{Peer, PeerEvent};
use ucb_files::{RecvProgress, RecvTransfer, SendAction, SendTransfer};
use ucb_sync::{Allowlist, EngineConfig, SyncEngine};

const TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

// --- shared helpers (thin copies of engine.rs's) -------------------------

fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ucb-named-{}-{}-{}-{}",
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

struct Node {
    engine: SyncEngine,
    handle: MockClipboardHandle,
    disc_tx: mpsc::Sender<PeerEvent>,
}

/// Build a fully wired engine on an ephemeral loopback port (auto file sync off).
async fn start_node(name: &str, identity: Identity, allowlist_path: PathBuf) -> (Node, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (mock, handle) = MockClipboard::new();
    let (writer, clip_rx) = ClipboardService::start(mock, POLL);
    let (disc_tx, disc_rx) = mpsc::channel(16);
    let received_dir = allowlist_path.parent().unwrap().join("received");

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path,
            device_name: name.to_string(),
            platform: Platform::Linux,
            static_peers: Vec::new(),
            history: None,
            received_dir,
            max_file_bytes: None,
            auto_file_sync: false,
            max_auto_file_bytes: ucb_sync::DEFAULT_MAX_AUTO_FILE_BYTES,
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

fn peer_event(id: DeviceId, name: &str, port: u16) -> PeerEvent {
    PeerEvent::Found(Peer {
        device_id: id,
        name: name.to_string(),
        addrs: vec![loopback()],
        port,
        version: PROTOCOL_VERSION,
    })
}

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

/// Two mutually-trusted identities, allowlists populated. Returns temp dirs and
/// identities.
fn trusted_pair(tag: &str) -> (PathBuf, PathBuf, Identity, Identity) {
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

// --- CASE 1: unpaired_device_rejection -----------------------------------

/// An untrusted device completes the Noise handshake but is *not* in the
/// allowlist, so the engine drops the connection right after: our next `recv`
/// fails, and the engine's clipboard is untouched. (SEC/PAIR: no clip flows to
/// or from an unpaired peer.)
#[tokio::test]
async fn unpaired_device_rejection() {
    let dir_a = temp_dir("unpaired-a");
    let dir_c = temp_dir("unpaired-c");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_c = Identity::load_or_generate(&FileKeyStore::new(dir_c.join("keys"))).unwrap();

    // A trusts nobody.
    let (node_a, port_a) = start_node("A", id_a, dir_a.join("trusted.json")).await;

    // C dials A and completes the handshake.
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port_a))
        .await
        .unwrap();
    let mut chan = ucb_crypto::handshake_initiator(stream, &id_c).await.unwrap();

    // C's Hello may buffer, but A (finding C untrusted) drops the socket, so the
    // next recv must error rather than yield a message.
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

    match tokio::time::timeout(TIMEOUT, chan.recv()).await {
        Ok(Err(_)) => {} // A closed the connection: expected.
        Ok(Ok(msg)) => panic!("unpaired peer should have been dropped, got {msg:?}"),
        Err(_) => panic!("timed out; A neither responded nor closed"),
    }

    // A's clipboard never changed.
    assert_eq!(node_a.handle.get(), None);
}

// --- CASE 2: transfer_resume_after_interrupt -----------------------------

fn offer_chunk_count(msg: &WireMessage) -> u64 {
    match msg {
        WireMessage::FileOffer { chunk_count, .. } => *chunk_count,
        other => panic!("expected FileOffer, got {other:?}"),
    }
}

/// A 20-chunk transfer is interrupted after 16 chunks (the flush boundary): the
/// receiver keeps its `.part` + sidecar on disk. A fresh offer for the same file
/// resumes at chunk 16 — earlier chunks are not re-sent — and the delivered file
/// is byte-identical. Driven purely through the public `ucb-files` state machines
/// (FILE-5), no engines needed.
#[tokio::test]
async fn transfer_resume_after_interrupt() {
    let dir = temp_dir("resume");
    let src = dir.join("payload.bin");
    let dest = dir.join("dest");
    // 20 chunks so the receiver flushes its sidecar at chunk 16 (FLUSH_EVERY).
    let bytes = patterned(FILE_CHUNK_BYTES * 20);
    tokio::fs::write(&src, &bytes).await.unwrap();

    // First attempt: deliver exactly 16 chunks, then "crash" (drop the receiver
    // with its part + sidecar intact).
    let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
    assert_eq!(offer_chunk_count(&offer), 20);
    let transfer_id = send.transfer_id();
    {
        let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
        assert_eq!(send.on_message(accept), SendAction::Accepted { resume_from: 0 });
        for _ in 0..16 {
            match send.next_chunk().await.unwrap().unwrap() {
                WireMessage::FileChunk { index, data, .. } => {
                    recv.on_chunk(index, &data.0).await.unwrap();
                }
                other => panic!("expected FileChunk, got {other:?}"),
            }
        }
        // on_chunk auto-flushes the sidecar at the 16-chunk boundary.
        assert_eq!(recv.progress(), (16, 20));
        drop(recv);
    }
    assert!(
        dest.join(format!("{transfer_id}.part")).exists(),
        "interrupted transfer must leave a .part file"
    );

    // Second attempt: a fresh offer for the same file must resume at 16.
    let (mut send2, offer2) = SendTransfer::offer(&src).await.unwrap();
    let (mut recv2, accept2) = RecvTransfer::on_offer(offer2, &dest).await.unwrap();
    match &accept2 {
        WireMessage::FileAccept { resume_from, .. } => {
            assert_eq!(*resume_from, 16, "receiver must ask to resume from chunk 16")
        }
        other => panic!("expected FileAccept, got {other:?}"),
    }
    assert_eq!(recv2.resume_from(), 16);
    assert_eq!(
        send2.on_message(accept2),
        SendAction::Accepted { resume_from: 16 }
    );

    // The sender must not re-emit any chunk below 16; drive to completion.
    let mut first_index = None;
    let mut delivered = None;
    loop {
        match send2.next_chunk().await.unwrap() {
            Some(WireMessage::FileChunk { index, data, .. }) => {
                first_index.get_or_insert(index);
                if let RecvProgress::Completed { path } =
                    recv2.on_chunk(index, &data.0).await.unwrap()
                {
                    delivered = Some(path);
                }
            }
            Some(other) => panic!("unexpected message: {other:?}"),
            None => break,
        }
    }
    assert_eq!(first_index, Some(16), "resume must start at chunk 16, not re-send earlier chunks");
    let path = delivered.expect("transfer should complete after resume");
    let out = tokio::fs::read(&path).await.unwrap();
    assert_eq!(out, bytes, "resumed file must be byte-identical to the source");
}

// --- CASE 3: conflict_resolution_convergence -----------------------------

/// SYNC-3. Two properties in one named case:
///  1. The conflict rule is a deterministic total order: two items with the
///     *same* timestamp but different origins pick the same winner regardless of
///     which side evaluates it (so all devices converge on one winner).
///  2. End-to-end, two connected engines that each copy different content
///     converge on a single shared clipboard value.
#[tokio::test]
async fn conflict_resolution_convergence() {
    // (1) Same ts, different origins — the winner is identical from either side.
    let ts = 1_700_000_000_000;
    let item_lo = ClipboardItem {
        payload: ClipboardPayload::Text("from-lo".into()),
        ts_ms: ts,
        origin: DeviceId([0x11; 32]),
    };
    let item_hi = ClipboardItem {
        payload: ClipboardPayload::Text("from-hi".into()),
        ts_ms: ts,
        origin: DeviceId([0xEE; 32]),
    };
    // Exactly one wins (strict total order, no tie).
    assert_ne!(
        item_lo.wins_over(&item_hi),
        item_hi.wins_over(&item_lo),
        "equal-ts items must have a strict winner"
    );
    // Both "sides" agree on which origin wins (higher device id on a ts tie).
    let winner_from_a = if item_lo.wins_over(&item_hi) { &item_lo } else { &item_hi };
    let winner_from_b = if item_hi.wins_over(&item_lo) { &item_hi } else { &item_lo };
    assert_eq!(
        winner_from_a.origin, winner_from_b.origin,
        "both sides must converge on the same winner"
    );
    assert_eq!(winner_from_a.origin, DeviceId([0xEE; 32]), "ts tie breaks to the higher device id");

    // (2) Live convergence: two engines each copy different content; they settle
    // on one shared value that is one of the two copies.
    let (dir_a, dir_b, id_a, id_b) = trusted_pair("converge");
    let (dev_a, dev_b) = (id_a.device_id(), id_b.device_id());
    let (node_a, port_a) = start_node("A", id_a, dir_a.join("trusted.json")).await;
    let (node_b, port_b) = start_node("B", id_b, dir_b.join("trusted.json")).await;
    link(&node_a, port_a, dev_a, &node_b, port_b, dev_b).await;

    node_a.handle.set("copy-on-A");
    node_b.handle.set("copy-on-B");

    let converged = wait_for(|| {
        let a = node_a.handle.get();
        let b = node_b.handle.get();
        match (a, b) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        }
    })
    .await;
    let value = converged.expect("both engines should converge on one clipboard value");
    assert!(
        value == "copy-on-A" || value == "copy-on-B",
        "converged value must be one of the two copies, got {value:?}"
    );
    // Stable: after settling, both sides still agree (no flip-flop / echo loop).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node_a.handle.get(), Some(value.clone()));
    assert_eq!(node_b.handle.get(), Some(value));
}

// --- CASE 4: clock_skew_rejection ----------------------------------------

/// CRYPTO-3. A *trusted* peer sends a clip whose timestamp is 10 minutes in the
/// future (well beyond the ±2-minute tolerance). The engine drops the clip
/// (clipboard stays empty) but keeps the session alive — a subsequent Ping is
/// answered with a Pong.
#[tokio::test]
async fn clock_skew_rejection() {
    let dir_a = temp_dir("skew-a");
    let dir_c = temp_dir("skew-c");
    let id_a = Identity::load_or_generate(&FileKeyStore::new(dir_a.join("keys"))).unwrap();
    let id_c = Identity::load_or_generate(&FileKeyStore::new(dir_c.join("keys"))).unwrap();
    let (dev_c, pk_c) = (id_c.device_id(), id_c.public_key());

    // A trusts C.
    Allowlist::load(dir_a.join("trusted.json"))
        .unwrap()
        .add(dev_c, "C", &pk_c, now_ms())
        .unwrap();
    let (node_a, port_a) = start_node("A", id_a, dir_a.join("trusted.json")).await;

    // C connects, handshakes, and exchanges Hello.
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port_a))
        .await
        .unwrap();
    let mut chan = ucb_crypto::handshake_initiator(stream, &id_c).await.unwrap();
    chan.send(&WireMessage::Hello {
        version: PROTOCOL_VERSION,
        device: DeviceInfo {
            id: dev_c,
            name: "C".into(),
            platform: Platform::Linux,
        },
    })
    .await
    .unwrap();

    // Send a clip 10 minutes in the future — beyond the skew tolerance.
    let skewed = ClipboardItem {
        payload: ClipboardPayload::Text("from-the-future".into()),
        ts_ms: now_ms() + 10 * 60 * 1000,
        origin: dev_c,
    };
    chan.send(&WireMessage::Clip { seq: 0, item: skewed })
        .await
        .unwrap();

    // Then a Ping: the engine must still answer with a Pong (session survived).
    chan.send(&WireMessage::Ping).await.unwrap();

    let mut got_pong = false;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), chan.recv()).await {
            Ok(Ok(WireMessage::Pong)) => {
                got_pong = true;
                break;
            }
            // A's own Hello / Ping keepalives are fine; keep waiting for the Pong.
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => panic!("session closed after a skewed clip: {e:?}"),
            Err(_) => continue,
        }
    }
    assert!(got_pong, "engine should answer Ping with Pong (session survived the skewed clip)");

    // The skewed clip was never applied.
    assert_eq!(node_a.handle.get(), None, "clip beyond skew tolerance must not be applied");
}
