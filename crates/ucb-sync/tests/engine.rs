//! Full-engine integration tests: two engines wired together in-process over
//! real loopback TCP, with mock clipboards and hand-crafted discovery events.
//!
//! No OS keychain (FileKeyStore in temp dirs), no real clipboard (MockClipboard)
//! and no real mDNS (we build the PeerEvent channels ourselves).

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use ucb_clipboard::{ClipboardService, MockClipboard, MockClipboardHandle};
use ucb_core::Platform;
use ucb_crypto::{FileKeyStore, Identity};
use ucb_discovery::{Peer, PeerEvent};
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (mock, handle) = MockClipboard::new();
    let (writer, clip_rx) = ClipboardService::start(mock, POLL);
    let (disc_tx, disc_rx) = mpsc::channel(16);

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path,
            device_name: name.to_string(),
            platform: Platform::Linux,
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
