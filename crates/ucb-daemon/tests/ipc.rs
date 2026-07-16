//! End-to-end status-IPC round-trip against the real `ucb` binary.
//!
//! Fully sandboxed: a temp `--config-dir` with a file keystore (never the OS
//! keychain) and `--headless-dir` (never the real clipboard or mDNS). The test
//! spawns `ucb run`, waits for the daemon socket, and performs the newline-JSON
//! status handshake by hand so it does not depend on the daemon's private IPC
//! types.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Kill the spawned daemon when the test ends.
struct DaemonGuard(Child);
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ucb_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ucb")
}

fn temp_dir(tag: &str) -> PathBuf {
    // Root under /tmp (not the platform temp dir) to keep the derived unix
    // socket path well under the ~104-char sun_path limit on macOS.
    let dir = PathBuf::from("/tmp").join(format!(
        "ucb-ipc-{}-{}-{}",
        tag,
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Spin up a fully sandboxed, headless daemon and return its guard + socket path.
/// Shared by the extended-command tests so each does not re-implement the dance.
async fn spawn_headless_daemon(tag: &str) -> (DaemonGuard, PathBuf, PathBuf) {
    let cfg = temp_dir(tag);
    let headless = temp_dir(&format!("{tag}-hl"));

    let init = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["init", "--file-keystore", "--print-id"])
        .output()
        .expect("failed to run `ucb init`");
    assert!(init.status.success(), "init failed: {init:?}");

    // Bind on a free ephemeral port so parallel tests never collide.
    let free_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg_path = cfg.join("config.json");
    let mut cfg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg_json["listen_port"] = serde_json::json!(free_port);
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg_json).unwrap()).unwrap();

    let log_path = cfg.join("daemon.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log2 = log.try_clone().unwrap();
    let child = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["run", "--headless-dir", headless.to_str().unwrap()])
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .spawn()
        .expect("failed to spawn `ucb run`");
    let guard = DaemonGuard(child);

    let socket = cfg.join("daemon.sock");
    if !wait_for_file(&socket, Duration::from_secs(15)).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        panic!("daemon socket never appeared\n--- daemon log ---\n{log}");
    }
    (guard, cfg, socket)
}

/// Send one request line and read exactly one reply line, as JSON.
async fn request_one(socket: &Path, req: &str) -> serde_json::Value {
    let stream = UnixStream::connect(socket).await.expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(req.as_bytes()).await.unwrap();
    write_half.write_all(b"\n").await.unwrap();
    write_half.flush().await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"))
}

#[tokio::test]
async fn status_ipc_round_trip() {
    let cfg = temp_dir("cfg");
    let headless = temp_dir("headless");

    // Initialize identity + config with a file keystore (no keychain prompts).
    let init = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["init", "--file-keystore", "--print-id"])
        .output()
        .expect("failed to run `ucb init`");
    assert!(init.status.success(), "init failed: {:?}", init);

    // Rewrite the config to listen on a free ephemeral port so parallel tests
    // (or a real local daemon) never collide on the fixed default port.
    let free_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg_path = cfg.join("config.json");
    let mut cfg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg_json["listen_port"] = serde_json::json!(free_port);
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg_json).unwrap()).unwrap();

    // Launch the daemon, sandboxed and headless. Capture its log so a startup
    // failure is visible if the socket never appears.
    let log_path = cfg.join("daemon.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log2 = log.try_clone().unwrap();
    let child = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["run", "--headless-dir", headless.to_str().unwrap()])
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .spawn()
        .expect("failed to spawn `ucb run`");
    let _guard = DaemonGuard(child);

    // The daemon writes its socket into the config dir once it is serving.
    let socket = cfg.join("daemon.sock");
    if !wait_for_file(&socket, Duration::from_secs(15)).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        panic!(
            "daemon socket never appeared at {}\n--- daemon log ---\n{}",
            socket.display(),
            log
        );
    }

    // Perform the newline-delimited JSON status handshake.
    let stream = UnixStream::connect(&socket).await.expect("connect to daemon socket");
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
    write_half.flush().await.unwrap();

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("valid status JSON");
    assert!(v.get("peers").and_then(|p| p.as_array()).is_some(), "peers array: {v}");
    assert!(v.get("version").and_then(|s| s.as_str()).is_some(), "version: {v}");
    assert!(
        v.get("protocol").and_then(|p| p.as_u64()).is_some(),
        "protocol: {v}"
    );
    // No peers are paired in this sandbox.
    assert_eq!(v["peers"].as_array().unwrap().len(), 0);
    assert_eq!(v["protocol"].as_u64().unwrap(), ucb_core::PROTOCOL_VERSION as u64);
}

/// history_list / history_star / history_delete over IPC. In a fresh headless
/// sandbox no clips have been applied, so the store is empty; this exercises the
/// full command plumbing (History shared into the IPC server) and the
/// no-such-row paths.
#[tokio::test]
async fn history_ipc_commands() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("hist").await;

    // Empty store: a clean `{"entries":[]}` envelope.
    let v = request_one(&socket, r#"{"cmd":"history_list"}"#).await;
    assert!(v["entries"].as_array().is_some(), "entries array: {v}");
    assert_eq!(v["entries"].as_array().unwrap().len(), 0);

    // Filters parse and still return an empty set.
    let v = request_one(
        &socket,
        r#"{"cmd":"history_list","search":"x","starred":true,"limit":10,"device":"dead"}"#,
    )
    .await;
    assert_eq!(v["entries"].as_array().unwrap().len(), 0);

    // Star / delete a non-existent row -> ok:false (no match), never an error.
    let v = request_one(&socket, r#"{"cmd":"history_star","id":1,"starred":true}"#).await;
    assert_eq!(v["ok"], serde_json::json!(false));
    let v = request_one(&socket, r#"{"cmd":"history_delete","id":1}"#).await;
    assert_eq!(v["ok"], serde_json::json!(false));
}

/// config_get / config_set round-trip: setting persists to config.json and a
/// follow-up config_get observes it, with the honest restart_required flag.
#[tokio::test]
async fn config_ipc_commands() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("cfg").await;

    let v = request_one(&socket, r#"{"cmd":"config_get"}"#).await;
    assert_eq!(v["auto_file_sync"], serde_json::json!(false), "default off: {v}");
    assert!(v["name"].as_str().is_some(), "config carries name: {v}");

    let v = request_one(&socket, r#"{"cmd":"config_set","auto_file_sync":true}"#).await;
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(
        v["restart_required"],
        serde_json::json!(true),
        "must report the hot-reload limitation honestly: {v}"
    );

    // The change is persisted and visible to a fresh config_get.
    let v = request_one(&socket, r#"{"cmd":"config_get"}"#).await;
    assert_eq!(v["auto_file_sync"], serde_json::json!(true));
}

/// revoke with no matching peer reports ok:false rather than erroring.
#[tokio::test]
async fn revoke_ipc_no_match() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("revoke").await;
    let v = request_one(&socket, r#"{"cmd":"revoke","prefix":"deadbeef"}"#).await;
    assert_eq!(v["ok"], serde_json::json!(false), "no such peer: {v}");
}

/// pair_listen_start streams a `pairing` line (URI + QR), and a second
/// concurrent pairing is rejected while the first holds the slot.
#[tokio::test]
async fn pair_listen_ipc_stream_and_concurrency() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("pair").await;

    // First connection: begin pairing, read the streamed `pairing` line. The
    // connection is kept open (no peer dials in), so it holds the pairing slot.
    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"{\"cmd\":\"pair_listen_start\"}\n")
        .await
        .unwrap();
    write_half.flush().await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("valid pairing JSON");
    assert_eq!(v["type"], serde_json::json!("pairing"), "first line: {v}");
    let uri = v["uri"].as_str().expect("uri present");
    assert!(uri.starts_with("ucb://"), "uri looks like a pairing URI: {uri}");
    assert!(!v["qr_text"].as_str().unwrap_or("").is_empty(), "qr rendered: {v}");

    // Second, concurrent pairing must be rejected while the first is live.
    let v2 = request_one(&socket, r#"{"cmd":"pair_listen_start"}"#).await;
    assert_eq!(v2["type"], serde_json::json!("error"), "concurrent reject: {v2}");
    assert!(
        v2["message"].as_str().unwrap_or("").contains("already in progress"),
        "message explains the rejection: {v2}"
    );

    // Dropping the first connection releases the slot.
    drop(write_half);
    drop(reader);
}
