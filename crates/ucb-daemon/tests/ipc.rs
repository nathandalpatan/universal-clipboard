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

/// A spawned, sandboxed daemon with the paths a test needs to drive it.
struct Daemon {
    _guard: DaemonGuard,
    cfg: PathBuf,
    headless: PathBuf,
    socket: PathBuf,
}

/// Grab a free TCP port by binding an ephemeral socket and reading its number.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Spawn a sandboxed, headless daemon listening on `listen_port` with the given
/// static peers (so two daemons can reach each other with mDNS disabled). Used
/// by the live-pairing test.
async fn spawn_daemon_configured(tag: &str, listen_port: u16, static_peers: &[String]) -> Daemon {
    let cfg = temp_dir(tag);
    let headless = temp_dir(&format!("{tag}-hl"));

    let init = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["init", "--file-keystore", "--print-id"])
        .output()
        .expect("failed to run `ucb init`");
    assert!(init.status.success(), "init failed: {init:?}");

    let cfg_path = cfg.join("config.json");
    let mut cfg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg_json["listen_port"] = serde_json::json!(listen_port);
    cfg_json["static_peers"] = serde_json::json!(static_peers);
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
    Daemon {
        _guard: guard,
        cfg,
        headless,
        socket,
    }
}

/// A persistent IPC connection for multi-line, stateful flows (pairing streams).
struct Conn {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    write: tokio::net::unix::OwnedWriteHalf,
}

impl Conn {
    async fn open(socket: &Path) -> Self {
        let stream = connect_retry(socket).await;
        let (read_half, write) = stream.into_split();
        Conn {
            reader: BufReader::new(read_half),
            write,
        }
    }

    async fn send(&mut self, line: &str) {
        self.write.write_all(line.as_bytes()).await.unwrap();
        self.write.write_all(b"\n").await.unwrap();
        self.write.flush().await.unwrap();
    }

    /// Read one JSON line (panics on EOF/timeout).
    async fn read_json(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(15), self.reader.read_line(&mut line))
            .await
            .expect("timed out reading pairing line")
            .expect("read pairing line");
        assert!(n > 0, "connection closed while awaiting a line");
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad line {line:?}: {e}"))
    }
}

/// Connect to the daemon socket, retrying briefly on connection-refused so a
/// client that races the server's accept loop (under parallel test load) does
/// not spuriously fail. Makes the IPC tests deterministic.
async fn connect_retry(socket: &Path) -> UnixStream {
    let mut last_err = None;
    for _ in 0..5 {
        match UnixStream::connect(socket).await {
            Ok(s) => return s,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("could not connect to daemon socket: {last_err:?}");
}

/// Send one request line and read exactly one reply line, as JSON. Retries the
/// connect and re-sends once if the server closes the connection before the
/// first reply line (an EOF-before-first-line race under parallel load).
async fn request_one(socket: &Path, req: &str) -> serde_json::Value {
    for attempt in 0..5 {
        let stream = connect_retry(socket).await;
        let (read_half, mut write_half) = stream.into_split();
        write_half.write_all(req.as_bytes()).await.unwrap();
        write_half.write_all(b"\n").await.unwrap();
        write_half.flush().await.unwrap();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) if attempt < 4 => {
                // EOF before any reply: retry.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Ok(_) => {
                return serde_json::from_str(line.trim())
                    .unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"))
            }
            Err(e) if attempt < 4 => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = e;
                continue;
            }
            Err(e) => panic!("reading reply failed: {e}"),
        }
    }
    panic!("daemon never produced a reply for {req}");
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

/// `discovered` on a fresh headless daemon (no mDNS) returns a clean, empty peer
/// list — exercising the command plumbing and the JSON envelope shape.
#[tokio::test]
async fn discovered_ipc_empty_ok() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("disc").await;
    let v = request_one(&socket, r#"{"cmd":"discovered"}"#).await;
    let peers = v["peers"].as_array().expect("peers array");
    assert!(peers.is_empty(), "no peers discovered in a headless sandbox: {v}");
}

/// `incoming` on a fresh headless daemon (nothing has tried to connect) returns
/// a clean, empty `{"attempts":[]}` envelope — the command plumbing + shape.
#[tokio::test]
async fn incoming_ipc_empty_ok() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("incempty").await;
    let v = request_one(&socket, r#"{"cmd":"incoming"}"#).await;
    let attempts = v["attempts"].as_array().expect("attempts array");
    assert!(attempts.is_empty(), "no attempts in a headless sandbox: {v}");
}

/// Two daemons that are NOT paired but can reach each other (static peers) each
/// dial the other's sync port and are rejected as untrusted — and that rejected
/// attempt surfaces in the `incoming` snapshot (NAT-60). Visibility only: the
/// peer is never trusted, so `status` stays empty.
#[tokio::test]
async fn incoming_ipc_records_rejected_untrusted_attempt() {
    let port_a = free_port();
    let port_b = free_port();
    let da = spawn_daemon_configured("inA", port_a, &[format!("127.0.0.1:{port_b}")]).await;
    // Kept alive to end of scope so B keeps dialing A's sync port.
    let _db = spawn_daemon_configured("inB", port_b, &[format!("127.0.0.1:{port_a}")]).await;

    // B's static connector dials A and is rejected (not paired) — A records it.
    // Poll until the attempt surfaces (the connector retries with backoff).
    let mut attempts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let v = request_one(&da.socket, r#"{"cmd":"incoming"}"#).await;
        attempts = v["attempts"].as_array().cloned().unwrap_or_default();
        if !attempts.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!attempts.is_empty(), "A must record B's rejected attempt");
    let a0 = &attempts[0];
    assert_eq!(a0["addr"], serde_json::json!("127.0.0.1"), "source ip: {a0}");
    assert!(a0["count"].as_u64().unwrap_or(0) >= 1, "count present: {a0}");
    assert!(a0["id_short"].as_str().is_some(), "id_short present: {a0}");
    assert!(a0["id"].as_str().is_some(), "full id present: {a0}");
    assert!(a0.get("first_seen_ms").and_then(|x| x.as_u64()).is_some(), "first_seen_ms: {a0}");
    assert!(a0.get("last_seen_ms").and_then(|x| x.as_u64()).is_some(), "last_seen_ms: {a0}");

    // Visibility grants NO trust: the rejected peer is not paired.
    let status = request_one(&da.socket, r#"{"cmd":"status"}"#).await;
    assert_eq!(
        status["peers"].as_array().unwrap().len(),
        0,
        "inbound visibility must not trust the peer: {status}"
    );
}

/// `config_set` accepts `max_auto_file_bytes` (alongside `auto_file_sync`) and
/// persists it, visible to a follow-up `config_get`.
#[tokio::test]
async fn config_set_max_auto_file_bytes_persists() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("cfgmax").await;

    let v = request_one(
        &socket,
        r#"{"cmd":"config_set","max_auto_file_bytes":1048576}"#,
    )
    .await;
    assert_eq!(v["ok"], serde_json::json!(true), "{v}");
    assert_eq!(v["restart_required"], serde_json::json!(true), "{v}");

    let v = request_one(&socket, r#"{"cmd":"config_get"}"#).await;
    assert_eq!(v["max_auto_file_bytes"], serde_json::json!(1_048_576u64), "{v}");
}

/// `transfers_subscribe` opens a long-lived stream. With no transfers happening
/// it stays open and produces nothing; the daemon does not close it. (A full
/// event-during-send assertion is covered by the engine-level transfer test;
/// here we assert the stream stays open and empty.)
#[tokio::test]
async fn transfers_subscribe_stays_open_and_silent() {
    let (_guard, _cfg, socket) = spawn_headless_daemon("xfer").await;
    let mut conn = Conn::open(&socket).await;
    conn.send(r#"{"cmd":"transfers_subscribe"}"#).await;

    // No transfer is in flight, so no line should arrive within a short window,
    // and the connection must remain open (not EOF).
    let mut line = String::new();
    let res = tokio::time::timeout(
        Duration::from_millis(600),
        conn.reader.read_line(&mut line),
    )
    .await;
    assert!(res.is_err(), "expected no event and no EOF, got {line:?}");
}

/// End-to-end live pairing over IPC: daemon A `pair_listen_start`, daemon B
/// `pair_connect` to A's pairing URI, both confirm — then BOTH allowlists gain
/// the peer AND a clip written on A syncs to B, all WITHOUT restarting either
/// daemon (thanks to live `trust_peer`). Static peers give the engines a way to
/// reach each other with mDNS disabled in this headless sandbox.
#[tokio::test]
async fn pair_connect_live_pairs_and_syncs_without_restart() {
    let port_a = free_port();
    let port_b = free_port();
    let da = spawn_daemon_configured("pcA", port_a, &[format!("127.0.0.1:{port_b}")]).await;
    let db = spawn_daemon_configured("pcB", port_b, &[format!("127.0.0.1:{port_a}")]).await;

    // A begins listening for a pairing; read the streamed URI to learn the
    // actual pairing port (listen_port+1, or an ephemeral fallback).
    let mut a = Conn::open(&da.socket).await;
    a.send(r#"{"cmd":"pair_listen_start"}"#).await;
    let pairing = a.read_json().await;
    assert_eq!(pairing["type"], serde_json::json!("pairing"), "{pairing}");
    let uri = pairing["uri"].as_str().expect("uri");
    let pair_port: u16 = uri.rsplit(':').next().unwrap().parse().expect("port in uri");

    // B dials A's pairing endpoint on loopback (independent of the URI host).
    let mut b = Conn::open(&db.socket).await;
    b.send(&format!(
        r#"{{"cmd":"pair_connect","addr":"127.0.0.1:{pair_port}"}}"#
    ))
    .await;

    // Both sides surface the 6-digit code (same value on both).
    let a_code = a.read_json().await;
    let b_code = b.read_json().await;
    assert_eq!(a_code["type"], serde_json::json!("code"), "A code line: {a_code}");
    assert_eq!(b_code["type"], serde_json::json!("code"), "B code line: {b_code}");
    assert_eq!(
        a_code["code"], b_code["code"],
        "both sides must show the same verification code"
    );

    // Confirm on both.
    a.send(r#"{"cmd":"pair_confirm","accept":true}"#).await;
    b.send(r#"{"cmd":"pair_confirm","accept":true}"#).await;

    let a_result = a.read_json().await;
    let b_result = b.read_json().await;
    assert_eq!(a_result["ok"], serde_json::json!(true), "A result: {a_result}");
    assert_eq!(b_result["ok"], serde_json::json!(true), "B result: {b_result}");

    // Both allowlists now hold the peer (trusted.json written by the pairing flow).
    let a_trusted = wait_for_json_nonempty(&da.cfg.join("trusted.json")).await;
    let b_trusted = wait_for_json_nonempty(&db.cfg.join("trusted.json")).await;
    assert!(
        a_trusted.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        "A trusted.json must list the peer: {a_trusted}"
    );
    assert!(
        b_trusted.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        "B trusted.json must list the peer: {b_trusted}"
    );

    // A clip written on A syncs to B WITHOUT restarting either daemon: live
    // trust_peer plus the static connectors bring the session up on their own.
    std::fs::write(da.headless.join("clip-in"), b"live-paired-clip").unwrap();
    let synced = wait_for_content(&db.headless.join("clip-out"), "live-paired-clip").await;
    assert!(
        synced,
        "clip did not sync A -> B after live pairing (no restart)"
    );
}

/// Poll a JSON file until it exists and parses to a non-null value.
async fn wait_for_json_nonempty(path: &Path) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    return v;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    serde_json::json!({})
}

/// Poll a file until its contents contain `needle`, up to a generous timeout
/// (the static connector reconnects after live trust with a short backoff).
async fn wait_for_content(path: &Path, needle: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(path) {
            if s.contains(needle) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}
