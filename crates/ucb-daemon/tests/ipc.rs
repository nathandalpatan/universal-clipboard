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
