// Universal Clipboard — desktop GUI shell (Tauri v2 tray app).
//
// This is a *frontend*: the daemon (`ucb run`) stays the single engine process.
// Every command here opens a short-lived connection to the daemon's unix socket
// (the existing newline-delimited JSON IPC) and relays one request/response.
// No direct dependency on the `ucb-*` crates — JSON in, JSON out.
//
// Tickets: HIST-3 (history GUI), UX-2 (devices + pair CTA), PAIR-2 (on-screen
// QR pairing), UX-3 groundwork (spinner threshold lives in the frontend).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod biometric;
mod capture;
mod sensitive;

use std::path::PathBuf;

use serde::Serialize;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};

#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::unix::OwnedWriteHalf;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::sync::Mutex;

/// Holds the write half of the *live* pairing connection so `pair_confirm` can
/// answer the daemon on the same socket the code arrived on. `None` when no
/// pairing is in progress.
#[cfg(unix)]
#[derive(Default)]
struct PairState(Mutex<Option<OwnedWriteHalf>>);

#[cfg(not(unix))]
#[derive(Default)]
struct PairState;

/// Resolve the daemon's IPC socket path, mirroring the daemon's own layout
/// (`ProjectDirs("dev","ucb","universal-clipboard")/daemon.sock`). Overridable
/// with `UCB_SOCKET` (full path) or `UCB_CONFIG_DIR` (its parent) so a sandboxed
/// daemon can be targeted without touching the real config dir.
fn socket_path() -> PathBuf {
    if let Ok(sock) = std::env::var("UCB_SOCKET") {
        return PathBuf::from(sock);
    }
    if let Ok(dir) = std::env::var("UCB_CONFIG_DIR") {
        return PathBuf::from(dir).join("daemon.sock");
    }
    directories::ProjectDirs::from("dev", "ucb", "universal-clipboard")
        .map(|d| d.config_dir().join("daemon.sock"))
        .unwrap_or_else(|| PathBuf::from("daemon.sock"))
}

/// Send one newline-terminated JSON request to the daemon and read exactly one
/// reply line back. Used by every single-shot command (everything but pairing).
#[cfg(unix)]
async fn send_request(req: String) -> Result<serde_json::Value, String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        format!(
            "could not reach the daemon at {} ({e}). Is `ucb run` active?",
            path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_half.write_all(b"\n").await.map_err(|e| e.to_string())?;
    write_half.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await.map_err(|e| e.to_string())? == 0 {
        return Err("daemon closed the connection without a reply".into());
    }
    serde_json::from_str(line.trim()).map_err(|e| format!("bad daemon reply: {e}"))
}

#[cfg(not(unix))]
async fn send_request(_req: String) -> Result<serde_json::Value, String> {
    Err("the GUI IPC client is only implemented for unix-socket platforms".into())
}

// --- single-shot commands --------------------------------------------------

#[tauri::command]
async fn ipc_status() -> Result<serde_json::Value, String> {
    send_request(r#"{"cmd":"status"}"#.to_string()).await
}

#[tauri::command]
async fn ipc_history_list(
    search: Option<String>,
    device: Option<String>,
    starred: Option<bool>,
    limit: Option<usize>,
    before_ts: Option<u64>,
) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({
        "cmd": "history_list",
        "search": search,
        "device": device,
        "starred": starred,
        "limit": limit,
        "before_ts": before_ts,
    });
    send_request(req.to_string()).await
}

#[tauri::command]
async fn ipc_history_star(id: i64, starred: bool) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "cmd": "history_star", "id": id, "starred": starred });
    send_request(req.to_string()).await
}

#[tauri::command]
async fn ipc_history_delete(id: i64) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "cmd": "history_delete", "id": id });
    send_request(req.to_string()).await
}

#[tauri::command]
async fn ipc_config_get() -> Result<serde_json::Value, String> {
    send_request(r#"{"cmd":"config_get"}"#.to_string()).await
}

#[tauri::command]
async fn ipc_config_set(
    auto_file_sync: Option<bool>,
    max_auto_file_bytes: Option<u64>,
) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({
        "cmd": "config_set",
        "auto_file_sync": auto_file_sync,
        "max_auto_file_bytes": max_auto_file_bytes,
    });
    send_request(req.to_string()).await
}

#[tauri::command]
async fn ipc_revoke(prefix: String) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "cmd": "revoke", "prefix": prefix });
    send_request(req.to_string()).await
}

/// Every peer discovery has seen (trusted or not) — the "nearby devices" list.
#[tauri::command]
async fn ipc_discovered() -> Result<serde_json::Value, String> {
    send_request(r#"{"cmd":"discovered"}"#.to_string()).await
}

// --- pairing (streaming over one persistent connection) --------------------

/// Begin an on-screen pairing session. Opens a dedicated connection, reads the
/// first (`pairing`) line to return immediately (URI + QR), then spawns a task
/// that relays every later line (`code`, `result`) to the frontend as
/// `pair://event` events. The write half is stashed in [`PairState`] so
/// `pair_confirm` can answer on the same socket.
#[cfg(unix)]
#[tauri::command]
async fn pair_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, PairState>,
) -> Result<serde_json::Value, String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        format!(
            "could not reach the daemon at {} ({e}). Is `ucb run` active?",
            path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"{\"cmd\":\"pair_listen_start\"}\n")
        .await
        .map_err(|e| e.to_string())?;
    write_half.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await.map_err(|e| e.to_string())? == 0 {
        return Err("daemon closed the connection".into());
    }
    let first: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("bad daemon reply: {e}"))?;

    // A concurrent-pairing rejection (or any error) arrives here; don't retain
    // the connection.
    if first.get("type").and_then(|t| t.as_str()) == Some("error") {
        return Ok(first);
    }

    *state.0.lock().await = Some(write_half);

    let app2 = app.clone();
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => {
                    let _ = app2.emit("pair://event", serde_json::json!({ "type": "closed" }));
                    break;
                }
                Ok(_) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                        let is_result = v.get("type").and_then(|t| t.as_str()) == Some("result");
                        let _ = app2.emit("pair://event", v);
                        if is_result {
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(first)
}

/// Begin an *outgoing* pairing to a listening peer (the one-click "Pair" on a
/// nearby device, or "Add by address"). Opens a dedicated connection, sends
/// `pair_connect`, stashes the write half in [`PairState`] so `pair_confirm`
/// answers on the same socket, and streams every daemon line (`code`, `result`,
/// `error`) to the frontend as `pair://event` events. Returns immediately; the
/// 6-digit code arrives as an event once the handshake completes.
#[cfg(unix)]
#[tauri::command]
async fn pair_connect_start(
    app: tauri::AppHandle,
    addr: String,
    state: tauri::State<'_, PairState>,
) -> Result<(), String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        format!(
            "could not reach the daemon at {} ({e}). Is sync running?",
            path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    let req = serde_json::json!({ "cmd": "pair_connect", "addr": addr }).to_string();
    write_half
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    write_half.write_all(b"\n").await.map_err(|e| e.to_string())?;
    write_half.flush().await.map_err(|e| e.to_string())?;

    *state.0.lock().await = Some(write_half);

    let app2 = app.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => {
                    let _ = app2.emit("pair://event", serde_json::json!({ "type": "closed" }));
                    break;
                }
                Ok(_) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                        let t = v.get("type").and_then(|t| t.as_str()).map(str::to_string);
                        let _ = app2.emit("pair://event", v);
                        if matches!(t.as_deref(), Some("result") | Some("error")) {
                            break;
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

/// Answer the pairing in progress with the user's accept/reject decision.
#[cfg(unix)]
#[tauri::command]
async fn pair_confirm(accept: bool, state: tauri::State<'_, PairState>) -> Result<(), String> {
    let mut guard = state.0.lock().await;
    match guard.as_mut() {
        Some(w) => {
            let line = format!("{{\"cmd\":\"pair_confirm\",\"accept\":{accept}}}\n");
            w.write_all(line.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            w.flush().await.map_err(|e| e.to_string())?;
            // The daemon will send `result` and close; release the connection.
            *guard = None;
            Ok(())
        }
        None => Err("no pairing in progress".into()),
    }
}

/// Abandon the pairing in progress (drops the connection; the daemon sees EOF
/// and declines, freeing its single pairing slot).
#[cfg(unix)]
#[tauri::command]
async fn pair_cancel(state: tauri::State<'_, PairState>) -> Result<(), String> {
    *state.0.lock().await = None;
    Ok(())
}

// Non-unix stubs so `generate_handler!` resolves on every platform.
#[cfg(not(unix))]
#[tauri::command]
async fn pair_start(
    _app: tauri::AppHandle,
    _state: tauri::State<'_, PairState>,
) -> Result<serde_json::Value, String> {
    Err("pairing IPC is only implemented for unix-socket platforms".into())
}
#[cfg(not(unix))]
#[tauri::command]
async fn pair_confirm(_accept: bool, _state: tauri::State<'_, PairState>) -> Result<(), String> {
    Err("pairing IPC is only implemented for unix-socket platforms".into())
}
#[cfg(not(unix))]
#[tauri::command]
async fn pair_cancel(_state: tauri::State<'_, PairState>) -> Result<(), String> {
    Ok(())
}
#[cfg(not(unix))]
#[tauri::command]
async fn pair_connect_start(
    _app: tauri::AppHandle,
    _addr: String,
    _state: tauri::State<'_, PairState>,
) -> Result<(), String> {
    Err("pairing IPC is only implemented for unix-socket platforms".into())
}

// --- transfers (streaming over one persistent connection) ------------------

/// Subscribe to the daemon's live transfer-event stream. Opens a dedicated
/// connection, sends `transfers_subscribe`, and relays each event line to the
/// frontend as a `transfer://event`. When the stream ends (daemon gone or socket
/// dropped) it emits a final `{"type":"stream_closed"}` so the frontend can
/// reconnect. Returns immediately.
#[cfg(unix)]
#[tauri::command]
async fn transfers_start(app: tauri::AppHandle) -> Result<(), String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        format!(
            "could not reach the daemon at {} ({e}). Is sync running?",
            path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"{\"cmd\":\"transfers_subscribe\"}\n")
        .await
        .map_err(|e| e.to_string())?;
    write_half.flush().await.map_err(|e| e.to_string())?;

    tokio::spawn(async move {
        // Keep the write half alive for the lifetime of the stream.
        let _write = write_half;
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => {
                    let _ = app.emit("transfer://event", serde_json::json!({ "type": "stream_closed" }));
                    break;
                }
                Ok(_) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                        let _ = app.emit("transfer://event", v);
                    }
                }
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
#[tauri::command]
async fn transfers_start(_app: tauri::AppHandle) -> Result<(), String> {
    Err("transfer IPC is only implemented for unix-socket platforms".into())
}

// --- HIST-5/6/7 history-protection commands --------------------------------

/// What this platform+device can enforce, so the frontend can adapt without
/// ever showing a fake lock or a dead toggle.
#[derive(Serialize)]
struct Capabilities {
    /// `std::env::consts::OS` (e.g. "macos", "windows", "linux").
    os: String,
    /// Whether screenshot/recording exclusion is enforced on this OS (HIST-7).
    capture_protection: bool,
    /// Whether biometric/device-owner auth is usable right now (HIST-5).
    biometrics: bool,
}

#[tauri::command]
fn platform_capabilities() -> Capabilities {
    Capabilities {
        os: std::env::consts::OS.to_string(),
        capture_protection: cfg!(any(target_os = "macos", target_os = "windows")),
        biometrics: biometric::available(),
    }
}

/// HIST-7: toggle screenshot / screen-sharing exclusion on the main window.
#[tauri::command]
async fn set_capture_protection(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("main") {
        capture::apply(&w, enabled)?;
    }
    Ok(())
}

/// HIST-5: run the biometric prompt, unlocking the History view on success.
#[tauri::command]
async fn authenticate(reason: String) -> biometric::AuthResult {
    biometric::authenticate(&reason).await
}

/// HIST-6: classify a batch of entry texts as sensitive (blur candidates).
#[tauri::command]
fn is_sensitive_batch(texts: Vec<String>) -> Vec<bool> {
    texts.iter().map(|t| sensitive::is_sensitive(t)).collect()
}

/// HIST-6: classify a single text (kept for completeness / ad-hoc checks).
#[tauri::command]
fn is_sensitive(text: String) -> bool {
    sensitive::is_sensitive(&text)
}

// --- onboarding + managed daemon (first-run "front door") ------------------

/// A `ucb run` child process the GUI started and therefore owns: it is killed
/// when the GUI quits. `None` when sync runs as a background service (or a
/// separately-started daemon) that we must not kill.
#[derive(Default)]
struct ManagedDaemon(std::sync::Mutex<Option<std::process::Child>>);

/// Locate the `ucb` daemon binary. Search order (documented in the README):
/// 1. **Bundled sidecar** — in a packaged app the Tauri bundler copies the
///    `externalBin` (`ucb-<target-triple>`) next to the GUI executable with the
///    triple suffix stripped (`.../Contents/MacOS/ucb`, `.../ucb.exe`, …). This
///    wins in a real install so we never fall back to `PATH`.
/// 2. `UCB_BIN` env var (explicit override, dev),
/// 3. a `target/{release,debug}/ucb` above the executable (dev checkout),
/// 4. bare `ucb` on `PATH` (last resort).
///
/// In a dev checkout step 1 finds nothing — the GUI's own `target/` dir has no
/// `ucb` next to `ucb-gui` (the daemon builds into the *root* workspace target) —
/// so the dev fallbacks apply exactly as before.
fn locate_ucb() -> PathBuf {
    let bin_name = if cfg!(windows) { "ucb.exe" } else { "ucb" };

    // 1. Bundled sidecar: next to the GUI executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let side = dir.join(bin_name);
            if side.exists() {
                return side;
            }
        }
    }
    // 2. Explicit override (dev).
    if let Ok(p) = std::env::var("UCB_BIN") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    // 3. Dev checkout: walk up looking for target/{release,debug}/ucb.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let mut cur = Some(dir);
            while let Some(d) = cur {
                for profile in ["release", "debug"] {
                    let cand = d.join("target").join(profile).join(bin_name);
                    if cand.exists() {
                        return cand;
                    }
                }
                cur = d.parent();
            }
        }
    }
    // 4. Resolved via PATH at spawn time.
    PathBuf::from(bin_name)
}

/// The config directory the GUI (and any daemon it spawns) uses, mirroring the
/// socket-path resolution: `UCB_CONFIG_DIR`, else the parent of `UCB_SOCKET`,
/// else the platform config dir.
fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("UCB_CONFIG_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(sock) = std::env::var("UCB_SOCKET") {
        return PathBuf::from(sock).parent().map(|p| p.to_path_buf());
    }
    directories::ProjectDirs::from("dev", "ucb", "universal-clipboard")
        .map(|d| d.config_dir().to_path_buf())
}

/// Build a `ucb` command, forwarding `--config-dir` when the GUI is pointed at a
/// non-default config dir (e.g. a sandbox), so spawned daemons share the state.
fn ucb_command() -> std::process::Command {
    let mut cmd = std::process::Command::new(locate_ucb());
    if let Ok(dir) = std::env::var("UCB_CONFIG_DIR") {
        cmd.args(["--config-dir", &dir]);
    }
    cmd
}

/// Spawn `ucb run` as a managed child (killed on GUI quit). A no-op if we
/// already manage a running child.
fn start_managed(managed: &ManagedDaemon) -> Result<(), String> {
    let mut guard = managed.0.lock().map_err(|_| "managed-daemon lock poisoned")?;
    if guard.is_some() {
        return Ok(()); // already running one we own
    }
    let child = ucb_command()
        .arg("run")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start `ucb run`: {e}"))?;
    *guard = Some(child);
    Ok(())
}

/// Kill the managed `ucb run` child if we own one.
fn stop_managed(managed: &ManagedDaemon) {
    if let Ok(mut guard) = managed.0.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Report where the `ucb` binary resolves to (for the onboarding UI / diagnostics).
#[tauri::command]
fn ucb_binary_path() -> String {
    locate_ucb().to_string_lossy().into_owned()
}

/// True if this device has been initialized (`config.json` exists).
#[tauri::command]
fn ucb_is_initialized() -> bool {
    config_dir()
        .map(|d| d.join("config.json").exists())
        .unwrap_or(false)
}

/// True if the GUI currently manages a running `ucb run` child.
#[tauri::command]
fn daemon_is_managed(managed: tauri::State<'_, ManagedDaemon>) -> bool {
    managed
        .0
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

/// First-run setup: initialize the device if needed, then start syncing.
///
/// * Runs `ucb init --name <name> --print-id` when `config.json` is absent,
///   returning the new identity.
/// * With `keep_background = true`, installs + activates the background service
///   (`ucb service install --activate`) so sync survives the GUI closing.
/// * Otherwise spawns a managed `ucb run` child that is killed when the GUI quits.
#[tauri::command]
async fn onboard(
    name: Option<String>,
    keep_background: bool,
    managed: tauri::State<'_, ManagedDaemon>,
) -> Result<serde_json::Value, String> {
    let cfg_dir = config_dir().ok_or("could not determine the config directory")?;

    let mut identity = serde_json::Value::Null;
    if !cfg_dir.join("config.json").exists() {
        let mut cmd = ucb_command();
        cmd.args(["init", "--print-id"]);
        if let Some(n) = name.as_deref().filter(|s| !s.trim().is_empty()) {
            cmd.args(["--name", n]);
        }
        let out = cmd
            .output()
            .map_err(|e| format!("could not run `ucb init`: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "`ucb init` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        identity = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    }

    let managed_flag = if keep_background {
        let out = ucb_command()
            .args(["service", "install", "--activate"])
            .output()
            .map_err(|e| format!("could not install the background service: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "installing the background service failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        false
    } else {
        start_managed(&managed)?;
        true
    };

    Ok(serde_json::json!({
        "ok": true,
        "managed": managed_flag,
        "identity": identity,
    }))
}

/// Start syncing under GUI management (the "Start sync" button).
#[tauri::command]
async fn daemon_start(managed: tauri::State<'_, ManagedDaemon>) -> Result<(), String> {
    start_managed(&managed)
}

/// Stop the GUI-managed daemon (the "Stop sync" button). No-op if sync runs as a
/// background service we do not own.
#[tauri::command]
async fn daemon_stop(managed: tauri::State<'_, ManagedDaemon>) -> Result<(), String> {
    stop_managed(&managed);
    Ok(())
}

/// Restart the GUI-managed daemon (the Settings "Restart sync" action, used to
/// apply config changes that need a fresh `ucb run`). Only meaningful when the
/// daemon is GUI-managed.
#[tauri::command]
async fn daemon_restart(managed: tauri::State<'_, ManagedDaemon>) -> Result<(), String> {
    stop_managed(&managed);
    // Give the OS a moment to release the socket/port before re-binding.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    start_managed(&managed)
}

/// Reveal a received file in the platform file manager ("Show in folder").
#[tauri::command]
async fn reveal_in_folder(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .args(["-R", &path])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(format!("/select,{path}"))
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let parent = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        std::process::Command::new("xdg-open")
            .arg(parent)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// --- auto-updater (REL-1) --------------------------------------------------

/// Holds a downloaded-but-not-yet-installed [`tauri_plugin_updater::Update`] so
/// `check_for_update` can return the version to the UI and a later
/// `install_update` (the toast's Install button) can act on the same handle.
#[derive(Default)]
struct PendingUpdate(tokio::sync::Mutex<Option<tauri_plugin_updater::Update>>);

/// Check the configured GitHub-releases `latest.json` for a newer version.
///
/// Returns `{ available: true, version, notes }` when an update exists (and
/// stashes the handle for `install_update`), or `{ available: false }` when the
/// app is current. Errors (offline, bad manifest, signature mismatch) surface as
/// a `Result::Err` so the caller can stay silent on an auto-check but show the
/// reason on a manual check.
#[tauri::command]
async fn check_for_update(
    app: tauri::AppHandle,
    pending: tauri::State<'_, PendingUpdate>,
) -> Result<serde_json::Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await.map_err(|e| e.to_string())? {
        Some(update) => {
            let version = update.version.clone();
            let notes = update.body.clone();
            *pending.0.lock().await = Some(update);
            Ok(serde_json::json!({
                "available": true,
                "version": version,
                "notes": notes,
            }))
        }
        None => {
            *pending.0.lock().await = None;
            Ok(serde_json::json!({ "available": false }))
        }
    }
}

/// Download + install the update stashed by the last successful
/// `check_for_update`, then relaunch into the new version. The download is
/// verified against the updater public key in `tauri.conf.json` before install.
#[tauri::command]
async fn install_update(
    app: tauri::AppHandle,
    pending: tauri::State<'_, PendingUpdate>,
) -> Result<(), String> {
    let update = pending
        .0
        .lock()
        .await
        .take()
        .ok_or("no update is pending — run a check first")?;
    update
        .download_and_install(|_downloaded, _total| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    // Relaunch into the freshly installed version. `restart` does not return.
    app.restart();
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(PairState::default())
        .manage(ManagedDaemon::default())
        .manage(PendingUpdate::default())
        .setup(|app| {
            // Tray menu: Open, a status line (UX-2 sync indicator via polling),
            // and Quit.
            let status_item = MenuItemBuilder::with_id("status", "Daemon: checking…")
                .enabled(false)
                .build(app)?;
            let open_item = MenuItemBuilder::with_id("open", "Open").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app)
                .item(&status_item)
                .separator()
                .item(&open_item)
                .item(&quit_item)
                .build()?;

            let mut tray = TrayIconBuilder::with_id("main")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            tray.build(app)?;

            // HIST-7: exclude the window from screen capture by default (secure
            // default = ON). The frontend re-applies the persisted preference on
            // boot, so an OFF preference is honored immediately after load.
            if let Some(w) = app.get_webview_window("main") {
                let _ = capture::apply(&w, true);
            }

            // UX-2: poll daemon status every 3s and reflect it in the tray label.
            let item = status_item.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let text = match send_request(r#"{"cmd":"status"}"#.to_string()).await {
                        Ok(v) => {
                            let peers = v.get("peers").and_then(|p| p.as_array());
                            let total = peers.map(|a| a.len()).unwrap_or(0);
                            let connected = peers
                                .map(|a| {
                                    a.iter()
                                        .filter(|p| {
                                            p.get("connected")
                                                .and_then(|c| c.as_bool())
                                                .unwrap_or(false)
                                        })
                                        .count()
                                })
                                .unwrap_or(0);
                            format!("Sync on — {connected}/{total} peer(s) connected")
                        }
                        Err(_) => "Daemon offline — run `ucb run`".to_string(),
                    };
                    let _ = item.set_text(text);
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc_status,
            ipc_history_list,
            ipc_history_star,
            ipc_history_delete,
            ipc_config_get,
            ipc_config_set,
            ipc_revoke,
            ipc_discovered,
            pair_start,
            pair_confirm,
            pair_cancel,
            pair_connect_start,
            transfers_start,
            platform_capabilities,
            set_capture_protection,
            authenticate,
            is_sensitive_batch,
            is_sensitive,
            ucb_binary_path,
            ucb_is_initialized,
            daemon_is_managed,
            onboard,
            daemon_start,
            daemon_stop,
            daemon_restart,
            reveal_in_folder,
            check_for_update,
            install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Universal Clipboard GUI");

    // Kill a GUI-managed `ucb run` child when the app exits, so closing the
    // window never leaves an orphaned daemon we started. A background-service
    // daemon is not owned by us and is left running.
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(managed) = handle.try_state::<ManagedDaemon>() {
                stop_managed(&managed);
            }
        }
    });
}
