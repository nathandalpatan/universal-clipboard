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
async fn ipc_config_set(auto_file_sync: Option<bool>) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "cmd": "config_set", "auto_file_sync": auto_file_sync });
    send_request(req.to_string()).await
}

#[tauri::command]
async fn ipc_revoke(prefix: String) -> Result<serde_json::Value, String> {
    let req = serde_json::json!({ "cmd": "revoke", "prefix": prefix });
    send_request(req.to_string()).await
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

fn main() {
    tauri::Builder::default()
        .manage(PairState::default())
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
            pair_start,
            pair_confirm,
            pair_cancel,
            platform_capabilities,
            set_capture_protection,
            authenticate,
            is_sensitive_batch,
            is_sensitive,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Universal Clipboard GUI");
}
