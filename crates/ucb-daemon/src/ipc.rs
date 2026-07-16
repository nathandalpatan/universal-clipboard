//! Status / send IPC between a running `ucb run` daemon and short-lived CLI
//! invocations (`ucb status`, `ucb send`) — UX-1.
//!
//! Transport: a unix domain socket at `<config-dir>/daemon.sock` (mode 0600)
//! on Unix; a named pipe derived from that same path on Windows, where unix
//! domain sockets aren't available. Framing: newline-delimited JSON. A
//! client writes exactly one [`Request`] line, then reads one or more
//! response lines until the server closes the connection:
//!
//! * `{"cmd":"status"}` → a single [`StatusResponse`] line.
//! * `{"cmd":"send","path":"...","to":null|"prefix"}` → zero or more
//!   [`SendUpdate::Progress`] lines, then exactly one terminal
//!   [`SendUpdate::Result`] or [`SendUpdate::Error`] line.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use ucb_core::{DeviceId, DeviceInfo, Platform, PROTOCOL_VERSION};
use ucb_crypto::Identity;
use ucb_history::{History, HistoryQuery};
use ucb_sync::{pair_listen, SendProgress, SyncEngine};

use crate::config::{Config, Paths};
use crate::pairing;

#[cfg(unix)]
type IpcStream = UnixStream;
#[cfg(windows)]
type IpcStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(unix)]
pub type Listener = UnixListener;
#[cfg(windows)]
pub type Listener = windows_pipe::PipeListener;

/// A command sent by a client (the CLI or the desktop GUI) to the running
/// daemon.
///
/// Serialized as newline-delimited JSON tagged by `cmd` in `snake_case`, e.g.
/// `{"cmd":"history_list","limit":50}`. The original `status`/`send` commands
/// keep their single-word tags; the GUI (HIST-3 / UX-2 / PAIR-2) adds the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Ask for a snapshot of peer connection state.
    Status,
    /// Send a file to a connected peer.
    Send {
        /// Absolute path of the file to send (the client canonicalizes it).
        path: String,
        /// Optional device-id prefix selecting the target peer; `None` uses the
        /// single connected peer.
        to: Option<String>,
    },
    /// List encrypted history entries (HIST-3). All filters are optional; a
    /// missing filter means "no restriction". Content is included in the reply.
    HistoryList {
        /// Case-sensitive substring match against entry text.
        search: Option<String>,
        /// Restrict to clips originating from this device-id prefix.
        device: Option<String>,
        /// Only return starred entries when `Some(true)`.
        starred: Option<bool>,
        /// Maximum rows to return (defaults to 50).
        limit: Option<usize>,
        /// Pagination cursor: only entries with `ts_ms` strictly less than this.
        before_ts: Option<u64>,
    },
    /// Star or unstar a history entry (HIST-3).
    HistoryStar { id: i64, starred: bool },
    /// Delete a single history entry (HIST-3).
    HistoryDelete { id: i64 },
    /// Read the persisted daemon configuration (`config.json`).
    ConfigGet,
    /// Change persisted configuration. Currently only `auto_file_sync` (FILE-1);
    /// the running engine does not hot-reload it, so the reply reports
    /// `restart_required: true`.
    ConfigSet { auto_file_sync: Option<bool> },
    /// Revoke a trusted peer by device-id prefix (PAIR-7), live in the engine.
    Revoke { prefix: String },
    /// Begin an on-screen pairing session (PAIR-2 GUI). Streams a `pairing`
    /// line (URI + QR), then a `code` line once a peer connects, then blocks for
    /// a [`Request::PairConfirm`] on the same connection, then a `result` line.
    PairListenStart,
    /// Accept or reject the pairing in progress on this connection (PAIR-2 GUI).
    /// Only meaningful after a [`Request::PairListenStart`] has streamed a
    /// `code` line on the same connection.
    PairConfirm { accept: bool },
}

/// One peer row in a [`StatusResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLine {
    pub id_short: String,
    pub name: String,
    pub connected: bool,
}

/// The daemon's reply to [`Request::Status`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub peers: Vec<PeerLine>,
    /// Daemon binary version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Wire protocol version (SYNC-6).
    pub protocol: u16,
}

/// A streamed update for [`Request::Send`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SendUpdate {
    /// Interim progress.
    Progress { sent: u64, total: u64, percent: u64 },
    /// Terminal success/failure reported by the receiver.
    Result {
        ok: bool,
        name: String,
        bytes: u64,
        detail: String,
    },
    /// Terminal local error (e.g. no such peer, IO failure).
    Error { message: String },
}

/// Everything an IPC connection may need to serve any command, assembled once
/// by `ucb run` and shared (behind an `Arc`) across all connections.
///
/// The daemon stays the single engine process: the GUI is a thin frontend that
/// issues these commands over the socket. History and pairing need more than the
/// engine handle, so they are bundled here.
pub struct IpcContext {
    /// The running sync engine (status, send, revoke).
    pub engine: Arc<SyncEngine>,
    /// The encrypted history store, when history is enabled (HIST-3).
    pub history: Option<Arc<History>>,
    /// Filesystem layout (config file for config get/set, allowlist for pairing).
    pub paths: Paths,
    /// This device's identity, used to run the pairing handshake (PAIR-2).
    pub identity: Arc<Identity>,
    /// This device's display name, sent in the pairing `Hello`.
    pub device_name: String,
    /// This device's platform, sent in the pairing `Hello`.
    pub platform: Platform,
    /// Guards "one pairing at a time": set while a `pair_listen_start` is live so
    /// a concurrent one is rejected.
    pairing_active: Arc<AtomicBool>,
}

impl IpcContext {
    /// Build the shared IPC context for `ucb run`.
    pub fn new(
        engine: Arc<SyncEngine>,
        history: Option<Arc<History>>,
        paths: Paths,
        identity: Arc<Identity>,
        device_name: String,
        platform: Platform,
    ) -> Self {
        Self {
            engine,
            history,
            paths,
            identity,
            device_name,
            platform,
            pairing_active: Arc::new(AtomicBool::new(false)),
        }
    }
}

// ---------------------------------------------------------------------------
// Server (runs inside `ucb run`)
// ---------------------------------------------------------------------------

/// Bind the IPC socket, replacing any stale file, and set it to mode 0600.
#[cfg(unix)]
pub fn bind(socket_path: &Path) -> Result<Listener> {
    // A leftover socket from a previous run would make bind() fail with
    // EADDRINUSE; remove it first (it is safe — we hold the config dir).
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding IPC socket at {}", socket_path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing IPC socket at {}", socket_path.display()))?;
    Ok(listener)
}

/// Bind the IPC named pipe (Windows has no unix domain sockets).
#[cfg(windows)]
pub fn bind(socket_path: &Path) -> Result<Listener> {
    Listener::bind(socket_path)
}

/// Accept and serve IPC connections until the listener is dropped. Each
/// connection is handled on its own task.
#[cfg(unix)]
pub async fn serve(listener: Listener, ctx: Arc<IpcContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, ctx).await {
                        tracing::debug!(error = %e, "IPC connection ended with error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "IPC accept failed");
                return;
            }
        }
    }
}

/// Accept and serve IPC connections until the listener stops producing new
/// pipe instances. Each connection is handled on its own task.
#[cfg(windows)]
pub async fn serve(mut listener: Listener, ctx: Arc<IpcContext>) {
    loop {
        match listener.accept().await {
            Ok(stream) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, ctx).await {
                        tracing::debug!(error = %e, "IPC connection ended with error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "IPC accept failed");
                return;
            }
        }
    }
}

async fn handle_conn<S>(stream: S, ctx: Arc<IpcContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(()); // client hung up without a request
    }
    let request: Request = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing IPC request: {}", line.trim()))?;

    match request {
        Request::Status => {
            let resp = status_snapshot(&ctx.engine);
            write_line(&mut write_half, &resp).await?;
        }
        Request::Send { path, to } => {
            handle_send(&ctx.engine, &path, to.as_deref(), &mut write_half).await?;
        }
        Request::HistoryList {
            search,
            device,
            starred,
            limit,
            before_ts,
        } => {
            handle_history_list(&ctx, search, device, starred, limit, before_ts, &mut write_half)
                .await?;
        }
        Request::HistoryStar { id, starred } => {
            let ok = match &ctx.history {
                Some(h) => h.set_starred(id, starred).unwrap_or(false),
                None => false,
            };
            write_line(&mut write_half, &serde_json::json!({ "ok": ok })).await?;
        }
        Request::HistoryDelete { id } => {
            let ok = match &ctx.history {
                Some(h) => h.delete(id).unwrap_or(false),
                None => false,
            };
            write_line(&mut write_half, &serde_json::json!({ "ok": ok })).await?;
        }
        Request::ConfigGet => {
            let resp = match Config::load(&ctx.paths) {
                Ok(cfg) => serde_json::to_value(&cfg).unwrap_or_else(|_| serde_json::json!({})),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            };
            write_line(&mut write_half, &resp).await?;
        }
        Request::ConfigSet { auto_file_sync } => {
            let resp = handle_config_set(&ctx, auto_file_sync);
            write_line(&mut write_half, &resp).await?;
        }
        Request::Revoke { prefix } => {
            let resp = match ctx.engine.revoke_prefix(&prefix) {
                Some((id, name)) => {
                    serde_json::json!({ "ok": true, "id": id.to_string(), "name": name })
                }
                None => serde_json::json!({
                    "ok": false,
                    "detail": format!("no unique trusted device matches prefix {prefix:?}")
                }),
            };
            write_line(&mut write_half, &resp).await?;
        }
        Request::PairListenStart => {
            handle_pair_listen(&ctx, &mut reader, &mut write_half).await?;
        }
        Request::PairConfirm { .. } => {
            write_line(
                &mut write_half,
                &serde_json::json!({
                    "type": "error",
                    "message": "pair_confirm is only valid after pair_listen_start on the same connection"
                }),
            )
            .await?;
        }
    }
    write_half.flush().await?;
    Ok(())
}

/// Persist a `config_set` change and report the hot-reload limitation honestly.
///
/// `ucb run` reads `config.json` once at startup and does not watch it, so a
/// change here only takes effect on the next daemon start — surfaced to the
/// caller as `restart_required: true`.
fn handle_config_set(ctx: &IpcContext, auto_file_sync: Option<bool>) -> serde_json::Value {
    let mut config = match Config::load(&ctx.paths) {
        Ok(c) => c,
        Err(e) => return serde_json::json!({ "ok": false, "detail": e.to_string() }),
    };
    if let Some(v) = auto_file_sync {
        config.auto_file_sync = v;
    }
    match config.save(&ctx.paths) {
        Ok(()) => serde_json::json!({ "ok": true, "restart_required": true }),
        Err(e) => serde_json::json!({ "ok": false, "detail": e.to_string() }),
    }
}

/// Serve a `history_list` query, mirroring the CLI's device-prefix filtering:
/// the store filters by full origin id only, so a device *prefix* is applied in
/// Rust after over-fetching. Emits a single `{"entries":[...]}` line.
async fn handle_history_list<W>(
    ctx: &IpcContext,
    search: Option<String>,
    device: Option<String>,
    starred: Option<bool>,
    limit: Option<usize>,
    before_ts: Option<u64>,
    out: &mut W,
) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let Some(history) = &ctx.history else {
        write_line(out, &serde_json::json!({ "entries": [], "history": false })).await?;
        return Ok(());
    };

    let want = limit.unwrap_or(ucb_history::DEFAULT_LIMIT);
    let query = HistoryQuery {
        text_search: search,
        origin: None,
        starred_only: starred.unwrap_or(false),
        // Over-fetch when narrowing by a device prefix (filtered below).
        limit: if device.is_some() { 100_000 } else { want },
        before_ts,
    };
    let entries = match history.list(query) {
        Ok(mut entries) => {
            if let Some(prefix) = &device {
                entries.retain(|e| e.origin_id.starts_with(prefix));
                entries.truncate(want);
            }
            entries
        }
        Err(e) => {
            write_line(out, &serde_json::json!({ "entries": [], "error": e.to_string() })).await?;
            return Ok(());
        }
    };
    write_line(out, &serde_json::json!({ "entries": entries })).await?;
    Ok(())
}

/// Reset the "pairing in progress" flag when the pairing handler returns, so a
/// panic or early error never wedges the single-pairing slot shut.
struct PairingGuard(Arc<AtomicBool>);
impl Drop for PairingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Drive an on-screen pairing session over this one IPC connection (PAIR-2 GUI).
///
/// Because `ucb run` already owns the configured sync port, pairing binds a
/// *fresh ephemeral* TCP listener and advertises that endpoint in the URI/QR —
/// the peer dials it with `ucb pair --connect ucb://ip:port`. Only one pairing
/// runs at a time; a concurrent request is rejected.
///
/// Bridge: `pair_listen`'s confirmation callback is synchronous, so it hands the
/// 6-digit code to this async task over a channel and blocks (via
/// `block_in_place`) on the user's decision, which arrives as a
/// [`Request::PairConfirm`] line on this same connection.
async fn handle_pair_listen<R, W>(ctx: &IpcContext, reader: &mut R, out: &mut W) -> Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // One pairing at a time (PAIR-2): claim the slot or reject.
    if ctx
        .pairing_active
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        write_line(
            out,
            &serde_json::json!({
                "type": "error",
                "message": "another pairing is already in progress"
            }),
        )
        .await?;
        return Ok(());
    }
    let _guard = PairingGuard(ctx.pairing_active.clone());

    // Bind a fresh ephemeral listener (the sync port is taken by the engine).
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", 0)).await {
        Ok(l) => l,
        Err(e) => {
            write_line(
                out,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("could not open a pairing listener: {e}")
                }),
            )
            .await?;
            return Ok(());
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let host = pairing::primary_local_ipv4()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let uri = pairing::format_pairing_uri(&host, port);
    let qr_text = pairing::render_qr(&uri).unwrap_or_default();

    write_line(
        out,
        &serde_json::json!({ "type": "pairing", "uri": uri, "qr_text": qr_text }),
    )
    .await?;
    out.flush().await?;

    // Bridge channels: code out to us, the user's decision back to the callback.
    let (code_tx, mut code_rx) = mpsc::unbounded_channel::<(String, DeviceInfo)>();
    let (decision_tx, decision_rx) = tokio::sync::oneshot::channel::<bool>();
    let mut decision_rx = Some(decision_rx);
    let confirm = move |code: &str, peer: &DeviceInfo| -> bool {
        if code_tx.send((code.to_string(), peer.clone())).is_err() {
            return false; // the IPC connection went away
        }
        match decision_rx.take() {
            Some(rx) => tokio::task::block_in_place(|| rx.blocking_recv()).unwrap_or(false),
            None => false,
        }
    };

    let identity = ctx.identity.clone();
    let allowlist_path = ctx.paths.trusted_file.clone();
    let device_name = ctx.device_name.clone();
    let platform = ctx.platform;
    let task = tokio::spawn(async move {
        pair_listen(
            listener,
            identity.as_ref(),
            allowlist_path,
            &device_name,
            platform,
            confirm,
        )
        .await
    });

    // Wait for the handshake to produce a verification code (or fail first).
    match code_rx.recv().await {
        Some((code, device)) => {
            write_line(
                out,
                &serde_json::json!({
                    "type": "code",
                    "code": code,
                    "device": {
                        "id": device.id.to_string(),
                        "name": device.name,
                        "platform": device.platform,
                    }
                }),
            )
            .await?;
            out.flush().await?;

            // Read the user's decision (PairConfirm) on this same connection.
            let accept = read_pair_confirm(reader).await;
            let _ = decision_tx.send(accept);
        }
        None => {
            // The callback was never reached — the handshake failed before a
            // code could be shown. Fall through to report the task's error.
        }
    }

    let result = match task.await {
        Ok(Ok(dev)) => serde_json::json!({ "type": "result", "ok": true, "name": dev.name }),
        Ok(Err(e)) => {
            serde_json::json!({ "type": "result", "ok": false, "message": e.to_string() })
        }
        Err(e) => serde_json::json!({
            "type": "result", "ok": false, "message": format!("pairing task failed: {e}")
        }),
    };
    write_line(out, &result).await?;
    Ok(())
}

/// Read one line and interpret it as a [`Request::PairConfirm`]. A closed
/// connection, a read error, or anything that is not `pair_confirm` counts as a
/// rejection (fail-safe: never trust a peer without an explicit `accept:true`).
async fn read_pair_confirm<R>(reader: &mut R) -> bool
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => false,
        Ok(_) => matches!(
            serde_json::from_str::<Request>(line.trim()),
            Ok(Request::PairConfirm { accept: true })
        ),
    }
}

/// Build a [`StatusResponse`] from the engine's current peer view.
pub fn status_snapshot(engine: &SyncEngine) -> StatusResponse {
    let peers = engine
        .status()
        .into_iter()
        .map(|p| PeerLine {
            id_short: p.device_id.short(),
            name: p.name,
            connected: p.connected,
        })
        .collect();
    StatusResponse {
        peers,
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol: PROTOCOL_VERSION,
    }
}

async fn handle_send<W>(
    engine: &Arc<SyncEngine>,
    path: &str,
    to: Option<&str>,
    out: &mut W,
) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    // Resolve an optional device-id prefix against the *connected* peers.
    let target = match to {
        None => None,
        Some(prefix) => match resolve_target(engine, prefix) {
            Ok(id) => Some(id),
            Err(msg) => {
                write_line(out, &SendUpdate::Error { message: msg }).await?;
                return Ok(());
            }
        },
    };

    let (prog_tx, mut prog_rx) = mpsc::channel::<SendProgress>(64);
    let engine2 = engine.clone();
    let path_owned = path.to_string();
    let send_task =
        tokio::spawn(async move { engine2.send_file(&path_owned, target, Some(prog_tx)).await });

    // Relay progress until the sender drops its progress channel.
    while let Some(p) = prog_rx.recv().await {
        let percent = p
            .sent
            .checked_mul(100)
            .and_then(|n| n.checked_div(p.total))
            .unwrap_or(0);
        write_line(
            out,
            &SendUpdate::Progress {
                sent: p.sent,
                total: p.total,
                percent,
            },
        )
        .await?;
    }

    let terminal = match send_task.await {
        Ok(Ok(report)) => SendUpdate::Result {
            ok: report.ok,
            name: report.name,
            bytes: report.bytes,
            detail: report.detail,
        },
        Ok(Err(e)) => SendUpdate::Error {
            message: e.to_string(),
        },
        Err(e) => SendUpdate::Error {
            message: format!("send task failed: {e}"),
        },
    };
    write_line(out, &terminal).await?;
    Ok(())
}

/// Resolve a device-id prefix to a connected peer's [`DeviceId`], or a
/// human-readable error listing the connected peers.
fn resolve_target(engine: &SyncEngine, prefix: &str) -> std::result::Result<DeviceId, String> {
    let peers = engine.status();
    let connected: Vec<_> = peers.iter().filter(|p| p.connected).collect();
    let matches: Vec<_> = connected
        .iter()
        .filter(|p| p.device_id.to_string().starts_with(prefix) || p.device_id.short().starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [only] => Ok(only.device_id),
        [] => Err(format!(
            "no connected peer matches {prefix:?}; connected: [{}]",
            connected
                .iter()
                .map(|p| format!("{} ({})", p.device_id.short(), p.name))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => Err(format!("prefix {prefix:?} matches multiple connected peers")),
    }
}

async fn write_line<W, T>(out: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let mut buf = serde_json::to_vec(value)?;
    buf.push(b'\n');
    out.write_all(&buf).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client (used by `ucb status` / `ucb send`)
// ---------------------------------------------------------------------------

/// Connect to the daemon socket, translating a missing/refused socket into a
/// clear "is the daemon running?" error.
#[cfg(unix)]
async fn connect(socket_path: &Path) -> Result<IpcStream> {
    UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow!(
            "could not reach the daemon at {} ({e}). Is `ucb run` active?",
            socket_path.display()
        )
    })
}

/// Connect to the daemon's named pipe, translating a missing/refused pipe
/// into a clear "is the daemon running?" error.
#[cfg(windows)]
async fn connect(socket_path: &Path) -> Result<IpcStream> {
    windows_pipe::connect(socket_path).await.map_err(|e| {
        anyhow!(
            "could not reach the daemon via {} ({e}). Is `ucb run` active?",
            socket_path.display()
        )
    })
}

/// Ask the running daemon for a status snapshot.
pub async fn request_status(socket_path: &Path) -> Result<StatusResponse> {
    let stream = connect(socket_path).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    write_half.write_all(b"{\"cmd\":\"status\"}\n").await?;
    write_half.flush().await?;
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Err(anyhow!("daemon closed the connection without a reply"));
    }
    Ok(serde_json::from_str(line.trim())?)
}

/// Ask the running daemon to send a file, invoking `on_update` for each
/// streamed update. Returns the terminal update.
pub async fn request_send(
    socket_path: &Path,
    path: &str,
    to: Option<&str>,
    mut on_update: impl FnMut(&SendUpdate),
) -> Result<SendUpdate> {
    let stream = connect(socket_path).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let req = Request::Send {
        path: path.to_string(),
        to: to.map(|s| s.to_string()),
    };
    let mut buf = serde_json::to_vec(&req)?;
    buf.push(b'\n');
    write_half.write_all(&buf).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut last: Option<SendUpdate> = None;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let update: SendUpdate = serde_json::from_str(line.trim())
            .with_context(|| format!("parsing daemon update: {}", line.trim()))?;
        on_update(&update);
        last = Some(update);
    }
    last.ok_or_else(|| anyhow!("daemon closed the connection without a result"))
}

// ---------------------------------------------------------------------------
// Windows transport: named pipes (no unix domain sockets on this platform).
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_pipe {
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    /// Derive a stable named-pipe path from the daemon's socket-file path, so
    /// sandboxed instances (distinct `--config-dir`, e.g. in tests) don't
    /// collide on a shared pipe name.
    fn pipe_name(socket_path: &Path) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        socket_path.hash(&mut hasher);
        format!(r"\\.\pipe\ucb-{:016x}", hasher.finish())
    }

    /// Server-side listener. A named pipe has no persistent "listening"
    /// handle the way a unix socket does: each instance serves exactly one
    /// client, so we keep one pending instance around and create the next
    /// one as soon as a client connects.
    pub struct PipeListener {
        name: String,
        next: Option<NamedPipeServer>,
    }

    impl PipeListener {
        pub fn bind(socket_path: &Path) -> Result<Self> {
            let name = pipe_name(socket_path);
            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
                .with_context(|| format!("binding IPC pipe at {name}"))?;
            Ok(Self {
                name,
                next: Some(first),
            })
        }

        pub async fn accept(&mut self) -> Result<NamedPipeServer> {
            let server = self
                .next
                .take()
                .ok_or_else(|| anyhow::anyhow!("IPC pipe listener exhausted"))?;
            server
                .connect()
                .await
                .context("accepting IPC pipe connection")?;
            // Line up the next instance before handing this one off, so a
            // client connecting immediately after doesn't race a missing pipe.
            self.next = Some(
                ServerOptions::new()
                    .create(&self.name)
                    .context("creating next IPC pipe instance")?,
            );
            Ok(server)
        }
    }

    /// Connect to the daemon's named pipe, retrying briefly on
    /// `ERROR_PIPE_BUSY` (all server instances are momentarily in use).
    pub async fn connect(socket_path: &Path) -> io::Result<NamedPipeClient> {
        const ERROR_PIPE_BUSY: i32 = 231;
        let name = pipe_name(socket_path);
        for attempt in 0..20 {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(client),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < 19 => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
}
