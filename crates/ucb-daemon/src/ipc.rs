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
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use ucb_core::{DeviceId, PROTOCOL_VERSION};
use ucb_sync::{SendProgress, SyncEngine};

#[cfg(unix)]
type IpcStream = UnixStream;
#[cfg(windows)]
type IpcStream = tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(unix)]
pub type Listener = UnixListener;
#[cfg(windows)]
pub type Listener = windows_pipe::PipeListener;

/// A command sent by a CLI client to the running daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
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
pub async fn serve(listener: Listener, engine: Arc<SyncEngine>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let engine = engine.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, engine).await {
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
pub async fn serve(mut listener: Listener, engine: Arc<SyncEngine>) {
    loop {
        match listener.accept().await {
            Ok(stream) => {
                let engine = engine.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, engine).await {
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

async fn handle_conn<S>(stream: S, engine: Arc<SyncEngine>) -> Result<()>
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
            let resp = status_snapshot(&engine);
            write_line(&mut write_half, &resp).await?;
        }
        Request::Send { path, to } => {
            handle_send(&engine, &path, to.as_deref(), &mut write_half).await?;
        }
    }
    write_half.flush().await?;
    Ok(())
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
