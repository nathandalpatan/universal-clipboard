//! The sync engine (SYNC-1/3/6, SEC-3, DISC-4 reconnect).
//!
//! [`SyncEngine::start`] wires the clipboard, discovery and transport together
//! and drives three long-lived tasks:
//!
//! * **accept loop** — accepts inbound TCP, rate-limits per source IP (SEC-3),
//!   runs the Noise responder handshake, checks the allowlist, exchanges
//!   `Hello`, then runs a session.
//! * **local-clip loop** — stamps each local clipboard change into a
//!   [`ClipboardItem`] and broadcasts it to every connected session (SYNC-1).
//! * **discovery loop** — on `PeerEvent::Found` for a trusted peer, spawns a
//!   *connector* that dials and (DISC-4) reconnects with capped exponential
//!   backoff for as long as discovery reports the peer present.
//!
//! ## Dial direction
//!
//! To avoid two devices dialing each other simultaneously (which would create a
//! duplicate connection), only the device with the numerically smaller
//! [`DeviceId`] dials; the larger-id device waits to accept. This is a total,
//! symmetric rule so exactly one side connects.
//!
//! ## Conflict resolution (SYNC-3)
//!
//! A single shared `latest: Option<ClipboardItem>` records the most recently
//! applied clip. An incoming clip is written to the OS clipboard only if it
//! [`wins_over`](ucb_core::ClipboardItem::wins_over) `latest` (timestamp, then
//! device-id tiebreak); local copies always update `latest`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use ucb_clipboard::{ClipboardEvent, ClipboardWriter};
use ucb_core::{
    ClipboardItem, ClipboardPayload, DeviceId, DeviceInfo, Platform, WireMessage, PROTOCOL_VERSION,
};
use ucb_crypto::{
    check_clock_skew, handshake_initiator, handshake_responder, Identity, ReplayGuard, SecureChannel,
};
use ucb_discovery::PeerEvent;
use ucb_files::{cleanup_stale, RecvProgress, RecvTransfer, SendAction, SendTransfer};
use ucb_history::History;

use crate::allowlist::Allowlist;
use crate::error::{Error, Result};
use crate::now_ms;
use crate::queue::OfflineQueue;
use crate::rate_limit::TokenBucketLimiter;

/// Reconnect backoff ceiling (DISC-4).
const BACKOFF_CAP: Duration = Duration::from_secs(30);
/// Initial reconnect backoff (DISC-4).
const BACKOFF_START: Duration = Duration::from_secs(1);
/// Bound on a session's outbound queue; clipboard updates are last-write-wins,
/// so a full queue simply drops the stale update.
const OUTBOUND_QUEUE: usize = 64;
/// How often the engine re-reads `revoked.json` and re-broadcasts tombstones to
/// live peers (PAIR-7). Because `ucb revoke` runs as a separate process, live
/// revocation propagation has an up-to-this-interval lag.
const REVOCATION_RECHECK: Duration = Duration::from_secs(30);
/// Window in which inbound clips at session start are counted as "synced while
/// away" for the UX-4 receiver-side notice.
const SYNCED_AWAY_WINDOW: Duration = Duration::from_secs(5);

/// History retention (HIST-2): drop non-starred entries older than this.
const HISTORY_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How often the engine runs the history retention sweep (HIST-2). Also run once
/// at startup.
const HISTORY_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Age past which incomplete `*.part`/`*.meta.json` artifacts are reclaimed
/// (FILE-7).
const FILE_STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the engine reclaims stale file-transfer artifacts (FILE-7). Also
/// run once at startup.
const FILE_CLEANUP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// One thing to send out on a session: a live/queued clip, a revocation
/// broadcast (PAIR-7), or a raw pre-built wire message (used for file-transfer
/// offers and chunks, FILE-4).
#[derive(Clone)]
enum Outbound {
    Clip(ClipboardItem),
    Revoke(DeviceId),
    Raw(WireMessage),
}

/// Progress of an outbound file transfer (FILE-4), for the CLI/IPC to surface.
#[derive(Clone, Copy, Debug)]
pub struct SendProgress {
    pub transfer_id: u64,
    pub sent: u64,
    pub total: u64,
}

/// Final outcome of an outbound file transfer (FILE-4).
#[derive(Clone, Debug)]
pub struct SendReport {
    pub transfer_id: u64,
    pub name: String,
    pub bytes: u64,
    /// True only when the receiver confirmed a complete, hash-verified file.
    pub ok: bool,
    /// Human-readable detail (rejection reason, receiver error, or empty).
    pub detail: String,
}

/// A snapshot of one trusted peer's connection state, for the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    pub device_id: DeviceId,
    pub name: String,
    pub connected: bool,
}

/// Static configuration for [`SyncEngine::start`].
pub struct EngineConfig {
    /// This device's long-term identity (moved into the engine).
    pub identity: Identity,
    /// Path to the `trusted.json` allowlist.
    pub allowlist_path: std::path::PathBuf,
    /// This device's display name, sent in `Hello`.
    pub device_name: String,
    /// This device's platform, sent in `Hello`.
    pub platform: Platform,
    /// Manually configured always-present peer endpoints, each `"ip:port"`
    /// (DISC-3). Dialed with the reconnect backoff regardless of device-id
    /// ordering; trust is still verified by the handshake + allowlist.
    pub static_peers: Vec<String>,
    /// Optional encrypted history store (HIST-1/2/3). When present, every applied
    /// clip (local broadcast and remote-applied) is recorded, and a retention
    /// sweep runs at startup and hourly. `None` disables history entirely.
    pub history: Option<Arc<History>>,
    /// Directory where inbound file transfers are stored (FILE-6). Created on
    /// demand; also periodically swept for stale artifacts (FILE-7).
    pub received_dir: PathBuf,
    /// Reject inbound file offers larger than this many bytes (FILE-6 policy).
    /// `None` accepts any size.
    pub max_file_bytes: Option<u64>,
    /// FILE-1: when `true`, copying files locally automatically sends them to
    /// every connected peer. Default `false` — copying files on a desktop is a
    /// common local action and must not silently start network transfers; this
    /// is opt-in.
    pub auto_file_sync: bool,
    /// FILE-1: per-file size cap for automatic file sync. Files larger than this
    /// are skipped (with an info log) rather than auto-sent. Ignored unless
    /// `auto_file_sync` is `true`.
    pub max_auto_file_bytes: u64,
}

/// Default per-file cap for automatic file sync (FILE-1): 100 MiB.
pub const DEFAULT_MAX_AUTO_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// A live session's outbound handle.
struct SessionEntry {
    /// Distinguishes concurrent sessions for the same peer so a closing session
    /// never deregisters a newer one.
    token: u64,
    tx: mpsc::Sender<Outbound>,
}

/// The last-known network endpoint for a discovered peer.
#[derive(Clone)]
struct Endpoint {
    addrs: Vec<IpAddr>,
    port: u16,
}

/// Shared engine state, held behind an `Arc` and used from every task.
struct Shared {
    identity: Arc<Identity>,
    self_id: DeviceId,
    name: String,
    platform: Platform,
    writer: ClipboardWriter,
    /// Path to `trusted.json`; re-read on the periodic tombstone re-check so the
    /// running engine picks up an out-of-process `ucb revoke` (PAIR-7).
    allowlist_path: std::path::PathBuf,
    allowlist: Mutex<Allowlist>,
    /// Per-peer offline queue (SYNC-5), persisted next to the allowlist.
    queue: Mutex<OfflineQueue>,
    latest: Mutex<Option<ClipboardItem>>,
    sessions: Mutex<HashMap<DeviceId, SessionEntry>>,
    peers: Mutex<HashMap<DeviceId, Endpoint>>,
    /// Trusted peers we are actively (re)connecting to; the flag is cleared on
    /// `PeerLost` to stop the connector.
    connectors: Mutex<HashMap<DeviceId, Arc<AtomicBool>>>,
    rate: Mutex<TokenBucketLimiter>,
    token_ctr: AtomicU64,
    /// HIST-1/2/3: optional encrypted history store.
    history: Option<Arc<History>>,
    /// FILE-6: destination directory for inbound file transfers.
    received_dir: PathBuf,
    /// FILE-6: inbound file offers larger than this are rejected.
    max_file_bytes: Option<u64>,
    /// FILE-1: auto-send locally-copied files to connected peers (opt-in).
    auto_file_sync: bool,
    /// FILE-1: per-file cap for auto file sync.
    max_auto_file_bytes: u64,
    /// FILE-4: routes inbound `FileAccept/FileReject/FileDone` for an outbound
    /// transfer (keyed by `transfer_id`) to its running send-pump task.
    send_routes: Mutex<HashMap<u64, mpsc::Sender<WireMessage>>>,
}

/// The running sync engine. Holds its background tasks; dropping it aborts them.
pub struct SyncEngine {
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl SyncEngine {
    /// Start the engine. Spawns background tasks and returns immediately.
    ///
    /// `listener` must already be bound (use `TcpListener::bind` on the desired
    /// port); the clipboard `writer`/`clip_rx` and discovery `disc_rx` come from
    /// `ucb-clipboard` and `ucb-discovery` respectively. The allowlist is loaded
    /// once at start; re-pair while stopped to change trust.
    pub async fn start(
        config: EngineConfig,
        listener: TcpListener,
        writer: ClipboardWriter,
        clip_rx: mpsc::Receiver<ClipboardEvent>,
        disc_rx: mpsc::Receiver<PeerEvent>,
    ) -> Result<Self> {
        let identity = Arc::new(config.identity);
        let self_id = identity.device_id();
        let allowlist = Allowlist::load(&config.allowlist_path)?;
        // SYNC-5: the offline queue lives next to the allowlist (`queue.json`).
        let queue_path = config.allowlist_path.with_file_name("queue.json");
        let queue = OfflineQueue::load(queue_path)?;

        let shared = Arc::new(Shared {
            identity,
            self_id,
            name: config.device_name,
            platform: config.platform,
            writer,
            allowlist_path: config.allowlist_path,
            allowlist: Mutex::new(allowlist),
            queue: Mutex::new(queue),
            latest: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            connectors: Mutex::new(HashMap::new()),
            rate: Mutex::new(TokenBucketLimiter::per_minute_5()),
            token_ctr: AtomicU64::new(0),
            history: config.history,
            received_dir: config.received_dir,
            max_file_bytes: config.max_file_bytes,
            auto_file_sync: config.auto_file_sync,
            max_auto_file_bytes: config.max_auto_file_bytes,
            send_routes: Mutex::new(HashMap::new()),
        });

        let mut tasks = vec![
            tokio::spawn(shared.clone().accept_loop(listener)),
            tokio::spawn(shared.clone().local_clip_loop(clip_rx)),
            tokio::spawn(shared.clone().discovery_loop(disc_rx)),
            tokio::spawn(shared.clone().revocation_loop()),
            // FILE-7: reclaim stale inbound-transfer artifacts at start + every 6h.
            tokio::spawn(shared.clone().file_cleanup_loop()),
        ];

        // HIST-2: only run the retention sweep when history is enabled.
        if shared.history.is_some() {
            tasks.push(tokio::spawn(shared.clone().history_sweep_loop()));
        }

        // DISC-3: one always-present connector per configured static peer.
        for addr in config.static_peers {
            tasks.push(tokio::spawn(shared.clone().static_connector(addr)));
        }

        Ok(Self { shared, tasks })
    }

    /// This device's id.
    pub fn device_id(&self) -> DeviceId {
        self.shared.self_id
    }

    /// A snapshot of every trusted peer and whether a session is currently live.
    pub fn status(&self) -> Vec<PeerStatus> {
        let allowlist = self.shared.allowlist.lock().unwrap();
        let sessions = self.shared.sessions.lock().unwrap();
        allowlist
            .list()
            .into_iter()
            .map(|d| PeerStatus {
                device_id: d.device_id,
                connected: sessions.contains_key(&d.device_id),
                name: d.name,
            })
            .collect()
    }

    /// Revoke a trusted peer by device-id hex *prefix* (PAIR-7), live.
    ///
    /// Resolves the prefix against the current allowlist (must match exactly one
    /// trusted device), removes it from the allowlist, records a tombstone,
    /// drops any live session, and broadcasts the revocation to connected peers
    /// — all in the running engine, so no restart or disk re-read lag is
    /// involved. Returns the revoked device's id and name, or `None` if no
    /// unique trusted device matches the prefix.
    ///
    /// Used by the daemon IPC `revoke` command (the GUI's Devices view); the
    /// out-of-process `ucb revoke` CLI writes the same tombstone to disk and the
    /// engine converges on it via the periodic re-check.
    pub fn revoke_prefix(&self, prefix: &str) -> Option<(DeviceId, String)> {
        let (id, name) = {
            let allowlist = self.shared.allowlist.lock().unwrap();
            let id = allowlist.resolve_prefix(prefix)?;
            let name = allowlist.name_of(&id).unwrap_or_default();
            (id, name)
        };
        self.shared.apply_revocation(id);
        self.shared.broadcast_revocations(&[id]);
        Some((id, name))
    }

    /// Send a file to a connected peer (FILE-1/4). With `target = Some(id)` the
    /// file goes to that peer (error if it is not connected); with `None` it goes
    /// to the single connected peer, erroring (and listing peers) when zero or
    /// more than one are connected. `progress` optionally receives per-chunk
    /// updates. Resolves when the receiver reports completion, rejection, or the
    /// session drops.
    pub async fn send_file(
        &self,
        path: impl AsRef<Path>,
        target: Option<DeviceId>,
        progress: Option<mpsc::Sender<SendProgress>>,
    ) -> Result<SendReport> {
        self.shared
            .clone()
            .send_file(path.as_ref().to_path_buf(), target, progress)
            .await
    }
}

impl Drop for SyncEngine {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Shared {
    fn next_token(&self) -> u64 {
        self.token_ctr.fetch_add(1, Ordering::Relaxed)
    }

    fn self_info(&self) -> DeviceInfo {
        DeviceInfo {
            id: self.self_id,
            name: self.name.clone(),
            platform: self.platform,
        }
    }

    // --- history (HIST-1/2/3) ---------------------------------------------

    /// Fire-and-forget record of an applied clip into the history store. Runs on
    /// a blocking thread (rusqlite is synchronous); a failure is logged, never
    /// propagated. No-op when history is disabled.
    fn record_history(&self, item: &ClipboardItem, origin_name: &str) {
        let Some(history) = self.history.clone() else {
            return;
        };
        let item = item.clone();
        let origin_name = origin_name.to_string();
        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || history.record(&item, &origin_name)).await;
            match res {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "failed to record clip in history"),
                Err(e) => tracing::warn!(error = %e, "history record task panicked"),
            }
        });
    }

    /// HIST-2: sweep expired history at startup, then every hour. Only spawned
    /// when history is enabled.
    async fn history_sweep_loop(self: Arc<Self>) {
        loop {
            if let Some(history) = self.history.clone() {
                let res =
                    tokio::task::spawn_blocking(move || history.sweep(HISTORY_RETENTION, now_ms()))
                        .await;
                match res {
                    Ok(Ok(n)) if n > 0 => tracing::info!(removed = n, "history retention sweep"),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::warn!(error = %e, "history sweep failed"),
                    Err(e) => tracing::warn!(error = %e, "history sweep task panicked"),
                }
            }
            tokio::time::sleep(HISTORY_SWEEP_INTERVAL).await;
        }
    }

    // --- file-transfer cleanup (FILE-7) -----------------------------------

    /// FILE-7: reclaim stale `.part`/`.meta.json` artifacts at startup, then
    /// every 6h. A missing `received_dir` is treated as empty.
    async fn file_cleanup_loop(self: Arc<Self>) {
        loop {
            match cleanup_stale(&self.received_dir, FILE_STALE_AGE).await {
                Ok(report) if report.removed > 0 => tracing::info!(
                    removed = report.removed,
                    bytes = report.bytes_freed,
                    "reclaimed stale file-transfer artifacts"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "file-transfer cleanup failed"),
            }
            tokio::time::sleep(FILE_CLEANUP_INTERVAL).await;
        }
    }

    // --- file-transfer sender (FILE-1/4) ----------------------------------

    /// Resolve a target session, offer `path`, and drive the send to completion.
    async fn send_file(
        self: Arc<Self>,
        path: PathBuf,
        target: Option<DeviceId>,
        progress: Option<mpsc::Sender<SendProgress>>,
    ) -> Result<SendReport> {
        // Resolve which connected peer receives the file.
        let out_tx = {
            let sessions = self.sessions.lock().unwrap();
            match target {
                Some(id) => sessions
                    .get(&id)
                    .map(|e| e.tx.clone())
                    .ok_or_else(|| Error::Other(format!("peer {} is not connected", id.short())))?,
                None => {
                    let mut iter = sessions.iter();
                    match (iter.next(), iter.next()) {
                        (Some((_, entry)), None) => entry.tx.clone(),
                        (None, _) => {
                            return Err(Error::Other(
                                "no connected peers to send to".to_string(),
                            ))
                        }
                        _ => {
                            let ids: Vec<String> =
                                sessions.keys().map(|id| id.short()).collect();
                            return Err(Error::Other(format!(
                                "multiple peers connected ({}); pass a target",
                                ids.join(", ")
                            )));
                        }
                    }
                }
            }
        };

        let (transfer, offer) = SendTransfer::offer(&path)
            .await
            .map_err(|e| Error::Other(format!("preparing file offer: {e}")))?;
        let transfer_id = transfer.transfer_id();

        // Register a route so inbound FileAccept/FileReject/FileDone reach the pump.
        let (inbound_tx, inbound_rx) = mpsc::channel::<WireMessage>(32);
        self.send_routes
            .lock()
            .unwrap()
            .insert(transfer_id, inbound_tx);

        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(send_pump(
            transfer, offer, out_tx, inbound_rx, progress, result_tx,
        ));

        let report = result_rx
            .await
            .map_err(|_| Error::Other("file send task ended without a result".to_string()));
        self.send_routes.lock().unwrap().remove(&transfer_id);
        report
    }

    // --- accept side -------------------------------------------------------

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let allowed = self.rate.lock().unwrap().allow(addr.ip());
                    if !allowed {
                        tracing::warn!(peer = %addr.ip(), "handshake rate-limited (SEC-3)");
                        continue;
                    }
                    let me = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = me.serve_inbound(stream).await {
                            tracing::debug!(error = %e, "inbound connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn serve_inbound<S>(self: Arc<Self>, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut chan = handshake_responder(stream, self.identity.as_ref()).await?;
        let remote_id = chan.remote_device_id();

        if !self.is_trusted(&remote_id, chan.remote_static_pubkey()) {
            tracing::warn!(peer = %remote_id.short(), "rejecting untrusted inbound peer");
            return Ok(()); // drop the connection
        }

        let peer = self.hello_exchange(&mut chan).await?;
        self.run_session(chan, remote_id, peer.name).await;
        Ok(())
    }

    // --- dial side ---------------------------------------------------------

    async fn dial_and_run(self: Arc<Self>, peer_id: DeviceId) -> Result<()> {
        let endpoint = self
            .peers
            .lock()
            .unwrap()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| Error::Other("no known endpoint for peer".into()))?;

        let stream = connect_any(&endpoint).await?;
        let mut chan = handshake_initiator(stream, self.identity.as_ref()).await?;
        let remote_id = chan.remote_device_id();

        if remote_id != peer_id {
            return Err(Error::Other("dialed the wrong device".into()));
        }
        if !self.is_trusted(&remote_id, chan.remote_static_pubkey()) {
            return Err(Error::UntrustedPeer(remote_id));
        }

        let peer = self.hello_exchange(&mut chan).await?;
        self.run_session(chan, remote_id, peer.name).await;
        Ok(())
    }

    /// The connector task (DISC-4): dial `peer_id`, run the session, and on drop
    /// reconnect with capped exponential backoff until the peer is lost.
    async fn connector(self: Arc<Self>, peer_id: DeviceId, present: Arc<AtomicBool>) {
        let mut backoff = BACKOFF_START;
        while present.load(Ordering::Relaxed) {
            match self.clone().dial_and_run(peer_id).await {
                Ok(()) => {
                    // Clean session end; reset backoff for a prompt reconnect.
                    backoff = BACKOFF_START;
                }
                Err(e) => {
                    tracing::debug!(peer = %peer_id.short(), error = %e, "dial attempt failed");
                }
            }
            if !present.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_CAP);
        }
        self.connectors.lock().unwrap().remove(&peer_id);
        tracing::debug!(peer = %peer_id.short(), "connector stopped (peer lost)");
    }

    // --- static peers (DISC-3) --------------------------------------------

    /// Dial a static peer at `addr`, verify trust, and run one session. Unlike
    /// discovery-driven dialing this ignores the device-id ordering rule (the
    /// static peer is always dialed); identity is verified by the handshake +
    /// allowlist exactly as usual.
    async fn dial_addr_and_run(self: Arc<Self>, addr: String) -> Result<()> {
        let stream = TcpStream::connect(&addr).await?;
        let mut chan = handshake_initiator(stream, self.identity.as_ref()).await?;
        let remote_id = chan.remote_device_id();

        if !self.is_trusted(&remote_id, chan.remote_static_pubkey()) {
            return Err(Error::UntrustedPeer(remote_id));
        }
        // Avoid a duplicate session if discovery already connected this peer.
        if self.sessions.lock().unwrap().contains_key(&remote_id) {
            return Ok(());
        }

        let peer = self.hello_exchange(&mut chan).await?;
        self.run_session(chan, remote_id, peer.name).await;
        Ok(())
    }

    /// A static-peer connector (DISC-3): dial `addr` forever with capped
    /// exponential backoff. A static peer is treated as always present, so
    /// (unlike [`connector`](Self::connector)) there is no `PeerLost` to stop it.
    async fn static_connector(self: Arc<Self>, addr: String) {
        let mut backoff = BACKOFF_START;
        loop {
            match self.clone().dial_addr_and_run(addr.clone()).await {
                Ok(()) => backoff = BACKOFF_START,
                Err(e) => {
                    tracing::debug!(peer = %addr, error = %e, "static dial attempt failed");
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_CAP);
        }
    }

    // --- shared session machinery -----------------------------------------

    /// Send our `Hello` and read the peer's, enforcing the version check
    /// (SYNC-6). On mismatch, send `Reject` and return an error.
    async fn hello_exchange<S>(&self, chan: &mut SecureChannel<S>) -> Result<DeviceInfo>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        chan.send(&WireMessage::Hello {
            version: PROTOCOL_VERSION,
            device: self.self_info(),
        })
        .await?;

        match chan.recv().await? {
            WireMessage::Hello { version, device } => {
                if version != PROTOCOL_VERSION {
                    let _ = chan
                        .send(&WireMessage::Reject {
                            reason: format!(
                                "protocol version {version} unsupported (want {PROTOCOL_VERSION})"
                            ),
                        })
                        .await;
                    return Err(Error::VersionMismatch {
                        local: PROTOCOL_VERSION,
                        remote: version,
                    });
                }
                Ok(device)
            }
            WireMessage::Reject { reason } => Err(Error::Rejected(reason)),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Run one established session to completion: fan clipboard broadcasts out
    /// and apply inbound clips. Registers the session on entry and deregisters
    /// on exit.
    async fn run_session<S>(
        self: Arc<Self>,
        mut chan: SecureChannel<S>,
        peer_id: DeviceId,
        peer_name: String,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let token = self.next_token();
        let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(OUTBOUND_QUEUE);
        self.sessions
            .lock()
            .unwrap()
            .insert(peer_id, SessionEntry { token, tx: out_tx });
        tracing::info!(peer = %peer_id.short(), name = %peer_name, "session established");

        let mut guard = ReplayGuard::new();
        let mut out_seq: u64 = 0;
        // FILE-6: inbound file transfers in flight for this session.
        let mut recvs: HashMap<u64, RecvTransfer> = HashMap::new();

        // PAIR-7: re-read revoked.json (catches an out-of-process `ucb revoke`)
        // and send a Revoke for every tombstone so a formerly-offline third
        // device still learns about revocations.
        let tombstones = self.refresh_from_disk();
        for device in &tombstones {
            if chan.send(&WireMessage::Revoke { device: *device }).await.is_err() {
                self.deregister_session(&peer_id, token);
                return;
            }
        }

        // SYNC-5: drain the offline queue in order before live flow. Each item
        // goes out as a fresh Clip with a new session seq.
        let queued = match self.queue.lock().unwrap().drain(&peer_id, now_ms()) {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!(error = %e, "failed to drain offline queue");
                Vec::new()
            }
        };
        let drained = queued.len();
        for item in queued {
            if chan.send(&WireMessage::Clip { seq: out_seq, item }).await.is_err() {
                self.deregister_session(&peer_id, token);
                return;
            }
            out_seq += 1;
        }
        if drained > 0 {
            // UX-4 (sender side): what we flushed to a peer that was away.
            tracing::info!(count = drained, name = %peer_name, "synced {drained} items to {peer_name} while away");
        }

        // UX-4 (receiver side): count clips applied in the first few seconds of
        // the session and emit a "synced N items while away from <name>" notice
        // (the CLI toast equivalent; a GUI toast is future work).
        let mut early_applied: u32 = 0;
        let settle = tokio::time::sleep(SYNCED_AWAY_WINDOW);
        tokio::pin!(settle);
        let mut settled = false;

        loop {
            tokio::select! {
                inbound = chan.recv() => {
                    match inbound {
                        Ok(msg) => {
                            match self.handle_inbound_msg(&mut chan, &mut guard, &peer_name, &mut recvs, msg).await {
                                Ok(applied) => {
                                    if applied && !settled {
                                        early_applied += 1;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        Err(e) => {
                            tracing::debug!(peer = %peer_id.short(), error = %e, "session read ended");
                            break;
                        }
                    }
                }
                outbound = out_rx.recv() => {
                    match outbound {
                        Some(out) => {
                            let msg = match out {
                                Outbound::Clip(item) => {
                                    let m = WireMessage::Clip { seq: out_seq, item };
                                    out_seq += 1;
                                    m
                                }
                                Outbound::Revoke(device) => WireMessage::Revoke { device },
                                // FILE-4: file offer/chunk built by a send-pump task.
                                Outbound::Raw(m) => m,
                            };
                            if let Err(e) = chan.send(&msg).await {
                                tracing::debug!(peer = %peer_id.short(), error = %e, "session write failed");
                                break;
                            }
                        }
                        None => break, // engine dropped our sender
                    }
                }
                _ = &mut settle, if !settled => {
                    settled = true;
                    if early_applied > 0 {
                        tracing::info!(count = early_applied, name = %peer_name, "synced {early_applied} items while away from {peer_name}");
                    }
                }
            }
        }

        self.deregister_session(&peer_id, token);
        tracing::info!(peer = %peer_id.short(), "session closed");
    }

    /// Deregister a session, but only if we are still the current session for
    /// this peer (a newer session must never be evicted by an older one closing).
    fn deregister_session(&self, peer_id: &DeviceId, token: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.get(peer_id).map(|e| e.token) == Some(token) {
            sessions.remove(peer_id);
        }
    }

    /// Handle one decrypted inbound message. Returns `Ok(true)` if an incoming
    /// clip was applied to the clipboard (used for the UX-4 "synced while away"
    /// counter), `Ok(false)` for anything else. Returns `Err` only to signal the
    /// session should end.
    async fn handle_inbound_msg<S>(
        &self,
        chan: &mut SecureChannel<S>,
        guard: &mut ReplayGuard,
        peer_name: &str,
        recvs: &mut HashMap<u64, RecvTransfer>,
        msg: WireMessage,
    ) -> Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match msg {
            WireMessage::Clip { seq, item } => {
                if let Err(e) = guard.check(seq) {
                    tracing::warn!(error = %e, "dropping replayed/out-of-order clip");
                    return Ok(false);
                }
                if let Err(e) = check_clock_skew(item.ts_ms, now_ms()) {
                    tracing::warn!(error = %e, "dropping clip with excessive clock skew");
                    return Ok(false);
                }
                // Conflict resolution (SYNC-3): apply only if it wins.
                let apply = {
                    let mut latest = self.latest.lock().unwrap();
                    apply_incoming(&mut latest, &item)
                };
                if apply {
                    // HIST-1/3: record the applied remote clip under the sender's
                    // display name.
                    self.record_history(&item, peer_name);
                    if let Err(e) = self.writer.write(item.payload).await {
                        tracing::warn!(error = %e, "failed to write clip to clipboard");
                    }
                }
                Ok(apply)
            }
            WireMessage::Ping => {
                let _ = chan.send(&WireMessage::Pong).await;
                Ok(false)
            }
            WireMessage::Pong => Ok(false),
            WireMessage::Hello { .. } => Ok(false), // already exchanged; ignore
            WireMessage::Reject { reason } => {
                tracing::info!(reason = %reason, "peer sent Reject; closing session");
                Err(Error::Rejected(reason))
            }
            // PAIR-7: a trusted, live peer tells us it revoked `device`. We are
            // inside an established session, so the sender is trusted. Remove
            // `device` from our own allowlist, tombstone it, and drop its
            // session. `apply_revocation` is idempotent (already-tombstoned ->
            // no-op), so this never loops back around the group.
            WireMessage::Revoke { device } => {
                self.apply_revocation(device);
                Ok(false)
            }
            // FILE-6 (receiver): a peer offers a file. Enforce the size policy,
            // then accept into `received_dir` and reply with the FileAccept.
            WireMessage::FileOffer {
                transfer_id,
                name,
                size,
                chunk_count,
                hash,
            } => {
                if let Some(max) = self.max_file_bytes {
                    if size > max {
                        let reason = format!("file too large: {size} bytes > limit {max}");
                        let _ = chan
                            .send(&WireMessage::FileReject { transfer_id, reason })
                            .await;
                        tracing::warn!(transfer_id, size, max, "rejecting oversized file offer");
                        return Ok(false);
                    }
                }
                let offer = WireMessage::FileOffer {
                    transfer_id,
                    name,
                    size,
                    chunk_count,
                    hash,
                };
                match RecvTransfer::on_offer(offer, &self.received_dir).await {
                    Ok((mut recv, accept)) => {
                        if chan.send(&accept).await.is_err() {
                            return Ok(false);
                        }
                        if recv.is_complete() {
                            // 0-chunk (empty) file: finalize immediately.
                            match recv.finish().await {
                                Ok(path) => self.deliver_received(chan, transfer_id, path).await,
                                Err(e) => {
                                    let _ = chan
                                        .send(&WireMessage::FileDone {
                                            transfer_id,
                                            ok: false,
                                            detail: e.to_string(),
                                        })
                                        .await;
                                    tracing::warn!(transfer_id, error = %e, "failed to finalize empty file");
                                }
                            }
                        } else {
                            recvs.insert(transfer_id, recv);
                        }
                    }
                    Err(e) => {
                        let _ = chan
                            .send(&WireMessage::FileReject {
                                transfer_id,
                                reason: e.to_string(),
                            })
                            .await;
                        tracing::warn!(transfer_id, error = %e, "failed to accept file offer");
                    }
                }
                Ok(false)
            }
            // FILE-6 (receiver): one inbound chunk.
            WireMessage::FileChunk {
                transfer_id,
                index,
                data,
            } => {
                if let Some(recv) = recvs.get_mut(&transfer_id) {
                    match recv.on_chunk(index, &data.0).await {
                        Ok(RecvProgress::InProgress { .. }) => {}
                        Ok(RecvProgress::Completed { path }) => {
                            recvs.remove(&transfer_id);
                            self.deliver_received(chan, transfer_id, path).await;
                        }
                        Err(e) => {
                            recvs.remove(&transfer_id);
                            let _ = chan
                                .send(&WireMessage::FileDone {
                                    transfer_id,
                                    ok: false,
                                    detail: e.to_string(),
                                })
                                .await;
                            tracing::warn!(transfer_id, error = %e, "inbound file chunk rejected");
                        }
                    }
                } else {
                    tracing::debug!(transfer_id, "chunk for unknown transfer; ignoring");
                }
                Ok(false)
            }
            // FILE-4 (sender): replies routed back to the running send-pump task.
            WireMessage::FileAccept {
                transfer_id,
                resume_from,
            } => {
                self.forward_reply(
                    transfer_id,
                    WireMessage::FileAccept {
                        transfer_id,
                        resume_from,
                    },
                );
                Ok(false)
            }
            WireMessage::FileReject {
                transfer_id,
                reason,
            } => {
                self.forward_reply(
                    transfer_id,
                    WireMessage::FileReject {
                        transfer_id,
                        reason,
                    },
                );
                Ok(false)
            }
            WireMessage::FileDone {
                transfer_id,
                ok,
                detail,
            } => {
                self.forward_reply(
                    transfer_id,
                    WireMessage::FileDone {
                        transfer_id,
                        ok,
                        detail,
                    },
                );
                Ok(false)
            }
        }
    }

    /// Finalize a received file (FILE-6): ack the sender, log the saved path, and
    /// place the received file on the local clipboard.
    ///
    /// Clipboard-pointer behavior (FILE-1): the received file is placed on the
    /// local clipboard as a real OS file reference via
    /// [`ClipboardWriter::write_files`], so pasting yields the actual file (e.g.
    /// in Finder). On platforms/backends without file-reference support the
    /// writer transparently falls back to writing the absolute path as text. The
    /// write goes through [`ClipboardWriter`], whose echo suppression keeps it
    /// from being re-broadcast to peers, so it stays local to this device.
    async fn deliver_received<S>(
        &self,
        chan: &mut SecureChannel<S>,
        transfer_id: u64,
        path: PathBuf,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let _ = chan
            .send(&WireMessage::FileDone {
                transfer_id,
                ok: true,
                detail: String::new(),
            })
            .await;
        tracing::info!(transfer_id, path = %path.display(), "file received");
        let abs = tokio::fs::canonicalize(&path).await.unwrap_or(path);
        if let Err(e) = self.writer.write_files(vec![abs]).await {
            tracing::warn!(error = %e, "failed to write received-file reference to clipboard");
        }
    }

    /// Route a file-transfer reply to the send-pump task awaiting it (FILE-4).
    fn forward_reply(&self, transfer_id: u64, msg: WireMessage) {
        if let Some(tx) = self.send_routes.lock().unwrap().get(&transfer_id).cloned() {
            let _ = tx.try_send(msg);
        } else {
            tracing::debug!(transfer_id, "file reply for unknown/finished transfer; ignoring");
        }
    }

    // --- local clipboard broadcast (SYNC-1) --------------------------------

    async fn local_clip_loop(self: Arc<Self>, mut clip_rx: mpsc::Receiver<ClipboardEvent>) {
        while let Some(event) = clip_rx.recv().await {
            match event {
                ClipboardEvent::Payload(payload) => self.broadcast_local_payload(payload),
                // FILE-1: a local file copy. Auto-send it to peers when enabled;
                // otherwise ignore (copying files locally is a common action and
                // must not silently start transfers).
                ClipboardEvent::Files(paths) => {
                    if self.auto_file_sync {
                        tokio::spawn(self.clone().auto_send_files(paths));
                    } else {
                        tracing::debug!(
                            count = paths.len(),
                            "local file copy ignored (auto_file_sync disabled)"
                        );
                    }
                }
            }
        }
    }

    /// SYNC-1: broadcast a locally-copied inline payload to live peers, record it
    /// as `latest`/history, and buffer it for offline trusted peers (SYNC-5).
    fn broadcast_local_payload(self: &Arc<Self>, payload: ClipboardPayload) {
        let item = ClipboardItem {
            payload,
            ts_ms: now_ms(),
            origin: self.self_id,
        };
        // A local copy is the freshest user intent: record it as latest.
        *self.latest.lock().unwrap() = Some(item.clone());
        // HIST-1/3: record the local clip under this device's own name.
        self.record_history(&item, &self.name);

        // Snapshot live sessions, then send outside the lock.
        let live: HashMap<DeviceId, mpsc::Sender<Outbound>> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(id, e)| (*id, e.tx.clone()))
            .collect();
        for tx in live.values() {
            // Drop rather than block if a peer's queue is backed up.
            let _ = tx.try_send(Outbound::Clip(item.clone()));
        }

        // SYNC-5: buffer this clip for every trusted peer that is currently
        // offline (no live session, not tombstoned).
        let offline: Vec<DeviceId> = {
            let allowlist = self.allowlist.lock().unwrap();
            allowlist
                .list()
                .into_iter()
                .map(|d| d.device_id)
                .filter(|id| !live.contains_key(id) && !allowlist.is_tombstoned(id))
                .collect()
        };
        if !offline.is_empty() {
            let mut queue = self.queue.lock().unwrap();
            for id in offline {
                if let Err(e) = queue.enqueue(&id, item.clone(), item.ts_ms) {
                    tracing::warn!(error = %e, "failed to enqueue offline clip");
                }
            }
        }
    }

    /// FILE-1: automatically send each eligible locally-copied file to every
    /// connected peer. Directories, unreadable entries, and files over the
    /// per-file cap are skipped with an info log (naming the reason and file, but
    /// never the contents — SEC-2). Reuses the existing `send_file` machinery.
    async fn auto_send_files(self: Arc<Self>, paths: Vec<PathBuf>) {
        // Snapshot the currently connected peers once for the whole batch.
        let targets: Vec<DeviceId> = self.sessions.lock().unwrap().keys().copied().collect();
        if targets.is_empty() {
            tracing::debug!(count = paths.len(), "auto file sync: no connected peers");
            return;
        }

        for path in paths {
            let meta = match tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::info!(file = %path.display(), error = %e, "auto file sync: skipping unreadable path");
                    continue;
                }
            };
            if meta.is_dir() {
                tracing::info!(file = %path.display(), "auto file sync: skipping directory");
                continue;
            }
            if !meta.is_file() {
                tracing::info!(file = %path.display(), "auto file sync: skipping non-regular file");
                continue;
            }
            if meta.len() > self.max_auto_file_bytes {
                tracing::info!(
                    file = %path.display(),
                    bytes = meta.len(),
                    cap = self.max_auto_file_bytes,
                    "auto file sync: skipping file over size cap"
                );
                continue;
            }

            for target in &targets {
                let me = self.clone();
                let path = path.clone();
                let target = *target;
                tokio::spawn(async move {
                    match me.send_file(path, Some(target), None).await {
                        Ok(report) if report.ok => tracing::info!(
                            name = %report.name,
                            peer = %target.short(),
                            "auto file sync: sent"
                        ),
                        Ok(report) => tracing::warn!(
                            name = %report.name,
                            peer = %target.short(),
                            detail = %report.detail,
                            "auto file sync: transfer not completed"
                        ),
                        Err(e) => tracing::warn!(
                            peer = %target.short(),
                            error = %e,
                            "auto file sync: send failed"
                        ),
                    }
                });
            }
        }
    }

    // --- discovery (DISC-4) ------------------------------------------------

    async fn discovery_loop(self: Arc<Self>, mut disc_rx: mpsc::Receiver<PeerEvent>) {
        while let Some(event) = disc_rx.recv().await {
            match event {
                PeerEvent::Found(peer) => {
                    self.peers.lock().unwrap().insert(
                        peer.device_id,
                        Endpoint {
                            addrs: peer.addrs.clone(),
                            port: peer.port,
                        },
                    );

                    let trusted = self.allowlist.lock().unwrap().is_trusted(&peer.device_id);
                    // Deterministic dial direction: only the smaller id dials.
                    if trusted && self.self_id < peer.device_id {
                        let mut connectors = self.connectors.lock().unwrap();
                        if !connectors.contains_key(&peer.device_id) {
                            let present = Arc::new(AtomicBool::new(true));
                            connectors.insert(peer.device_id, present.clone());
                            let me = self.clone();
                            let pid = peer.device_id;
                            tokio::spawn(async move { me.connector(pid, present).await });
                        }
                    }
                }
                PeerEvent::Lost(id) => {
                    if let Some(present) = self.connectors.lock().unwrap().remove(&id) {
                        present.store(false, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// True if `id` is trusted, not tombstoned, *and* the presented static key
    /// matches what we stored (defends against a device-id record whose key was
    /// tampered, and rejects a revoked device even if somehow still listed).
    fn is_trusted(&self, id: &DeviceId, presented_pubkey: [u8; 32]) -> bool {
        let allowlist = self.allowlist.lock().unwrap();
        !allowlist.is_tombstoned(id)
            && allowlist.is_trusted(id)
            && allowlist.pubkey_of(id) == Some(presented_pubkey)
    }

    // --- revocation propagation (PAIR-7) ----------------------------------

    /// Reload the allowlist (and its tombstone set) from disk so an
    /// out-of-process `ucb revoke` takes effect in the running engine, then
    /// drop any live session / connector for a now-tombstoned peer. Returns the
    /// current tombstone list.
    fn refresh_from_disk(&self) -> Vec<DeviceId> {
        let tombstones = match Allowlist::load(&self.allowlist_path) {
            Ok(fresh) => {
                let tombstones = fresh.tombstones();
                *self.allowlist.lock().unwrap() = fresh;
                tombstones
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to reload allowlist for revocation re-check");
                self.allowlist.lock().unwrap().tombstones()
            }
        };
        for id in &tombstones {
            self.drop_peer(id);
        }
        tombstones
    }

    /// Drop any live session and stop any connector for `id` (used when a peer
    /// becomes revoked).
    fn drop_peer(&self, id: &DeviceId) {
        // Removing the SessionEntry drops its outbound sender, which ends the
        // peer's `run_session` on its next `out_rx.recv()`.
        self.sessions.lock().unwrap().remove(id);
        if let Some(present) = self.connectors.lock().unwrap().remove(id) {
            present.store(false, Ordering::Relaxed);
        }
    }

    /// Apply a revocation learned from a trusted peer (or locally): remove the
    /// device from the allowlist, tombstone it, and drop its session. Idempotent
    /// — an already-tombstoned device is a no-op, which prevents `Revoke`
    /// messages from looping around the group. Returns whether it was newly
    /// applied.
    fn apply_revocation(&self, device: DeviceId) -> bool {
        let newly = match self.allowlist.lock().unwrap().revoke(device) {
            Ok(newly) => newly,
            Err(e) => {
                tracing::warn!(error = %e, "failed to record revocation");
                false
            }
        };
        if newly {
            tracing::info!(revoked = %device.short(), "device revoked by a trusted peer; removed from allowlist");
            self.drop_peer(&device);
        }
        newly
    }

    /// Send a `Revoke` for each tombstoned device to every live session.
    fn broadcast_revocations(&self, tombstones: &[DeviceId]) {
        if tombstones.is_empty() {
            return;
        }
        let sinks: Vec<mpsc::Sender<Outbound>> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|e| e.tx.clone())
            .collect();
        for tx in sinks {
            for device in tombstones {
                let _ = tx.try_send(Outbound::Revoke(*device));
            }
        }
    }

    /// Periodic PAIR-7 re-check: every [`REVOCATION_RECHECK`], re-read
    /// `revoked.json` (to pick up an out-of-process `ucb revoke`) and
    /// re-broadcast tombstones to connected peers. Live propagation therefore
    /// lags by up to one interval.
    async fn revocation_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(REVOCATION_RECHECK).await;
            let tombstones = self.refresh_from_disk();
            self.broadcast_revocations(&tombstones);
        }
    }
}

/// Drive a single outbound file transfer (FILE-4): send the offer, wait for the
/// peer's acceptance, stream chunks through the bounded session channel (natural
/// backpressure), log progress every 10%, then await the receiver's `FileDone`.
/// Outbound wire messages go through `out_tx`; inbound replies arrive on
/// `inbound_rx` via the engine's reply router.
async fn send_pump(
    mut transfer: SendTransfer,
    offer: WireMessage,
    out_tx: mpsc::Sender<Outbound>,
    mut inbound_rx: mpsc::Receiver<WireMessage>,
    progress: Option<mpsc::Sender<SendProgress>>,
    result_tx: oneshot::Sender<SendReport>,
) {
    let transfer_id = transfer.transfer_id();
    let (name, size) = match &offer {
        WireMessage::FileOffer { name, size, .. } => (name.clone(), *size),
        _ => (String::new(), 0),
    };
    let report = |ok: bool, detail: String| SendReport {
        transfer_id,
        name: name.clone(),
        bytes: size,
        ok,
        detail,
    };

    // 1. Transmit the offer.
    if out_tx.send(Outbound::Raw(offer)).await.is_err() {
        let _ = result_tx.send(report(false, "session closed before offer".into()));
        return;
    }

    // 2. Wait for acceptance (or an early rejection / done).
    loop {
        match inbound_rx.recv().await {
            Some(msg) => match transfer.on_message(msg) {
                SendAction::Accepted { .. } => break,
                SendAction::Rejected { reason } => {
                    tracing::info!(name = %name, reason = %reason, "file offer rejected by peer");
                    let _ = result_tx.send(report(false, format!("rejected: {reason}")));
                    return;
                }
                SendAction::Done { ok, detail } => {
                    let _ = result_tx.send(report(ok, detail));
                    return;
                }
                SendAction::Ignored => {}
            },
            None => {
                let _ = result_tx.send(report(false, "session closed awaiting acceptance".into()));
                return;
            }
        }
    }

    // 3. Stream chunks, logging progress every 10% (FILE-4; a GUI spinner is
    //    UX-3 future work).
    let mut next_pct: u64 = 10;
    loop {
        match transfer.next_chunk().await {
            Ok(Some(chunk)) => {
                if out_tx.send(Outbound::Raw(chunk)).await.is_err() {
                    let _ = result_tx.send(report(false, "session closed mid-transfer".into()));
                    return;
                }
                let (sent, total) = transfer.progress();
                if let Some(p) = &progress {
                    let _ = p
                        .send(SendProgress {
                            transfer_id,
                            sent,
                            total,
                        })
                        .await;
                }
                if let Some(pct) = sent.checked_mul(100).and_then(|n| n.checked_div(total)) {
                    if pct >= next_pct {
                        tracing::info!(name = %name, percent = pct, "file transfer progress");
                        while next_pct <= pct {
                            next_pct += 10;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = result_tx.send(report(false, format!("read error: {e}")));
                return;
            }
        }
    }

    // 4. Await the receiver's completion notice.
    loop {
        match inbound_rx.recv().await {
            Some(msg) => {
                if let SendAction::Done { ok, detail } = transfer.on_message(msg) {
                    if ok {
                        tracing::info!(name = %name, "file transfer complete");
                    } else {
                        tracing::warn!(name = %name, detail = %detail, "file transfer failed on receiver");
                    }
                    let _ = result_tx.send(report(ok, detail));
                    return;
                }
            }
            None => {
                let _ = result_tx.send(report(false, "session closed awaiting completion".into()));
                return;
            }
        }
    }
}

/// Try each of a peer's addresses in turn until one connects.
async fn connect_any(endpoint: &Endpoint) -> Result<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    for ip in &endpoint.addrs {
        match TcpStream::connect((*ip, endpoint.port)).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(Error::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses to dial")
    })))
}

/// Apply the conflict rule (SYNC-3) to shared `latest` state: update it to
/// `item` and return `true` iff `item` should be written to the clipboard.
///
/// Extracted and `pub(crate)` so it can be unit-tested without a live session.
pub(crate) fn apply_incoming(latest: &mut Option<ClipboardItem>, item: &ClipboardItem) -> bool {
    let wins = match latest {
        None => true,
        Some(current) => item.wins_over(current),
    };
    if wins {
        *latest = Some(item.clone());
    }
    wins
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucb_core::ClipboardPayload;

    fn item(ts: u64, origin: u8, text: &str) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Text(text.into()),
            ts_ms: ts,
            origin: DeviceId([origin; 32]),
        }
    }

    #[test]
    fn first_clip_always_applies() {
        let mut latest = None;
        assert!(apply_incoming(&mut latest, &item(100, 1, "a")));
        assert_eq!(latest.unwrap().payload, ClipboardPayload::Text("a".into()));
    }

    #[test]
    fn newer_timestamp_wins() {
        let mut latest = Some(item(100, 1, "old"));
        assert!(apply_incoming(&mut latest, &item(200, 1, "new")));
        assert!(!apply_incoming(&mut latest, &item(150, 1, "stale")));
    }

    #[test]
    fn equal_timestamp_breaks_by_device_id_deterministically() {
        // Same ts, different origins: higher origin id wins (per wins_over).
        let mut latest = Some(item(100, 1, "from-1"));
        // origin 2 > origin 1 -> wins.
        assert!(apply_incoming(&mut latest, &item(100, 2, "from-2")));
        // origin 1 < origin 2 -> loses; state unchanged.
        assert!(!apply_incoming(&mut latest, &item(100, 1, "from-1")));
        assert_eq!(latest.unwrap().origin, DeviceId([2; 32]));
    }
}
