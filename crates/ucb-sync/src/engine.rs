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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use ucb_clipboard::ClipboardWriter;
use ucb_core::{
    ClipboardItem, ClipboardPayload, DeviceId, DeviceInfo, Platform, WireMessage, PROTOCOL_VERSION,
};
use ucb_crypto::{
    check_clock_skew, handshake_initiator, handshake_responder, Identity, ReplayGuard, SecureChannel,
};
use ucb_discovery::PeerEvent;

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

/// One thing to send out on a session: a live/queued clip, or a revocation
/// broadcast (PAIR-7).
#[derive(Clone)]
enum Outbound {
    Clip(ClipboardItem),
    Revoke(DeviceId),
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
}

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
        clip_rx: mpsc::Receiver<ClipboardPayload>,
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
        });

        let mut tasks = vec![
            tokio::spawn(shared.clone().accept_loop(listener)),
            tokio::spawn(shared.clone().local_clip_loop(clip_rx)),
            tokio::spawn(shared.clone().discovery_loop(disc_rx)),
            tokio::spawn(shared.clone().revocation_loop()),
        ];

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
                            match self.handle_inbound_msg(&mut chan, &mut guard, msg).await {
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
            // File* messages are wired in by a later integration wave; ignore
            // them (with their frames already decrypted) until then.
            WireMessage::FileOffer { .. }
            | WireMessage::FileAccept { .. }
            | WireMessage::FileReject { .. }
            | WireMessage::FileChunk { .. }
            | WireMessage::FileDone { .. } => {
                tracing::debug!("ignoring File* message (not yet wired in)");
                Ok(false)
            }
        }
    }

    // --- local clipboard broadcast (SYNC-1) --------------------------------

    async fn local_clip_loop(self: Arc<Self>, mut clip_rx: mpsc::Receiver<ClipboardPayload>) {
        while let Some(payload) = clip_rx.recv().await {
            let item = ClipboardItem {
                payload,
                ts_ms: now_ms(),
                origin: self.self_id,
            };
            // A local copy is the freshest user intent: record it as latest.
            *self.latest.lock().unwrap() = Some(item.clone());

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
