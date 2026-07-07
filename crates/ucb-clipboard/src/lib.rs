//! ucb-clipboard — OS clipboard watch/write with echo-loop prevention (SYNC-2).
//!
//! See ARCHITECTURE.md for the contract. This crate is responsible for reading
//! from and writing to the OS clipboard, watching it for changes, and making
//! sure a clip we write to the clipboard (because a peer sent it to us) is not
//! observed and re-broadcast as if it were a fresh local copy.
//!
//! # Threading model
//!
//! `arboard::Clipboard` is not `Send` on every platform (e.g. some Linux
//! backends), and the clipboard calls are blocking. Rather than sprinkle
//! `spawn_blocking` around (which would pin a Tokio blocking-pool thread for
//! the entire lifetime of the service) we give the clipboard a single dedicated
//! `std::thread` that *owns* the backend and is the only thread that ever
//! touches it. Everything else talks to that thread over channels:
//!
//! * [`ArboardClipboard`] is itself just a handle to a dedicated thread that
//!   owns the real `arboard::Clipboard`. That is what makes it `Send` (a
//!   requirement of the [`SystemClipboard`] trait) even though the underlying
//!   backend is not.
//! * [`ClipboardService::start`] spawns a *watcher/writer* thread that owns the
//!   `SystemClipboard` value. That single thread performs both the polling and
//!   the writes, so all mutable state (last-seen hash, last-written hash) is
//!   owned by one thread and needs no `Arc<Mutex<_>>`: the command channel
//!   serializes reads and writes for us. This was chosen over shared
//!   `Arc<Mutex<_>>` state on purpose — there is no shared mutable state, no
//!   lock contention, and no lock-poisoning to reason about.
//!
//! # Shutdown
//!
//! The watcher/writer thread runs until *either* handle returned by
//! [`ClipboardService::start`] is dropped:
//! * dropping every [`ClipboardWriter`] clone disconnects the command channel,
//!   which the thread detects on its next poll and then exits;
//! * dropping the event [`Receiver`](tokio::sync::mpsc::Receiver) makes the next
//!   emit fail, which also stops the thread.
//!
//! In practice a consumer (ucb-sync) holds both for the lifetime of the service
//! and drops them together to shut it down. Hold both alive to keep watching.

use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use ucb_core::ClipboardPayload;

/// Result type for clipboard operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by clipboard backends and the clipboard service.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying OS clipboard backend reported an error. The string is a
    /// backend-provided message; it never contains clipboard content.
    #[error("clipboard backend error: {0}")]
    Backend(String),
    /// The dedicated clipboard thread has stopped (e.g. the service was shut
    /// down), so the request could not be served.
    #[error("clipboard worker has stopped")]
    WorkerStopped,
}

/// Abstraction over an OS clipboard, so the service can be driven by a real
/// backend in production and by [`MockClipboard`] in tests.
///
/// Implementors are used from a single dedicated thread; the `Send + 'static`
/// bound only exists so the value can be *moved onto* that thread.
pub trait SystemClipboard: Send + 'static {
    /// Return the current clipboard text, or `Ok(None)` if the clipboard is
    /// empty or holds non-text content. Non-text/empty is never an error.
    fn get_text(&mut self) -> Result<Option<String>>;
    /// Replace the clipboard contents with `text`.
    fn set_text(&mut self, text: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Arboard backend
// ---------------------------------------------------------------------------

enum ArboardCmd {
    Get(std_mpsc::Sender<Result<Option<String>>>),
    Set(String, std_mpsc::Sender<Result<()>>),
}

/// Real OS clipboard backed by the `arboard` crate.
///
/// Construction spawns a dedicated thread that owns the (possibly non-`Send`)
/// `arboard::Clipboard`; this handle just forwards commands to it, which is what
/// lets `ArboardClipboard` be `Send`.
pub struct ArboardClipboard {
    tx: std_mpsc::Sender<ArboardCmd>,
}

impl ArboardClipboard {
    /// Create a new arboard-backed clipboard, spawning its owner thread.
    ///
    /// Returns [`Error::Backend`] if the platform clipboard cannot be opened.
    pub fn new() -> Result<Self> {
        let (tx, rx) = std_mpsc::channel::<ArboardCmd>();
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

        thread::Builder::new()
            .name("ucb-arboard".into())
            .spawn(move || {
                let mut clipboard = match arboard::Clipboard::new() {
                    Ok(c) => {
                        let _ = ready_tx.send(Ok(()));
                        c
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(Error::Backend(e.to_string())));
                        return;
                    }
                };
                while let Ok(cmd) = rx.recv() {
                    match cmd {
                        ArboardCmd::Get(reply) => {
                            let r = match clipboard.get_text() {
                                Ok(s) => Ok(Some(s)),
                                // Empty clipboard / non-text content is not an error.
                                Err(arboard::Error::ContentNotAvailable) => Ok(None),
                                Err(e) => Err(Error::Backend(e.to_string())),
                            };
                            let _ = reply.send(r);
                        }
                        ArboardCmd::Set(text, reply) => {
                            let r = clipboard
                                .set_text(text)
                                .map_err(|e| Error::Backend(e.to_string()));
                            let _ = reply.send(r);
                        }
                    }
                }
            })
            .map_err(|e| Error::Backend(e.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(ArboardClipboard { tx }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::WorkerStopped),
        }
    }
}

impl SystemClipboard for ArboardClipboard {
    fn get_text(&mut self) -> Result<Option<String>> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::Get(reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }

    fn set_text(&mut self, text: &str) -> Result<()> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::Set(text.to_owned(), reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }
}

// ---------------------------------------------------------------------------
// Mock backend (used by ucb-sync integration tests; not feature-gated)
// ---------------------------------------------------------------------------

/// Handle to a [`MockClipboard`]'s shared state, so tests can inject "external"
/// clipboard changes and inspect what the service wrote.
#[derive(Clone)]
pub struct MockClipboardHandle {
    state: Arc<Mutex<Option<String>>>,
}

impl MockClipboardHandle {
    /// Simulate an external app copying `text` to the clipboard.
    pub fn set(&self, text: impl Into<String>) {
        *self.state.lock().expect("mock clipboard poisoned") = Some(text.into());
    }

    /// Simulate the clipboard being cleared / holding non-text content.
    pub fn clear(&self) {
        *self.state.lock().expect("mock clipboard poisoned") = None;
    }

    /// Read the current mock clipboard contents (e.g. to assert what the
    /// service wrote).
    pub fn get(&self) -> Option<String> {
        self.state.lock().expect("mock clipboard poisoned").clone()
    }
}

/// In-memory [`SystemClipboard`] backed by shared state, for tests. Create with
/// [`MockClipboard::new`], which also hands back a [`MockClipboardHandle`] for
/// injecting changes from the test thread.
pub struct MockClipboard {
    state: Arc<Mutex<Option<String>>>,
}

impl MockClipboard {
    /// Create a mock clipboard (initially empty) and a handle to its state.
    pub fn new() -> (Self, MockClipboardHandle) {
        let state = Arc::new(Mutex::new(None));
        (
            MockClipboard {
                state: Arc::clone(&state),
            },
            MockClipboardHandle { state },
        )
    }
}

impl SystemClipboard for MockClipboard {
    fn get_text(&mut self) -> Result<Option<String>> {
        Ok(self.state.lock().expect("mock clipboard poisoned").clone())
    }

    fn set_text(&mut self, text: &str) -> Result<()> {
        *self.state.lock().expect("mock clipboard poisoned") = Some(text.to_owned());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clipboard service (watcher + writer)
// ---------------------------------------------------------------------------

enum WorkerCmd {
    Write {
        payload: ClipboardPayload,
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Write side of a running [`ClipboardService`]. Cheap to clone.
///
/// Writing both pushes content to the OS clipboard *and* records its hash as
/// "last written" so the watcher will not re-broadcast that same content when it
/// observes it (echo-loop prevention, SYNC-2).
#[derive(Clone)]
pub struct ClipboardWriter {
    tx: std_mpsc::Sender<WorkerCmd>,
}

impl ClipboardWriter {
    /// Write `payload` to the OS clipboard and mark it as our own write so the
    /// watcher suppresses the resulting change event.
    pub async fn write(&self, payload: ClipboardPayload) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(WorkerCmd::Write { payload, reply })
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.await.map_err(|_| Error::WorkerStopped)?
    }
}

/// Entry point for clipboard watching + writing.
pub struct ClipboardService;

impl ClipboardService {
    /// Start watching `clipboard`, polling every `poll_interval`.
    ///
    /// Returns a [`ClipboardWriter`] and a receiver of clipboard change events.
    /// The watcher emits a [`ClipboardPayload`] whenever it observes new text
    /// content that (a) differs from the previously observed content and (b) was
    /// not the content of our own most recent [`ClipboardWriter::write`].
    ///
    /// The current clipboard content at startup is recorded as "last seen" and
    /// is **not** emitted (we only report changes, not the pre-existing state).
    /// This baseline read happens synchronously before `start` returns, so any
    /// change made after `start` returns is guaranteed to be observed as new —
    /// there is no startup race with the first injected/copied value.
    pub fn start<C: SystemClipboard>(
        mut clipboard: C,
        poll_interval: Duration,
    ) -> (ClipboardWriter, mpsc::Receiver<ClipboardPayload>) {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<WorkerCmd>();
        let (event_tx, event_rx) = mpsc::channel::<ClipboardPayload>(64);

        // Establish the baseline synchronously so pre-existing content is not
        // emitted as a spurious change and does not race the first real change.
        let initial_seen = match clipboard.get_text() {
            Ok(Some(text)) => Some(text_hash(&text)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "initial clipboard read failed");
                None
            }
        };

        thread::Builder::new()
            .name("ucb-clipboard-watch".into())
            .spawn(move || worker_loop(clipboard, poll_interval, cmd_rx, event_tx, initial_seen))
            .expect("failed to spawn clipboard watch thread");

        (ClipboardWriter { tx: cmd_tx }, event_rx)
    }
}

fn text_hash(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

/// The single thread that owns the clipboard backend and all watcher state.
///
/// Echo-loop semantics (SYNC-2): `last_written` is a one-shot suppression token.
/// The next *change* the watcher observes clears it: if that change's content
/// matches the token it is suppressed (it was our own write echoing back),
/// otherwise it is emitted and the token is abandoned (the expected echo never
/// materialised, so a later identical copy must not be suppressed).
///
/// Edge case: if the user copies the *same* content we just wrote, before the
/// echo is observed, we cannot distinguish it from the echo and suppress it.
/// This is deliberate and considered acceptable — we dedup purely by content
/// hash and never inspect content (SEC-2).
fn worker_loop<C: SystemClipboard>(
    mut clipboard: C,
    poll_interval: Duration,
    cmd_rx: std_mpsc::Receiver<WorkerCmd>,
    event_tx: mpsc::Sender<ClipboardPayload>,
    initial_seen: Option<[u8; 32]>,
) {
    // Baseline is read synchronously in `ClipboardService::start` so that
    // pre-existing content is neither emitted nor able to race a real change.
    let mut last_seen: Option<[u8; 32]> = initial_seen;
    let mut last_written: Option<[u8; 32]> = None;

    loop {
        match cmd_rx.recv_timeout(poll_interval) {
            Ok(WorkerCmd::Write { payload, reply }) => {
                let res = match &payload {
                    ClipboardPayload::Text(text) => clipboard.set_text(text),
                };
                if res.is_ok() {
                    // Record our own write so the resulting change is suppressed.
                    last_written = Some(payload.content_hash());
                }
                let _ = reply.send(res);
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                match clipboard.get_text() {
                    Ok(Some(text)) => {
                        let h = text_hash(&text);
                        if Some(h) != last_seen {
                            let was_echo = last_written == Some(h);
                            // Any observed change consumes the echo token.
                            last_written = None;
                            last_seen = Some(h);
                            if !was_echo
                                && event_tx
                                    .blocking_send(ClipboardPayload::Text(text))
                                    .is_err()
                            {
                                break; // event receiver dropped -> shut down
                            }
                        }
                    }
                    // Empty / non-text clipboard: nothing to report.
                    Ok(None) => {}
                    // Transient read error: log and keep polling.
                    Err(e) => tracing::warn!(error = %e, "clipboard read failed"),
                }
            }
            // All ClipboardWriter clones dropped -> shut down.
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn recv(rx: &mut mpsc::Receiver<ClipboardPayload>) -> ClipboardPayload {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for a clipboard event")
            .expect("event channel closed unexpectedly")
    }

    /// Returns true if no event arrives within a window of several poll
    /// intervals (i.e. the watcher correctly stayed silent).
    async fn no_event(rx: &mut mpsc::Receiver<ClipboardPayload>) -> bool {
        tokio::time::timeout(Duration::from_millis(80), rx.recv())
            .await
            .is_err()
    }

    fn text(s: &str) -> ClipboardPayload {
        ClipboardPayload::Text(s.into())
    }

    const POLL: Duration = Duration::from_millis(2);

    #[tokio::test]
    async fn change_detection_reports_new_and_dedups_repeats() {
        let (mock, handle) = MockClipboard::new();
        let (_writer, mut rx) = ClipboardService::start(mock, POLL);

        handle.set("A");
        assert_eq!(recv(&mut rx).await, text("A"));

        // Same content injected again -> no duplicate event.
        handle.set("A");
        assert!(no_event(&mut rx).await, "duplicate content should not emit");

        handle.set("B");
        assert_eq!(recv(&mut rx).await, text("B"));
    }

    #[tokio::test]
    async fn echo_prevention_suppresses_own_write_then_reports_external() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        writer.write(text("X")).await.unwrap();
        // The watcher will observe X (our own write) -> must NOT emit.
        assert!(no_event(&mut rx).await, "own write must not echo back");
        // Sanity: the write actually reached the clipboard.
        assert_eq!(handle.get().as_deref(), Some("X"));

        // A genuine external change is still reported.
        handle.set("Y");
        assert_eq!(recv(&mut rx).await, text("Y"));
    }

    #[tokio::test]
    async fn edge_external_same_content_after_write_is_suppressed() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        writer.write(text("X")).await.unwrap();
        // User copies identical content externally before the echo is observed;
        // indistinguishable from the echo, so suppressed (documented semantics).
        handle.set("X");
        assert!(no_event(&mut rx).await, "identical re-copy should be suppressed");
    }

    #[tokio::test]
    async fn genuine_recopy_after_echo_token_cleared_is_reported() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        writer.write(text("X")).await.unwrap();
        assert!(no_event(&mut rx).await, "echo suppressed");

        handle.set("Y");
        assert_eq!(recv(&mut rx).await, text("Y"));

        // The echo token for X was cleared once a different change was seen, so
        // a genuine later copy of X must be reported.
        handle.set("X");
        assert_eq!(recv(&mut rx).await, text("X"));
    }
}
