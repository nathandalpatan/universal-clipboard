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

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use ucb_core::{ClipboardPayload, MAX_CLIP_BYTES};

/// Result type for clipboard operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A change observed on the OS clipboard by [`ClipboardService`] (FILE-1).
///
/// `ucb_core::ClipboardPayload` intentionally does not carry a file-reference
/// variant (other crates own that type and its wire format), so file copies are
/// surfaced here, one level up, as a distinct event alongside inline payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// Inline clipboard content (text / HTML / image).
    Payload(ClipboardPayload),
    /// The clipboard holds one or more file references (e.g. a Finder copy).
    /// Carries the local absolute paths; the transfer of their bytes is the
    /// engine's concern, not this crate's.
    Files(Vec<PathBuf>),
}

/// Deterministic change-detection hash for a file-reference list (FILE-1).
///
/// The list is sorted first so the hash is order-independent (selecting the same
/// files in a different order is the same clipboard state), then each path's raw
/// OS bytes are folded in with an unambiguous length prefix so distinct lists
/// never collide. Used both for watcher change detection and for echo
/// suppression of file lists we wrote ourselves. Never logs the paths (SEC-2).
pub(crate) fn hash_paths(paths: &[PathBuf]) -> [u8; 32] {
    let mut sorted: Vec<&PathBuf> = paths.iter().collect();
    sorted.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"files\0");
    for p in sorted {
        let bytes = p.as_os_str().as_encoded_bytes();
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    *h.finalize().as_bytes()
}

/// Plain-text fallback used when a backend cannot place a real OS file reference
/// (unsupported platform or a failed native write): the newline-joined absolute
/// paths, matching the pre-FILE-1 "path as text" behavior for a single file.
fn paths_as_text(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

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
///
/// This is a full multi-format surface (SYNC-4): a single [`ClipboardPayload`]
/// carries text, HTML (with a plain-text alternative), or a raw RGBA image.
pub trait SystemClipboard: Send + 'static {
    /// Return the current clipboard contents as a [`ClipboardPayload`], or
    /// `Ok(None)` if the clipboard is empty or holds content we cannot map to
    /// a payload variant. Empty / unsupported content is never an error.
    fn get(&mut self) -> Result<Option<ClipboardPayload>>;
    /// Replace the clipboard contents with `payload`.
    fn set(&mut self, payload: &ClipboardPayload) -> Result<()>;

    /// Return the file references currently on the clipboard (FILE-1), or
    /// `Ok(None)` when none are present. An empty list is reported as `None`.
    ///
    /// The default implementation reports no file references, so a backend with
    /// no file support (e.g. a headless file-backed clipboard) needs no changes.
    fn get_files(&mut self) -> Result<Option<Vec<PathBuf>>> {
        Ok(None)
    }

    /// Place `paths` on the clipboard as real OS file references (FILE-1).
    ///
    /// Returns `Ok(true)` if a real file reference was written, or `Ok(false)`
    /// if this backend cannot write file references (so the caller should fall
    /// back to writing the paths as text). A failed *native* write is reported
    /// as `Ok(false)` (never an error) so the fallback still runs.
    ///
    /// The default implementation writes nothing and returns `Ok(false)`.
    fn set_files(&mut self, _paths: &[PathBuf]) -> Result<bool> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Arboard backend
// ---------------------------------------------------------------------------

enum ArboardCmd {
    Get(std_mpsc::Sender<Result<Option<ClipboardPayload>>>),
    Set(ClipboardPayload, std_mpsc::Sender<Result<()>>),
    GetFiles(std_mpsc::Sender<Result<Option<Vec<PathBuf>>>>),
    SetFiles(Vec<PathBuf>, std_mpsc::Sender<Result<bool>>),
}

/// Real OS clipboard backed by the `arboard` crate.
///
/// Construction spawns a dedicated thread that owns the (possibly non-`Send`)
/// `arboard::Clipboard`; this handle just forwards commands to it, which is what
/// lets `ArboardClipboard` be `Send`.
///
/// # Read strategy (SYNC-4)
///
/// The documented priority is image > HTML > text, but reading an image on
/// every poll is expensive on macOS (the pasteboard stores TIFF, which arboard
/// decodes into RGBA on each `get_image`). arboard exposes no cheap
/// "is an image present?" probe, so we use *text presence* as a cheap gate:
///
/// * If plain text is present (the common case), we never call `get_image` —
///   text and images practically never coexist on the clipboard. We still
///   check `get().html()`: if HTML is also present we return the richer
///   [`ClipboardPayload::Html`] (HTML over plain text), otherwise
///   [`ClipboardPayload::Text`].
/// * Only when text is absent do we pay for `get_image`; failing that we fall
///   back to an HTML-only read, then to `None`.
///
/// The tradeoff: an image copied together with text (rare) is reported as
/// text/HTML rather than as an image. In exchange, the steady-state text-poll
/// path never decodes an image.
///
/// # HTML echo caveat (macOS)
///
/// arboard's `set_html` wraps the HTML in a `<html><head>…</head><body>…`
/// document on macOS, so reading our own HTML write back yields *different*
/// bytes than we wrote. Echo-loop suppression (SYNC-2) is by content hash, so
/// a locally-written HTML clip may not be recognised as its own echo on macOS
/// and can be re-broadcast once. Text and image writes round-trip byte-for-byte
/// and are unaffected. (Not exercised in tests, which use [`MockClipboard`].)
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
                // FILE-1: a second, file-aware backend owned by the same thread.
                // arboard has no file-list API, so file references go through
                // clipboard-rs (NSPasteboard file URLs on macOS, and the native
                // equivalents on Windows/Linux). If it cannot initialise, file
                // reads report none and file writes fall back to text.
                let files_ctx: Option<clipboard_rs::ClipboardContext> =
                    clipboard_rs::ClipboardContext::new().ok();
                while let Ok(cmd) = rx.recv() {
                    match cmd {
                        ArboardCmd::Get(reply) => {
                            let _ = reply.send(arboard_get(&mut clipboard));
                        }
                        ArboardCmd::Set(payload, reply) => {
                            let _ = reply.send(arboard_set(&mut clipboard, &payload));
                        }
                        ArboardCmd::GetFiles(reply) => {
                            let _ = reply.send(files_get(files_ctx.as_ref()));
                        }
                        ArboardCmd::SetFiles(paths, reply) => {
                            let _ = reply.send(Ok(files_set(files_ctx.as_ref(), &paths)));
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
    fn get(&mut self) -> Result<Option<ClipboardPayload>> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::Get(reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }

    fn set(&mut self, payload: &ClipboardPayload) -> Result<()> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::Set(payload.clone(), reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }

    fn get_files(&mut self) -> Result<Option<Vec<PathBuf>>> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::GetFiles(reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }

    fn set_files(&mut self, paths: &[PathBuf]) -> Result<bool> {
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .send(ArboardCmd::SetFiles(paths.to_vec(), reply_tx))
            .map_err(|_| Error::WorkerStopped)?;
        reply_rx.recv().map_err(|_| Error::WorkerStopped)?
    }
}

/// Read file references from the OS clipboard via clipboard-rs. Runs on the
/// dedicated backend thread. `None` means the context is unavailable or no file
/// references are present. clipboard-rs yields plain absolute paths on macOS.
fn files_get(ctx: Option<&clipboard_rs::ClipboardContext>) -> Result<Option<Vec<PathBuf>>> {
    use clipboard_rs::Clipboard as _;
    let Some(ctx) = ctx else {
        return Ok(None);
    };
    match ctx.get_files() {
        Ok(list) if !list.is_empty() => {
            Ok(Some(list.into_iter().map(strip_file_uri).collect()))
        }
        // Empty list or "no files on the clipboard" are both simply "no files".
        _ => Ok(None),
    }
}

/// Write file references to the OS clipboard via clipboard-rs. Returns `true` on
/// a real file-reference write, `false` if the context is missing or the native
/// write failed (so the caller falls back to text). Never logs the paths (SEC-2).
fn files_set(ctx: Option<&clipboard_rs::ClipboardContext>, paths: &[PathBuf]) -> bool {
    use clipboard_rs::Clipboard as _;
    let Some(ctx) = ctx else {
        return false;
    };
    let strs: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    match ctx.set_files(strs) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, count = paths.len(), "native file-reference write failed; falling back to text");
            false
        }
    }
}

/// clipboard-rs returns plain paths on macOS but may return `file://` URIs on
/// other backends; normalise to a plain path either way.
fn strip_file_uri(s: String) -> PathBuf {
    match s.strip_prefix("file://") {
        Some(rest) => PathBuf::from(rest),
        None => PathBuf::from(s),
    }
}

/// Read the OS clipboard into a [`ClipboardPayload`]. Runs on the dedicated
/// arboard thread. See [`ArboardClipboard`] for the read-priority rationale.
fn arboard_get(clipboard: &mut arboard::Clipboard) -> Result<Option<ClipboardPayload>> {
    match clipboard.get_text() {
        // Text present: prefer HTML if it is also on the clipboard, else text.
        // Do not probe for an image here (it practically never coexists with
        // text, and get_image is the expensive call we want to avoid per poll).
        Ok(text) => match clipboard.get().html() {
            Ok(html) if !html.is_empty() => {
                Ok(Some(ClipboardPayload::Html { html, alt_text: text }))
            }
            _ => Ok(Some(ClipboardPayload::Text(text))),
        },
        // No text: now it is worth checking for an image, then HTML-only.
        Err(arboard::Error::ContentNotAvailable) => match clipboard.get_image() {
            Ok(img) => Ok(Some(ClipboardPayload::Image {
                width: img.width as u32,
                height: img.height as u32,
                rgba: img.bytes.into_owned(),
            })),
            Err(arboard::Error::ContentNotAvailable) => match clipboard.get().html() {
                Ok(html) if !html.is_empty() => Ok(Some(ClipboardPayload::Html {
                    html,
                    alt_text: String::new(),
                })),
                _ => Ok(None),
            },
            Err(e) => Err(Error::Backend(e.to_string())),
        },
        Err(e) => Err(Error::Backend(e.to_string())),
    }
}

/// Write a [`ClipboardPayload`] to the OS clipboard. Runs on the dedicated
/// arboard thread. The image bytes are borrowed from the payload (no copy).
fn arboard_set(clipboard: &mut arboard::Clipboard, payload: &ClipboardPayload) -> Result<()> {
    let r = match payload {
        ClipboardPayload::Text(text) => clipboard.set_text(text.as_str()),
        ClipboardPayload::Html { html, alt_text } => {
            clipboard.set_html(html.as_str(), Some(alt_text.as_str()))
        }
        ClipboardPayload::Image { width, height, rgba } => {
            clipboard.set_image(arboard::ImageData {
                width: *width as usize,
                height: *height as usize,
                bytes: Cow::Borrowed(rgba),
            })
        }
    };
    r.map_err(|e| Error::Backend(e.to_string()))
}

// ---------------------------------------------------------------------------
// Mock backend (used by ucb-sync integration tests; not feature-gated)
// ---------------------------------------------------------------------------

/// Handle to a [`MockClipboard`]'s shared state, so tests can inject "external"
/// clipboard changes and inspect what the service wrote.
///
/// The shared state is a full [`ClipboardPayload`] (SYNC-4). The string-based
/// [`set`](Self::set) / [`get`](Self::get) helpers are retained for existing
/// text-only tests; [`set_payload`](Self::set_payload) /
/// [`get_payload`](Self::get_payload) drive the full multi-format surface.
#[derive(Clone)]
pub struct MockClipboardHandle {
    state: Arc<Mutex<MockState>>,
}

/// Shared mock clipboard contents. Holds at most one of an inline payload or a
/// file-reference list at a time, mirroring a real clipboard where copying text
/// clears any previously-copied files and vice versa.
#[derive(Default)]
struct MockState {
    payload: Option<ClipboardPayload>,
    files: Option<Vec<PathBuf>>,
}

impl MockClipboardHandle {
    /// Simulate an external app copying plain `text` to the clipboard.
    pub fn set(&self, text: impl Into<String>) {
        self.set_payload(ClipboardPayload::Text(text.into()));
    }

    /// Simulate an external app copying an arbitrary payload to the clipboard.
    pub fn set_payload(&self, payload: ClipboardPayload) {
        let mut s = self.state.lock().expect("mock clipboard poisoned");
        s.payload = Some(payload);
        s.files = None;
    }

    /// Simulate an external app copying file references (FILE-1).
    pub fn set_files(&self, paths: Vec<PathBuf>) {
        let mut s = self.state.lock().expect("mock clipboard poisoned");
        s.files = Some(paths);
        s.payload = None;
    }

    /// Simulate the clipboard being cleared / holding unsupported content.
    pub fn clear(&self) {
        let mut s = self.state.lock().expect("mock clipboard poisoned");
        s.payload = None;
        s.files = None;
    }

    /// Read the current mock clipboard contents as text (e.g. to assert what
    /// the service wrote). Returns the text for `Text`, the plain-text
    /// alternative for `Html`, and `None` for images / files / empty.
    pub fn get(&self) -> Option<String> {
        match &self.state.lock().expect("mock clipboard poisoned").payload {
            Some(ClipboardPayload::Text(s)) => Some(s.clone()),
            Some(ClipboardPayload::Html { alt_text, .. }) => Some(alt_text.clone()),
            _ => None,
        }
    }

    /// Read the current mock clipboard contents as a full payload.
    pub fn get_payload(&self) -> Option<ClipboardPayload> {
        self.state.lock().expect("mock clipboard poisoned").payload.clone()
    }

    /// Read the file references currently on the mock clipboard (FILE-1). Used
    /// by tests to assert what the service wrote via [`ClipboardWriter::write_files`].
    pub fn get_files(&self) -> Option<Vec<PathBuf>> {
        self.state.lock().expect("mock clipboard poisoned").files.clone()
    }
}

/// In-memory [`SystemClipboard`] backed by shared state, for tests. Create with
/// [`MockClipboard::new`], which also hands back a [`MockClipboardHandle`] for
/// injecting changes from the test thread.
pub struct MockClipboard {
    state: Arc<Mutex<MockState>>,
}

impl MockClipboard {
    /// Create a mock clipboard (initially empty) and a handle to its state.
    pub fn new() -> (Self, MockClipboardHandle) {
        let state = Arc::new(Mutex::new(MockState::default()));
        (
            MockClipboard {
                state: Arc::clone(&state),
            },
            MockClipboardHandle { state },
        )
    }
}

impl SystemClipboard for MockClipboard {
    fn get(&mut self) -> Result<Option<ClipboardPayload>> {
        Ok(self.state.lock().expect("mock clipboard poisoned").payload.clone())
    }

    fn set(&mut self, payload: &ClipboardPayload) -> Result<()> {
        let mut s = self.state.lock().expect("mock clipboard poisoned");
        s.payload = Some(payload.clone());
        s.files = None;
        Ok(())
    }

    fn get_files(&mut self) -> Result<Option<Vec<PathBuf>>> {
        Ok(self.state.lock().expect("mock clipboard poisoned").files.clone())
    }

    fn set_files(&mut self, paths: &[PathBuf]) -> Result<bool> {
        let mut s = self.state.lock().expect("mock clipboard poisoned");
        s.files = Some(paths.to_vec());
        s.payload = None;
        Ok(true)
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
    /// FILE-1: place file references on the clipboard, falling back to writing
    /// the paths as text if the backend has no file-reference support.
    WriteFiles {
        paths: Vec<PathBuf>,
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

    /// Place `paths` on the OS clipboard as real file references (FILE-1) and
    /// mark them as our own write so the watcher suppresses the resulting change
    /// event. If the backend cannot write file references, the paths are written
    /// as newline-joined text instead (and that text write is echo-suppressed).
    /// Resolves `Ok` when either the file-reference or the text fallback write
    /// succeeds.
    pub async fn write_files(&self, paths: Vec<PathBuf>) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(WorkerCmd::WriteFiles { paths, reply })
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
    ) -> (ClipboardWriter, mpsc::Receiver<ClipboardEvent>) {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<WorkerCmd>();
        let (event_tx, event_rx) = mpsc::channel::<ClipboardEvent>(64);

        // Establish the baseline synchronously so pre-existing content is not
        // emitted as a spurious change and does not race the first real change.
        // Baselines for file references and inline payloads are tracked
        // independently (they are mutually exclusive on a real clipboard).
        let initial_files = match clipboard.get_files() {
            Ok(Some(paths)) if !paths.is_empty() => Some(hash_paths(&paths)),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = %e, "initial clipboard file read failed");
                None
            }
        };
        let initial_seen = match clipboard.get() {
            Ok(Some(payload)) => Some(payload.content_hash()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "initial clipboard read failed");
                None
            }
        };

        thread::Builder::new()
            .name("ucb-clipboard-watch".into())
            .spawn(move || {
                worker_loop(clipboard, poll_interval, cmd_rx, event_tx, initial_seen, initial_files)
            })
            .expect("failed to spawn clipboard watch thread");

        (ClipboardWriter { tx: cmd_tx }, event_rx)
    }
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
    event_tx: mpsc::Sender<ClipboardEvent>,
    initial_seen: Option<[u8; 32]>,
    initial_files: Option<[u8; 32]>,
) {
    // Baseline is read synchronously in `ClipboardService::start` so that
    // pre-existing content is neither emitted nor able to race a real change.
    // File references and inline payloads track their own last-seen/last-written
    // tokens (they are mutually exclusive on a real clipboard).
    let mut last_seen: Option<[u8; 32]> = initial_seen;
    let mut last_written: Option<[u8; 32]> = None;
    let mut last_seen_files: Option<[u8; 32]> = initial_files;
    let mut last_written_files: Option<[u8; 32]> = None;

    loop {
        match cmd_rx.recv_timeout(poll_interval) {
            Ok(WorkerCmd::Write { payload, reply }) => {
                // Full multi-format write (SYNC-4): text, HTML, or image.
                let res = clipboard.set(&payload);
                if res.is_ok() {
                    // Record our own write so the resulting change is suppressed
                    // (echo-loop prevention across all variants, SYNC-2). The
                    // hash is format-aware via ClipboardPayload::content_hash.
                    last_written = Some(payload.content_hash());
                }
                let _ = reply.send(res);
            }
            Ok(WorkerCmd::WriteFiles { paths, reply }) => {
                // FILE-1: prefer a real OS file reference; fall back to text.
                match clipboard.set_files(&paths) {
                    Ok(true) => {
                        // Suppress the echo of our own file-list write (SYNC-2).
                        last_written_files = Some(hash_paths(&paths));
                        let _ = reply.send(Ok(()));
                    }
                    // Unsupported or failed native write: write paths as text and
                    // let the payload echo-suppression path handle the echo.
                    Ok(false) | Err(_) => {
                        let payload = ClipboardPayload::Text(paths_as_text(&paths));
                        let res = clipboard.set(&payload);
                        if res.is_ok() {
                            last_written = Some(payload.content_hash());
                        }
                        let _ = reply.send(res);
                    }
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // Read priority (FILE-1): file references first, then inline
                // content (image > HTML > text, handled inside `clipboard.get`).
                match clipboard.get_files() {
                    Ok(Some(paths)) if !paths.is_empty() => {
                        let h = hash_paths(&paths);
                        if Some(h) != last_seen_files {
                            let was_echo = last_written_files == Some(h);
                            last_written_files = None;
                            last_seen_files = Some(h);
                            if !was_echo && event_tx.blocking_send(ClipboardEvent::Files(paths)).is_err()
                            {
                                break; // event receiver dropped -> shut down
                            }
                        }
                    }
                    // No file references: fall through to the inline-payload read.
                    Ok(_) => match clipboard.get() {
                        Ok(Some(payload)) => {
                            let h = payload.content_hash();
                            if Some(h) != last_seen {
                                let was_echo = last_written == Some(h);
                                // Any observed change consumes the echo token.
                                last_written = None;
                                last_seen = Some(h);
                                if !was_echo {
                                    // Skip payloads too large to send inline; never
                                    // log content (SEC-2), only the size.
                                    if payload.byte_len() > MAX_CLIP_BYTES {
                                        tracing::warn!(
                                            bytes = payload.byte_len(),
                                            max = MAX_CLIP_BYTES,
                                            "clipboard payload exceeds MAX_CLIP_BYTES; skipping"
                                        );
                                    } else if event_tx
                                        .blocking_send(ClipboardEvent::Payload(payload))
                                        .is_err()
                                    {
                                        break; // event receiver dropped -> shut down
                                    }
                                }
                            }
                        }
                        // Empty / unsupported clipboard content: nothing to report.
                        Ok(None) => {}
                        // Transient read error: log and keep polling.
                        Err(e) => tracing::warn!(error = %e, "clipboard read failed"),
                    },
                    // Transient file-read error: log and keep polling.
                    Err(e) => tracing::warn!(error = %e, "clipboard file read failed"),
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

    async fn recv_event(rx: &mut mpsc::Receiver<ClipboardEvent>) -> ClipboardEvent {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for a clipboard event")
            .expect("event channel closed unexpectedly")
    }

    /// Receive and unwrap the next event as an inline payload.
    async fn recv(rx: &mut mpsc::Receiver<ClipboardEvent>) -> ClipboardPayload {
        match recv_event(rx).await {
            ClipboardEvent::Payload(p) => p,
            ClipboardEvent::Files(f) => panic!("expected a payload event, got Files({f:?})"),
        }
    }

    /// Receive and unwrap the next event as a file-reference list.
    async fn recv_files(rx: &mut mpsc::Receiver<ClipboardEvent>) -> Vec<PathBuf> {
        match recv_event(rx).await {
            ClipboardEvent::Files(f) => f,
            ClipboardEvent::Payload(p) => panic!("expected a Files event, got Payload({p:?})"),
        }
    }

    /// Returns true if no event arrives within a window of several poll
    /// intervals (i.e. the watcher correctly stayed silent).
    async fn no_event(rx: &mut mpsc::Receiver<ClipboardEvent>) -> bool {
        tokio::time::timeout(Duration::from_millis(80), rx.recv())
            .await
            .is_err()
    }

    fn text(s: &str) -> ClipboardPayload {
        ClipboardPayload::Text(s.into())
    }

    fn html(html: &str, alt: &str) -> ClipboardPayload {
        ClipboardPayload::Html { html: html.into(), alt_text: alt.into() }
    }

    fn image(width: u32, height: u32, rgba: Vec<u8>) -> ClipboardPayload {
        ClipboardPayload::Image { width, height, rgba }
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

    // ---- SYNC-4: multi-format payloads ------------------------------------

    #[tokio::test]
    async fn html_payload_roundtrip_through_service() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        // Injected external HTML is emitted as a full Html payload.
        let injected = html("<b>hi</b>", "hi");
        handle.set_payload(injected.clone());
        assert_eq!(recv(&mut rx).await, injected);

        // Writing our own (different) HTML back is echo-suppressed.
        let written = html("<i>yo</i>", "yo");
        writer.write(written.clone()).await.unwrap();
        assert!(no_event(&mut rx).await, "own html write must not echo back");
        assert_eq!(handle.get_payload(), Some(written));

        // A genuine external change afterwards is still reported.
        handle.set("plain");
        assert_eq!(recv(&mut rx).await, text("plain"));
    }

    #[tokio::test]
    async fn image_payload_change_detection_and_echo_prevention() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        let img = image(2, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        handle.set_payload(img.clone());
        assert_eq!(recv(&mut rx).await, img);

        // Same image injected again -> no duplicate event (format-aware hash).
        handle.set_payload(img.clone());
        assert!(no_event(&mut rx).await, "duplicate image should not emit");

        // Our own image write is echo-suppressed.
        let img2 = image(1, 1, vec![9, 9, 9, 9]);
        writer.write(img2.clone()).await.unwrap();
        assert!(no_event(&mut rx).await, "own image write must not echo back");
        assert_eq!(handle.get_payload(), Some(img2));
    }

    #[tokio::test]
    async fn oversized_payload_is_skipped() {
        let (mock, handle) = MockClipboard::new();
        let (_writer, mut rx) = ClipboardService::start(mock, POLL);

        // Cheaply construct an image whose RGBA buffer exceeds MAX_CLIP_BYTES.
        let big = image(1, 1, vec![0u8; ucb_core::MAX_CLIP_BYTES + 1]);
        handle.set_payload(big);
        assert!(no_event(&mut rx).await, "oversized payload must be skipped");

        // The watcher keeps working: a normal change afterwards is reported.
        handle.set("ok");
        assert_eq!(recv(&mut rx).await, text("ok"));
    }

    #[test]
    fn distinct_hashes_for_text_and_html() {
        // Format-aware hashing keeps Text("x") and Html{html:"x",..} distinct,
        // which is what makes cross-format echo suppression correct.
        assert_ne!(
            text("x").content_hash(),
            html("x", "x").content_hash(),
            "Text and Html with the same string must not collide"
        );
    }

    // ---- FILE-1: file-reference detection ---------------------------------

    fn paths(ps: &[&str]) -> Vec<PathBuf> {
        ps.iter().map(PathBuf::from).collect()
    }

    #[tokio::test]
    async fn file_list_change_detection_and_dedup() {
        let (mock, handle) = MockClipboard::new();
        let (_writer, mut rx) = ClipboardService::start(mock, POLL);

        let a = paths(&["/tmp/a.bin"]);
        handle.set_files(a.clone());
        assert_eq!(recv_files(&mut rx).await, a);

        // Same list injected again -> no duplicate event (order-independent hash).
        handle.set_files(paths(&["/tmp/a.bin"]));
        assert!(no_event(&mut rx).await, "duplicate file list should not emit");

        // A different list is reported.
        let b = paths(&["/tmp/a.bin", "/tmp/b.bin"]);
        handle.set_files(b.clone());
        assert_eq!(recv_files(&mut rx).await, b);
    }

    #[tokio::test]
    async fn file_list_has_priority_over_text_when_both_present() {
        // A backend that always reports text, and reports a file list once the
        // shared slot is populated. When both are present the watcher must
        // prefer the file list (files > image > html > text).
        struct BothClipboard {
            files: Arc<Mutex<Option<Vec<PathBuf>>>>,
        }
        impl SystemClipboard for BothClipboard {
            fn get(&mut self) -> Result<Option<ClipboardPayload>> {
                Ok(Some(ClipboardPayload::Text("path-as-text".into())))
            }
            fn set(&mut self, _p: &ClipboardPayload) -> Result<()> {
                Ok(())
            }
            fn get_files(&mut self) -> Result<Option<Vec<PathBuf>>> {
                Ok(self.files.lock().unwrap().clone())
            }
        }
        let slot = Arc::new(Mutex::new(None));
        let (_writer, mut rx) = ClipboardService::start(
            BothClipboard { files: slot.clone() },
            POLL,
        );
        // Baseline captured text; now surface a file list alongside the text.
        let f = paths(&["/tmp/x", "/tmp/y"]);
        *slot.lock().unwrap() = Some(f.clone());
        assert_eq!(recv_files(&mut rx).await, f, "files must win over coexisting text");
    }

    #[tokio::test]
    async fn write_files_is_echo_suppressed_then_external_reported() {
        let (mock, handle) = MockClipboard::new();
        let (writer, mut rx) = ClipboardService::start(mock, POLL);

        // Our own file-reference write must not echo back as a fresh event.
        let f = paths(&["/tmp/recv/payload.bin"]);
        writer.write_files(f.clone()).await.unwrap();
        assert!(no_event(&mut rx).await, "own file write must not echo back");
        // The write actually reached the (mock) clipboard as a file reference.
        assert_eq!(handle.get_files(), Some(f));

        // A genuine external file copy afterwards is still reported.
        let g = paths(&["/tmp/other.bin"]);
        handle.set_files(g.clone());
        assert_eq!(recv_files(&mut rx).await, g);
    }

    #[test]
    fn hash_paths_is_order_independent_and_collision_resistant() {
        // Order independence: same set in a different order hashes identically.
        assert_eq!(
            hash_paths(&paths(&["/a", "/b"])),
            hash_paths(&paths(&["/b", "/a"])),
        );
        // Distinct lists differ.
        assert_ne!(hash_paths(&paths(&["/a"])), hash_paths(&paths(&["/b"])));
        assert_ne!(hash_paths(&paths(&["/a"])), hash_paths(&paths(&["/a", "/b"])));
        // The length prefix prevents boundary collisions ("/ab"+"/c" vs "/a"+"/bc").
        assert_ne!(
            hash_paths(&paths(&["/ab", "/c"])),
            hash_paths(&paths(&["/a", "/bc"])),
        );
    }
}
