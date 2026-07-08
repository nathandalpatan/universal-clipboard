//! ucb-files — transport-agnostic file transfer for Universal Clipboard.
//!
//! See ARCHITECTURE.md (Wave 2 section). This crate implements the sender /
//! receiver state machines behind the `FileOffer/FileAccept/FileReject/
//! FileChunk/FileDone` wire contract from `ucb-core`. It owns no socket: the
//! engine pumps [`WireMessage`]s in and out.
//!
//! Tickets: FILE-2 (chunking + BLAKE3), FILE-4 (streaming + progress),
//! FILE-5 (resume), FILE-6 (temp storage + completion), FILE-7 (cleanup).
//! FILE-3 (encryption) is satisfied by the session-channel AEAD, so there is
//! no crypto here.
//!
//! ## Message pumping (intended engine integration)
//!
//! Sender side:
//! 1. `let (mut send, offer) = SendTransfer::offer(path).await?;` — transmit `offer`.
//! 2. On an inbound message, call `send.on_message(msg)`:
//!    - `SendAction::Accepted { .. }` → repeatedly call `send.next_chunk().await?`
//!      and transmit each `Some(FileChunk)` until it yields `None`.
//!    - `SendAction::Rejected`/`Done` → the transfer is finished.
//! 3. `send.progress()` reports `(sent_chunks, total_chunks)`.
//!
//! Receiver side:
//! 1. `let (mut recv, accept) = RecvTransfer::on_offer(offer, dest_dir).await?;`
//!    — transmit `accept` (a `FileAccept` carrying `resume_from`).
//! 2. If `recv.is_complete()` (an empty, 0-chunk file), call `recv.finish().await?`
//!    and transmit `FileDone { ok: true, .. }`.
//! 3. For each inbound `FileChunk { index, data }`, call
//!    `recv.on_chunk(index, &data.0).await`:
//!    - `Ok(RecvProgress::InProgress { .. })` → keep going.
//!    - `Ok(RecvProgress::Completed { path })` → transmit `FileDone { ok: true, .. }`.
//!    - `Err(..)` → transmit `FileDone { ok: false, detail }` and drop the transfer.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use ucb_core::{ChunkData, WireMessage, FILE_CHUNK_BYTES};

/// Flush the `.part` file and rewrite the sidecar every this many chunks
/// (FILE-6). Also always done on completion.
const FLUSH_EVERY: u64 = 16;

/// Errors surfaced by the file-transfer state machines.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message is not a FileOffer")]
    NotAnOffer,
    #[error("path has no file name component")]
    NoFileName,
    #[error("out-of-order chunk: got {got}, expected {expected}")]
    OutOfOrder { got: u64, expected: u64 },
    #[error("unexpected chunk {index}: transfer already has all {chunk_count} chunks")]
    UnexpectedChunk { index: u64, chunk_count: u64 },
    #[error("chunk {index} has wrong length: got {got}, expected {expected}")]
    BadChunkLength {
        index: u64,
        got: usize,
        expected: usize,
    },
    #[error("hash mismatch: received content does not match the offer")]
    HashMismatch,
    #[error("invalid destination file name: {0:?}")]
    BadName(String),
    #[error("transfer already finished")]
    AlreadyFinished,
    #[error("sidecar json error: {0}")]
    Json(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, FileError>;

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Outcome of feeding an inbound [`WireMessage`] to a [`SendTransfer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendAction {
    /// The peer accepted; begin/continue emitting chunks from `resume_from`.
    Accepted { resume_from: u64 },
    /// The peer rejected the offer.
    Rejected { reason: String },
    /// The peer reported completion or abort (`FileDone`).
    Done { ok: bool, detail: String },
    /// The message did not concern this transfer; nothing changed.
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendState {
    Offered,
    Sending,
    Rejected,
    Done,
}

/// Sender-side transfer state machine (FILE-2/4/5). Reads the source file
/// sequentially; never loads it fully into memory.
pub struct SendTransfer {
    transfer_id: u64,
    path: PathBuf,
    size: u64,
    chunk_count: u64,
    hash: [u8; 32],
    /// Index of the next chunk to emit (== number already sent/skipped).
    next_index: u64,
    file: Option<File>,
    state: SendState,
}

impl SendTransfer {
    /// Create a transfer from a source path (FILE-2). Computes the size,
    /// chunk count (`ceil(size / FILE_CHUNK_BYTES)`) and the whole-file BLAKE3
    /// via a streaming read, and mints a random `transfer_id`. Returns the
    /// machine plus the `FileOffer` message to transmit.
    pub async fn offer(path: impl AsRef<Path>) -> Result<(SendTransfer, WireMessage)> {
        let path = path.as_ref().to_path_buf();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(FileError::NoFileName)?
            .to_string();

        let size = tokio::fs::metadata(&path).await?.len();
        let chunk = FILE_CHUNK_BYTES as u64;
        let chunk_count = size.div_ceil(chunk); // 0 bytes -> 0 chunks
        let hash = hash_file(&path).await?;
        let transfer_id: u64 = rand::random();

        let offer = WireMessage::FileOffer {
            transfer_id,
            name,
            size,
            chunk_count,
            hash,
        };
        let st = SendTransfer {
            transfer_id,
            path,
            size,
            chunk_count,
            hash,
            next_index: 0,
            file: None,
            state: SendState::Offered,
        };
        Ok((st, offer))
    }

    /// The 32-byte whole-file BLAKE3 advertised in the offer.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// This transfer's id.
    pub fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    /// `(sent_chunks, total_chunks)` (FILE-4).
    pub fn progress(&self) -> (u64, u64) {
        (self.next_index, self.chunk_count)
    }

    /// React to an inbound message routed to this transfer. Messages for a
    /// different `transfer_id`, or unrelated variants, return
    /// [`SendAction::Ignored`].
    pub fn on_message(&mut self, msg: WireMessage) -> SendAction {
        match msg {
            WireMessage::FileAccept {
                transfer_id,
                resume_from,
            } if transfer_id == self.transfer_id => {
                self.next_index = resume_from.min(self.chunk_count);
                self.state = SendState::Sending;
                SendAction::Accepted { resume_from }
            }
            WireMessage::FileReject {
                transfer_id,
                reason,
            } if transfer_id == self.transfer_id => {
                self.state = SendState::Rejected;
                SendAction::Rejected { reason }
            }
            WireMessage::FileDone {
                transfer_id,
                ok,
                detail,
            } if transfer_id == self.transfer_id => {
                self.state = SendState::Done;
                SendAction::Done { ok, detail }
            }
            _ => SendAction::Ignored,
        }
    }

    /// Produce the next `FileChunk` message, or `None` when every chunk has
    /// been emitted (or the transfer is not in a sending state). Reads at most
    /// `FILE_CHUNK_BYTES` per call using async, sequential IO (FILE-4).
    pub async fn next_chunk(&mut self) -> Result<Option<WireMessage>> {
        if self.state != SendState::Sending || self.next_index >= self.chunk_count {
            return Ok(None);
        }
        let chunk = FILE_CHUNK_BYTES as u64;
        let offset = self.next_index * chunk;

        if self.file.is_none() {
            let mut f = File::open(&self.path).await?;
            if offset > 0 {
                f.seek(SeekFrom::Start(offset)).await?;
            }
            self.file = Some(f);
        }

        let remaining = self.size - offset;
        let to_read = remaining.min(chunk) as usize;
        let mut buf = vec![0u8; to_read];
        // Sequential: the handle is already positioned at `offset`.
        self.file
            .as_mut()
            .expect("file opened above")
            .read_exact(&mut buf)
            .await?;

        let msg = WireMessage::FileChunk {
            transfer_id: self.transfer_id,
            index: self.next_index,
            data: ChunkData(buf),
        };
        self.next_index += 1;
        Ok(Some(msg))
    }
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

/// Progress reported by [`RecvTransfer::on_chunk`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecvProgress {
    /// More chunks are still expected.
    InProgress { received: u64, total: u64 },
    /// The final chunk arrived, the hash verified, and the file was moved to
    /// its final location.
    Completed { path: PathBuf },
}

/// Sidecar recorded next to the `.part` file so a transfer can resume across
/// process restarts (FILE-5).
#[derive(Serialize, Deserialize)]
struct MetaSidecar {
    name: String,
    size: u64,
    chunk_count: u64,
    /// Hex-encoded whole-file BLAKE3 from the offer.
    hash: String,
    /// Number of contiguous chunks flushed to the `.part` file so far.
    received_up_to: u64,
}

/// Receiver-side transfer state machine (FILE-5/6). Streams incoming chunks
/// to `<dest_dir>/<transfer_id>.part`, verifies the whole-file hash on
/// completion, then renames to a sanitized final name inside `dest_dir`.
pub struct RecvTransfer {
    transfer_id: u64,
    name: String,
    size: u64,
    chunk_count: u64,
    hash: [u8; 32],
    dest_dir: PathBuf,
    part_path: PathBuf,
    meta_path: PathBuf,
    /// Number of contiguous chunks written (the next expected index).
    received: u64,
    file: File,
    hasher: blake3::Hasher,
    since_flush: u64,
    finished: bool,
}

impl RecvTransfer {
    /// Accept an offer (FILE-5/6). Creates `dest_dir` if needed, and — if a
    /// matching `.part` + sidecar already exist — resumes from the last flushed
    /// chunk. Returns the machine and a `FileAccept` carrying `resume_from`.
    pub async fn on_offer(
        offer: WireMessage,
        dest_dir: impl AsRef<Path>,
    ) -> Result<(RecvTransfer, WireMessage)> {
        let (transfer_id, name, size, chunk_count, hash) = match offer {
            WireMessage::FileOffer {
                transfer_id,
                name,
                size,
                chunk_count,
                hash,
            } => (transfer_id, name, size, chunk_count, hash),
            _ => return Err(FileError::NotAnOffer),
        };

        let dest_dir = dest_dir.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&dest_dir).await?;
        // A fresh transfer keys its files by this offer's (random) transfer_id.
        let default_part = dest_dir.join(format!("{transfer_id}.part"));
        let default_meta = dest_dir.join(format!("{transfer_id}.meta.json"));

        // Resume matches on the file's identity (hash + size + chunk_count),
        // not on transfer_id (which is random per offer), so scan the dir for a
        // sidecar that matches this offer and adopt its .part file.
        let resume = scan_for_resume(&dest_dir, size, chunk_count, &hash).await;

        let (part_path, meta_path, received, file, hasher) = match resume {
            Some((part_path, meta_path, received)) => {
                let expected_len = bytes_for_chunks(received, chunk_count, size);
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&part_path)
                    .await?;
                // Drop any partial bytes written after the last flushed chunk.
                file.set_len(expected_len).await?;
                // Rebuild the incremental hasher from the retained prefix.
                file.seek(SeekFrom::Start(0)).await?;
                let mut hasher = blake3::Hasher::new();
                let mut remaining = expected_len;
                let mut buf = vec![0u8; FILE_CHUNK_BYTES];
                while remaining > 0 {
                    let want = (remaining as usize).min(FILE_CHUNK_BYTES);
                    file.read_exact(&mut buf[..want]).await?;
                    hasher.update(&buf[..want]);
                    remaining -= want as u64;
                }
                // The cursor now sits at `expected_len`, ready to append.
                (part_path, meta_path, received, file, hasher)
            }
            None => {
                // Fresh start: truncate/create the part and drop any stale meta.
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&default_part)
                    .await?;
                let _ = tokio::fs::remove_file(&default_meta).await;
                (default_part, default_meta, 0u64, file, blake3::Hasher::new())
            }
        };

        let st = RecvTransfer {
            transfer_id,
            name,
            size,
            chunk_count,
            hash,
            dest_dir,
            part_path,
            meta_path,
            received,
            file,
            hasher,
            since_flush: 0,
            finished: false,
        };
        let accept = WireMessage::FileAccept {
            transfer_id,
            resume_from: received,
        };
        Ok((st, accept))
    }

    /// This transfer's id.
    pub fn transfer_id(&self) -> u64 {
        self.transfer_id
    }

    /// `(received_chunks, total_chunks)`.
    pub fn progress(&self) -> (u64, u64) {
        (self.received, self.chunk_count)
    }

    /// The first chunk index still needed (what the `FileAccept` advertised).
    pub fn resume_from(&self) -> u64 {
        self.received
    }

    /// True when every chunk has been received. For a 0-chunk (empty) file
    /// this is true immediately after [`on_offer`](Self::on_offer); the engine
    /// should then call [`finish`](Self::finish).
    pub fn is_complete(&self) -> bool {
        self.received >= self.chunk_count
    }

    /// Accept the next chunk (FILE-4/5/6). `index` must equal the next expected
    /// index; an out-of-order or wrong-length chunk is rejected (the caller
    /// should then send `FileDone { ok: false }`). On the final chunk the
    /// whole-file hash is verified and the file is finalized.
    pub async fn on_chunk(&mut self, index: u64, data: &[u8]) -> Result<RecvProgress> {
        if self.finished {
            return Err(FileError::AlreadyFinished);
        }
        if self.received >= self.chunk_count {
            return Err(FileError::UnexpectedChunk {
                index,
                chunk_count: self.chunk_count,
            });
        }
        if index != self.received {
            return Err(FileError::OutOfOrder {
                got: index,
                expected: self.received,
            });
        }
        let expected = self.expected_chunk_len(index);
        if data.len() != expected {
            return Err(FileError::BadChunkLength {
                index,
                got: data.len(),
                expected,
            });
        }

        self.file.write_all(data).await?;
        self.hasher.update(data);
        self.received += 1;

        if self.received == self.chunk_count {
            let path = self.finish().await?;
            return Ok(RecvProgress::Completed { path });
        }

        self.since_flush += 1;
        if self.since_flush >= FLUSH_EVERY {
            self.file.flush().await?;
            self.write_meta().await?;
            self.since_flush = 0;
        }
        Ok(RecvProgress::InProgress {
            received: self.received,
            total: self.chunk_count,
        })
    }

    /// Verify the accumulated hash, then move the `.part` to a sanitized,
    /// deduplicated final path inside `dest_dir` and drop the sidecar (FILE-6).
    /// Normally invoked internally on the final chunk; call it directly only
    /// for a 0-chunk transfer (see [`is_complete`](Self::is_complete)). On hash
    /// mismatch the `.part` and sidecar are deleted and
    /// [`FileError::HashMismatch`] is returned.
    pub async fn finish(&mut self) -> Result<PathBuf> {
        if self.finished {
            return Err(FileError::AlreadyFinished);
        }
        self.file.flush().await?;
        self.file.sync_all().await?;

        let actual = *self.hasher.finalize().as_bytes();
        if actual != self.hash {
            let _ = tokio::fs::remove_file(&self.part_path).await;
            let _ = tokio::fs::remove_file(&self.meta_path).await;
            self.finished = true;
            return Err(FileError::HashMismatch);
        }

        let safe = sanitize_name(&self.name)?;
        let final_path = unique_path(&self.dest_dir, &safe);
        tokio::fs::rename(&self.part_path, &final_path).await?;
        let _ = tokio::fs::remove_file(&self.meta_path).await;
        self.finished = true;
        Ok(final_path)
    }

    fn expected_chunk_len(&self, index: u64) -> usize {
        let chunk = FILE_CHUNK_BYTES as u64;
        if index + 1 == self.chunk_count {
            (self.size - index * chunk) as usize
        } else {
            FILE_CHUNK_BYTES
        }
    }

    async fn write_meta(&self) -> Result<()> {
        let meta = MetaSidecar {
            name: self.name.clone(),
            size: self.size,
            chunk_count: self.chunk_count,
            hash: hex::encode(self.hash),
            received_up_to: self.received,
        };
        let json = serde_json::to_vec(&meta).map_err(|e| FileError::Json(e.to_string()))?;
        tokio::fs::write(&self.meta_path, json).await?;
        Ok(())
    }
}

/// Scan `dir` for a `*.meta.json` sidecar (and its `.part`) that matches this
/// offer's identity. Returns `(part_path, meta_path, chunks_to_keep)` for the
/// first match, or `None` to start fresh. Because `transfer_id` is random per
/// offer, resume is keyed on `hash + size + chunk_count`, not the id.
async fn scan_for_resume(
    dir: &Path,
    size: u64,
    chunk_count: u64,
    hash: &[u8; 32],
) -> Option<(PathBuf, PathBuf, u64)> {
    let want_hash = hex::encode(hash);
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) if n.ends_with(".meta.json") => n.to_string(),
            _ => continue,
        };
        let meta_path = entry.path();
        let bytes = match tokio::fs::read(&meta_path).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        let meta: MetaSidecar = match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.size != size || meta.chunk_count != chunk_count || meta.hash != want_hash {
            continue;
        }
        let stem = name.trim_end_matches(".meta.json");
        let part_path = dir.join(format!("{stem}.part"));
        let part_len = match tokio::fs::metadata(&part_path).await {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        let received = meta.received_up_to.min(chunk_count);
        let expected_len = bytes_for_chunks(received, chunk_count, size);
        // The part must hold at least the flushed prefix; trailing partials ok.
        if part_len < expected_len {
            continue;
        }
        return Some((part_path, meta_path, received));
    }
    None
}

/// Bytes occupied by the first `received` contiguous chunks.
fn bytes_for_chunks(received: u64, chunk_count: u64, size: u64) -> u64 {
    if received >= chunk_count {
        size
    } else {
        received * FILE_CHUNK_BYTES as u64
    }
}

// ---------------------------------------------------------------------------
// Filename safety
// ---------------------------------------------------------------------------

/// Reduce an offered name to a single safe component that always lands directly
/// inside the destination directory (guards against `../` traversal).
fn sanitize_name(name: &str) -> Result<String> {
    // Strip everything up to the last path separator (both unix and windows).
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    if base.is_empty() || base == "." || base == ".." {
        return Err(FileError::BadName(name.to_string()));
    }
    Ok(base.to_string())
}

/// A path inside `dir` for `name`, adding a `" (n)"` suffix if it already
/// exists (FILE-6).
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = p.extension().and_then(|s| s.to_str());
    let mut n: u64 = 1;
    loop {
        let fname = match ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = dir.join(fname);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

// ---------------------------------------------------------------------------
// Cleanup (FILE-7)
// ---------------------------------------------------------------------------

/// Summary returned by [`cleanup_stale`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Number of files removed.
    pub removed: usize,
    /// Total bytes reclaimed.
    pub bytes_freed: u64,
}

/// Remove stale `*.part` and `*.meta.json` files under `dir` older than
/// `max_age` (by mtime), leaving all other files untouched (FILE-7). Callers
/// run this at startup and periodically. A missing directory is treated as
/// empty.
pub async fn cleanup_stale(dir: impl AsRef<Path>, max_age: Duration) -> Result<CleanupReport> {
    let dir = dir.as_ref();
    let mut report = CleanupReport::default();

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(e) => return Err(e.into()),
    };

    let now = std::time::SystemTime::now();
    while let Some(entry) = rd.next_entry().await? {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        if !(name.ends_with(".part") || name.ends_with(".meta.json")) {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified()?;
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age > max_age {
            let len = meta.len();
            if tokio::fs::remove_file(entry.path()).await.is_ok() {
                report.removed += 1;
                report.bytes_freed += len;
            }
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whole-file BLAKE3 via a streaming read (never buffers the whole file).
async fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut f = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_BYTES];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A unique temp dir under the system temp dir (no network, per task).
    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("ucb-files-test-{tag}-{pid}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn patterned(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    async fn write_file(path: &Path, bytes: &[u8]) {
        tokio::fs::write(path, bytes).await.unwrap();
    }

    fn offer_fields(msg: &WireMessage) -> (u64, u64) {
        match msg {
            WireMessage::FileOffer {
                transfer_id,
                chunk_count,
                ..
            } => (*transfer_id, *chunk_count),
            other => panic!("expected FileOffer, got {other:?}"),
        }
    }

    /// Drive a sender and receiver against each other to completion, returning
    /// the final delivered path.
    async fn run_to_completion(send: &mut SendTransfer, recv: &mut RecvTransfer) -> PathBuf {
        // Sender consumes the accept and starts sending.
        loop {
            match send.next_chunk().await.unwrap() {
                Some(WireMessage::FileChunk { index, data, .. }) => {
                    match recv.on_chunk(index, &data.0).await.unwrap() {
                        RecvProgress::Completed { path } => return path,
                        RecvProgress::InProgress { .. } => {}
                    }
                }
                Some(other) => panic!("unexpected chunk message: {other:?}"),
                None => break,
            }
        }
        // 0-chunk (empty) file: nothing was sent; finalize directly.
        assert!(recv.is_complete());
        recv.finish().await.unwrap()
    }

    #[tokio::test]
    async fn round_trip_multi_chunk() {
        let dir = temp_dir("roundtrip");
        let src = dir.join("hello.bin");
        let dest = dir.join("dest");
        let bytes = patterned(1024 * 1024 + 7); // ~1 MiB, not a chunk multiple
        write_file(&src, &bytes).await;

        let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
        let (_id, chunk_count) = offer_fields(&offer);
        assert_eq!(chunk_count, (bytes.len() as u64).div_ceil(FILE_CHUNK_BYTES as u64));

        let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
        assert_eq!(
            send.on_message(accept),
            SendAction::Accepted { resume_from: 0 }
        );

        let path = run_to_completion(&mut send, &mut recv).await;
        assert_eq!(path, dest.join("hello.bin"));

        let out = tokio::fs::read(&path).await.unwrap();
        assert_eq!(out, bytes, "delivered bytes must be identical");
        let (sent, total) = send.progress();
        assert_eq!(sent, total);
        // No leftover part/meta.
        assert!(!dest.join(format!("{}.part", _id)).exists());
    }

    #[tokio::test]
    async fn empty_file_round_trips() {
        let dir = temp_dir("empty");
        let src = dir.join("empty.txt");
        let dest = dir.join("dest");
        write_file(&src, &[]).await;

        let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
        let (_id, chunk_count) = offer_fields(&offer);
        assert_eq!(chunk_count, 0);

        let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
        send.on_message(accept);
        let path = run_to_completion(&mut send, &mut recv).await;

        assert_eq!(path, dest.join("empty.txt"));
        assert_eq!(tokio::fs::metadata(&path).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resume_from_last_flushed_chunk() {
        let dir = temp_dir("resume");
        let src = dir.join("big.bin");
        let dest = dir.join("dest");
        // 20 chunks so the meta is flushed at chunk 16.
        let bytes = patterned(FILE_CHUNK_BYTES * 20);
        write_file(&src, &bytes).await;

        // First attempt: deliver exactly 16 chunks then "crash".
        let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
        let (id, _) = offer_fields(&offer);
        {
            let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
            send.on_message(accept);
            for _ in 0..16 {
                let msg = send.next_chunk().await.unwrap().unwrap();
                if let WireMessage::FileChunk { index, data, .. } = msg {
                    recv.on_chunk(index, &data.0).await.unwrap();
                }
            }
            // Force a flush of file + meta at the boundary.
            recv.file.flush().await.unwrap();
            recv.write_meta().await.unwrap();
            drop(recv); // keep .part + .meta on disk
        }
        assert!(dest.join(format!("{id}.part")).exists());
        assert!(dest.join(format!("{id}.meta.json")).exists());

        // Second attempt: a fresh offer for the same file must resume at 16.
        let (mut send2, offer2) = SendTransfer::offer(&src).await.unwrap();
        let (mut recv2, accept2) = RecvTransfer::on_offer(offer2, &dest).await.unwrap();
        match &accept2 {
            WireMessage::FileAccept { resume_from, .. } => assert_eq!(*resume_from, 16),
            other => panic!("expected FileAccept, got {other:?}"),
        }
        assert_eq!(
            send2.on_message(accept2),
            SendAction::Accepted { resume_from: 16 }
        );

        // The sender must not re-emit chunks below 16.
        let mut first_index = None;
        loop {
            match send2.next_chunk().await.unwrap() {
                Some(WireMessage::FileChunk { index, data, .. }) => {
                    if first_index.is_none() {
                        first_index = Some(index);
                    }
                    if let RecvProgress::Completed { path } =
                        recv2.on_chunk(index, &data.0).await.unwrap()
                    {
                        let out = tokio::fs::read(&path).await.unwrap();
                        assert_eq!(out, bytes);
                    }
                }
                Some(other) => panic!("unexpected: {other:?}"),
                None => break,
            }
        }
        assert_eq!(first_index, Some(16), "resume must start at chunk 16");
    }

    #[tokio::test]
    async fn corrupted_part_fails_hash_and_is_removed() {
        let dir = temp_dir("corrupt");
        let src = dir.join("big.bin");
        let dest = dir.join("dest");
        let bytes = patterned(FILE_CHUNK_BYTES * 20);
        write_file(&src, &bytes).await;

        let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
        let (id, _) = offer_fields(&offer);
        {
            let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
            send.on_message(accept);
            for _ in 0..16 {
                let msg = send.next_chunk().await.unwrap().unwrap();
                if let WireMessage::FileChunk { index, data, .. } = msg {
                    recv.on_chunk(index, &data.0).await.unwrap();
                }
            }
            recv.file.flush().await.unwrap();
            recv.write_meta().await.unwrap();
            drop(recv);
        }

        // Flip a byte in the retained prefix of the .part file.
        let part = dest.join(format!("{id}.part"));
        let mut data = tokio::fs::read(&part).await.unwrap();
        data[100] ^= 0xff;
        tokio::fs::write(&part, &data).await.unwrap();

        // Resume and run to the end; the whole-file hash must fail.
        let (mut send2, offer2) = SendTransfer::offer(&src).await.unwrap();
        let (mut recv2, accept2) = RecvTransfer::on_offer(offer2, &dest).await.unwrap();
        send2.on_message(accept2);
        let mut err = None;
        loop {
            match send2.next_chunk().await.unwrap() {
                Some(WireMessage::FileChunk { index, data, .. }) => {
                    match recv2.on_chunk(index, &data.0).await {
                        Ok(RecvProgress::Completed { .. }) => panic!("should not complete"),
                        Ok(RecvProgress::InProgress { .. }) => {}
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                Some(_) => unreachable!(),
                None => break,
            }
        }
        assert!(matches!(err, Some(FileError::HashMismatch)));
        assert!(!part.exists(), ".part must be removed on hash mismatch");
    }

    #[tokio::test]
    async fn out_of_order_chunk_rejected() {
        let dir = temp_dir("ooo");
        let src = dir.join("f.bin");
        let dest = dir.join("dest");
        let bytes = patterned(FILE_CHUNK_BYTES * 3);
        write_file(&src, &bytes).await;

        let (mut send, offer) = SendTransfer::offer(&src).await.unwrap();
        let (mut recv, accept) = RecvTransfer::on_offer(offer, &dest).await.unwrap();
        send.on_message(accept);

        // First chunk 0 is fine.
        let msg0 = send.next_chunk().await.unwrap().unwrap();
        if let WireMessage::FileChunk { index, data, .. } = msg0 {
            recv.on_chunk(index, &data.0).await.unwrap();
        }
        // Now feed index 2 out of order -> rejected.
        let good_len = FILE_CHUNK_BYTES;
        let err = recv
            .on_chunk(2, &vec![0u8; good_len])
            .await
            .unwrap_err();
        assert!(matches!(err, FileError::OutOfOrder { got: 2, expected: 1 }));
    }

    #[tokio::test]
    async fn sanitizes_traversal_and_dedupes() {
        let dir = temp_dir("sanitize");
        let dest = dir.join("dest");
        let src = dir.join("payload.bin");
        let bytes = patterned(1000);
        write_file(&src, &bytes).await;

        // Craft an offer whose name attempts path traversal.
        let (send_hash, size, chunk_count) = {
            let (s, offer) = SendTransfer::offer(&src).await.unwrap();
            let _ = s;
            match offer {
                WireMessage::FileOffer {
                    hash,
                    size,
                    chunk_count,
                    ..
                } => (hash, size, chunk_count),
                _ => unreachable!(),
            }
        };
        let evil = WireMessage::FileOffer {
            transfer_id: 1,
            name: "../../evil.txt".to_string(),
            size,
            chunk_count,
            hash: send_hash,
        };
        let (mut recv, _accept) = RecvTransfer::on_offer(evil, &dest).await.unwrap();
        // Feed the single chunk.
        let path = recv.on_chunk(0, &bytes).await.unwrap();
        let path = match path {
            RecvProgress::Completed { path } => path,
            _ => panic!("should complete"),
        };
        assert_eq!(path, dest.join("evil.txt"));
        assert_eq!(path.parent().unwrap(), dest, "must stay inside dest_dir");

        // A second transfer with the same name dedupes to "evil (1).txt".
        let evil2 = WireMessage::FileOffer {
            transfer_id: 2,
            name: "evil.txt".to_string(),
            size,
            chunk_count,
            hash: send_hash,
        };
        let (mut recv2, _a) = RecvTransfer::on_offer(evil2, &dest).await.unwrap();
        let path2 = match recv2.on_chunk(0, &bytes).await.unwrap() {
            RecvProgress::Completed { path } => path,
            _ => panic!("should complete"),
        };
        assert_eq!(path2, dest.join("evil (1).txt"));
    }

    #[test]
    fn empty_and_dot_names_rejected() {
        assert!(matches!(sanitize_name(""), Err(FileError::BadName(_))));
        assert!(matches!(sanitize_name("."), Err(FileError::BadName(_))));
        assert!(matches!(sanitize_name(".."), Err(FileError::BadName(_))));
        assert!(matches!(sanitize_name("a/b/.."), Err(FileError::BadName(_))));
        assert_eq!(sanitize_name("../../evil.txt").unwrap(), "evil.txt");
        assert_eq!(sanitize_name("plain.bin").unwrap(), "plain.bin");
    }

    #[tokio::test]
    async fn cleanup_removes_only_old_transfer_files() {
        let dir = temp_dir("cleanup");
        // Old transfer artifacts.
        let old_part = dir.join("111.part");
        let old_meta = dir.join("111.meta.json");
        // A recent part that must survive.
        let new_part = dir.join("222.part");
        // An unrelated file that must never be touched.
        let keep = dir.join("notes.txt");
        write_file(&old_part, &patterned(500)).await;
        write_file(&old_meta, b"{}").await;
        write_file(&new_part, &patterned(300)).await;
        write_file(&keep, b"keep me").await;

        // Backdate the old files well past the threshold.
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
        set_mtime(&old_part, long_ago);
        set_mtime(&old_meta, long_ago);

        let report = cleanup_stale(&dir, Duration::from_secs(60)).await.unwrap();
        assert_eq!(report.removed, 2);
        assert_eq!(report.bytes_freed, 500 + 2); // part + "{}"
        assert!(!old_part.exists());
        assert!(!old_meta.exists());
        assert!(new_part.exists(), "recent part must survive");
        assert!(keep.exists(), "unrelated file must survive");
    }

    // --- small mtime helper (std only, no extra deps) ---

    fn set_mtime(path: &Path, t: std::time::SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }
}
