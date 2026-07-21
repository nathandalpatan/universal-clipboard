//! File-backed clipboard for the headless integration test harness.
//!
//! This is test/automation plumbing, not a library feature — it lives in the
//! daemon rather than `ucb-clipboard`. It implements [`SystemClipboard`] over
//! three files in a directory (created if missing):
//!
//! * `clip-in`  — the harness writes clipboard *text* here to simulate a local
//!   copy; the watcher polls it (mtime + content) and treats a change as a new
//!   local clip.
//! * `clip-out` — every applied *remote* clip's text is truncate-written here.
//! * `clip-log.jsonl` — one JSON line per applied remote clip:
//!   `{ "ts_ms": <now>, "origin_short": "remote", "len": <bytes> }`.
//!
//! Note: the [`SystemClipboard`] write hook only receives clipboard text, not
//! the originating [`ucb_core::DeviceId`], so `origin_short` is a fixed
//! `"remote"` placeholder here (the wire-level origin is not plumbed through the
//! clipboard-writer API). `ts_ms` and `len` are exact.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ucb_clipboard::{Error, Result, SystemClipboard};
use ucb_core::ClipboardPayload;

/// A [`SystemClipboard`] backed by files under a directory (see module docs).
pub struct FileClipboard {
    in_path: PathBuf,
    out_path: PathBuf,
    log_path: PathBuf,
    /// mtime of `clip-in` at the last read, to skip re-reading unchanged files.
    last_mtime: Option<SystemTime>,
    last_content: Option<String>,
}

impl FileClipboard {
    /// Create a file-backed clipboard rooted at `dir`, creating the directory.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| Error::Backend(e.to_string()))?;
        Ok(Self {
            in_path: dir.join("clip-in"),
            out_path: dir.join("clip-out"),
            log_path: dir.join("clip-log.jsonl"),
            last_mtime: None,
            last_content: None,
        })
    }
}

impl SystemClipboard for FileClipboard {
    fn get(&mut self) -> Result<Option<ClipboardPayload>> {
        let meta = match fs::metadata(&self.in_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Backend(e.to_string())),
        };
        // Fast path: if the mtime is unchanged, return the cached content.
        let mtime = meta.modified().ok();
        if mtime.is_some() && mtime == self.last_mtime {
            return Ok(self.last_content.clone().map(ClipboardPayload::Text));
        }
        let content = fs::read_to_string(&self.in_path)
            .map_err(|e| Error::Backend(e.to_string()))?;
        let content = if content.is_empty() {
            None
        } else {
            Some(content)
        };
        self.last_mtime = mtime;
        self.last_content = content.clone();
        Ok(content.map(ClipboardPayload::Text))
    }

    fn set(&mut self, payload: &ClipboardPayload) -> Result<()> {
        // The headless harness is text-oriented: use the plain-text projection.
        let text = match payload {
            ClipboardPayload::Text(s) => s.clone(),
            ClipboardPayload::Html { alt_text, .. } => alt_text.clone(),
            ClipboardPayload::Image { width, height, .. } => format!("[image {width}x{height}]"),
        };
        // Truncate-write the applied remote clip to clip-out.
        fs::write(&self.out_path, text.as_bytes()).map_err(|e| Error::Backend(e.to_string()))?;

        // Append a JSON line to clip-log.jsonl. `origin_short` is a placeholder
        // (see module docs); ts_ms and len are exact.
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let line = format!(
            "{{\"ts_ms\":{},\"origin_short\":\"remote\",\"len\":{}}}\n",
            ts_ms,
            payload.byte_len()
        );
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| Error::Backend(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| Error::Backend(e.to_string()))?;
        Ok(())
    }
}
