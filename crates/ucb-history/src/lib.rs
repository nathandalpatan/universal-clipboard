//! ucb-history — encrypted local clipboard history (HIST-1/2/3 backend).
//!
//! See ARCHITECTURE.md (Wave 2) for the contract. This crate persists every
//! applied clip (local and remote) into a SQLCipher-encrypted SQLite database,
//! exposes a search/filter/star/delete API, and enforces age-based retention
//! (starred items are exempt).
//!
//! ## Security (SEC-2)
//! Clipboard content is never written to logs. [`HistoryEntry`]'s `Debug` impl
//! redacts `content`. The database itself is encrypted at rest: the 32-byte key
//! lives in the [`KeyStore`] under `"history-db-key"`, never in the DB file.
//!
//! ## Concurrency
//! [`History`] wraps a [`rusqlite::Connection`] in a [`Mutex`], so it is
//! `Send + Sync` and can be shared across async tasks (call it from
//! `tokio::task::spawn_blocking`). Every write holds the lock only for the
//! duration of a single short statement.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row, ToSql};
use serde::{Serialize, Serializer};
use ucb_core::{ClipboardItem, ClipboardPayload, DeviceId};
use ucb_crypto::KeyStore;

/// KeyStore entry name holding the 32-byte SQLCipher database key (HIST-1).
pub const DB_KEY_NAME: &str = "history-db-key";

/// Current on-disk schema version (stored in `PRAGMA user_version`).
const SCHEMA_VERSION: i64 = 1;

/// Default number of rows returned by [`History::list`] when the query's
/// `limit` is left at 0.
pub const DEFAULT_LIMIT: usize = 50;

/// Errors produced by the history store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failure from the underlying SQLite/SQLCipher engine.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The [`KeyStore`] failed to read or write the database key.
    #[error("keystore error: {0}")]
    KeyStore(String),

    /// The key stored under [`DB_KEY_NAME`] was not 32 bytes.
    #[error("stored history key is invalid: {0}")]
    InvalidKey(String),

    /// The database could not be decrypted — wrong key or corrupt file.
    #[error("history database could not be decrypted (wrong key or corrupt)")]
    WrongKey,
}

/// Convenience alias for this crate's fallible API.
pub type Result<T> = std::result::Result<T, Error>;

/// One persisted clipboard event.
///
/// Mirrors a row of the `items` table. `content` holds full text for text
/// clips, the plain-text alternative for HTML clips, and `None` for images
/// (which store only dimensions + hash + byte length to save space).
///
/// `Serialize` is derived for the forthcoming CLI/JSON output; `content_hash`
/// serializes as a lowercase hex string. `Debug` redacts `content` (SEC-2).
#[derive(Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    /// Milliseconds since the UNIX epoch (originating device's clock).
    pub ts_ms: u64,
    /// Full hex `DeviceId` of the clip's origin.
    pub origin_id: String,
    /// Human-readable name of the origin device at record time.
    pub origin_name: String,
    /// `"text"`, `"html"`, or `"image"`.
    pub kind: String,
    /// Full text (text), alt text (html), or `None` (image).
    pub content: Option<String>,
    /// BLAKE3 content hash, hex-encoded when serialized.
    #[serde(serialize_with = "serialize_hash_hex")]
    pub content_hash: [u8; 32],
    /// Payload size in bytes.
    pub byte_len: u64,
    /// Image width in pixels (images only).
    pub width: Option<u32>,
    /// Image height in pixels (images only).
    pub height: Option<u32>,
    /// Whether the user has starred this entry (retention-exempt).
    pub starred: bool,
    /// Milliseconds since the UNIX epoch when the row was inserted locally.
    pub created_ms: u64,
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SEC-2: never render clipboard content.
        let content = self
            .content
            .as_ref()
            .map(|c| format!("<{} bytes redacted>", c.len()));
        f.debug_struct("HistoryEntry")
            .field("id", &self.id)
            .field("ts_ms", &self.ts_ms)
            .field("origin_id", &self.origin_id)
            .field("origin_name", &self.origin_name)
            .field("kind", &self.kind)
            .field("content", &content)
            .field("content_hash", &hex::encode(&self.content_hash[..4]))
            .field("byte_len", &self.byte_len)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("starred", &self.starred)
            .field("created_ms", &self.created_ms)
            .finish()
    }
}

fn serialize_hash_hex<S: Serializer>(
    hash: &[u8; 32],
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(hash))
}

/// Filter/pagination parameters for [`History::list`].
///
/// `Default` yields an unfiltered newest-first query with [`DEFAULT_LIMIT`].
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    /// Case-sensitive substring match against `content` (SQL `LIKE`; `%` and
    /// `_` in the term are escaped and matched literally).
    pub text_search: Option<String>,
    /// Restrict to clips originating from this device.
    pub origin: Option<DeviceId>,
    /// Only return starred entries.
    pub starred_only: bool,
    /// Maximum rows to return; 0 means [`DEFAULT_LIMIT`].
    pub limit: usize,
    /// Pagination cursor: only return entries with `ts_ms` strictly less than
    /// this value (pass the oldest `ts_ms` of the previous page).
    pub before_ts: Option<u64>,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            text_search: None,
            origin: None,
            starred_only: false,
            limit: DEFAULT_LIMIT,
            before_ts: None,
        }
    }
}

/// Encrypted local clipboard history store.
pub struct History {
    conn: Mutex<Connection>,
}

impl History {
    /// Open (creating if absent) the encrypted history database at `db_path`.
    ///
    /// Fetches — or generates and persists — a 32-byte database key from
    /// `keystore` under [`DB_KEY_NAME`], applies it via SQLCipher's
    /// `PRAGMA key` as the very first statement, verifies decryption actually
    /// engaged, then runs schema migrations.
    ///
    /// Returns [`Error::WrongKey`] if the file exists but the key does not
    /// decrypt it.
    pub fn open(db_path: &Path, keystore: &dyn KeyStore) -> Result<History> {
        let key = get_or_create_key(keystore)?;

        let conn = Connection::open(db_path)?;

        // PRAGMA key MUST run before any other statement. The 64-char hex form
        // inside x'...' is consumed as a raw key (no KDF). hex::encode emits
        // only [0-9a-f], so the interpolation is injection-safe.
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))?;

        // Force a read of an encrypted page: on a wrong key SQLCipher reports
        // "file is not a database" here rather than on first real query.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| Error::WrongKey)?;

        migrate(&conn)?;

        Ok(History {
            conn: Mutex::new(conn),
        })
    }

    /// Record an applied clip, returning the row id.
    ///
    /// Dedupe (HIST-1): if the newest existing row has the same content hash,
    /// its `ts_ms` is bumped to this item's timestamp instead of inserting a
    /// duplicate; the existing row id is returned.
    pub fn record(&self, item: &ClipboardItem, origin_name: &str) -> Result<i64> {
        let hash = item.content_hash();
        let (kind, content, width, height): (&str, Option<String>, Option<i64>, Option<i64>) =
            match &item.payload {
                ClipboardPayload::Text(s) => ("text", Some(s.clone()), None, None),
                ClipboardPayload::Html { alt_text, .. } => {
                    ("html", Some(alt_text.clone()), None, None)
                }
                ClipboardPayload::Image { width, height, .. } => {
                    ("image", None, Some(*width as i64), Some(*height as i64))
                }
            };
        let byte_len = item.payload.byte_len() as i64;
        let origin_id = item.origin.to_string();
        let ts_ms = item.ts_ms as i64;
        let created_ms = now_ms() as i64;

        let conn = self.conn.lock().expect("history mutex poisoned");

        // Dedupe against the single newest row.
        let newest: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT id, content_hash FROM items ORDER BY ts_ms DESC, id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, existing_hash)) = newest {
            if existing_hash.as_slice() == hash {
                conn.execute("UPDATE items SET ts_ms = ?1 WHERE id = ?2", params![ts_ms, id])?;
                tracing::trace!(id, "history dedupe: bumped ts on existing row");
                return Ok(id);
            }
        }

        conn.execute(
            "INSERT INTO items \
             (ts_ms, origin_id, origin_name, kind, content, content_hash, byte_len, width, height, starred, created_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10)",
            params![
                ts_ms,
                origin_id,
                origin_name,
                kind,
                content,
                &hash[..],
                byte_len,
                width,
                height,
                created_ms
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List history entries newest-first, applying the query's filters.
    pub fn list(&self, query: HistoryQuery) -> Result<Vec<HistoryEntry>> {
        let mut sql = String::from(
            "SELECT id, ts_ms, origin_id, origin_name, kind, content, content_hash, \
             byte_len, width, height, starred, created_ms FROM items WHERE 1 = 1",
        );
        let mut binds: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(text) = &query.text_search {
            // Escape LIKE metacharacters so the term matches literally.
            sql.push_str(" AND content LIKE ? ESCAPE '\\'");
            binds.push(Box::new(format!("%{}%", escape_like(text))));
        }
        if let Some(origin) = &query.origin {
            sql.push_str(" AND origin_id = ?");
            binds.push(Box::new(origin.to_string()));
        }
        if query.starred_only {
            sql.push_str(" AND starred = 1");
        }
        if let Some(before) = query.before_ts {
            sql.push_str(" AND ts_ms < ?");
            binds.push(Box::new(before as i64));
        }

        let limit = if query.limit == 0 { DEFAULT_LIMIT } else { query.limit };
        sql.push_str(" ORDER BY ts_ms DESC, id DESC LIMIT ?");
        binds.push(Box::new(limit as i64));

        let conn = self.conn.lock().expect("history mutex poisoned");
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(params_from_iter(refs), row_to_entry)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Set (or clear) the starred flag on an entry. Returns whether a row
    /// matched.
    pub fn set_starred(&self, id: i64, starred: bool) -> Result<bool> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n = conn.execute(
            "UPDATE items SET starred = ?1 WHERE id = ?2",
            params![starred as i64, id],
        )?;
        Ok(n > 0)
    }

    /// The content hash of the entry with `id`, or `None` if no such row.
    ///
    /// Used by the daemon (HIST-4) to learn which content a just-starred row
    /// refers to, so the star can be broadcast to peers by hash.
    pub fn starred_hash_of(&self, id: i64) -> Result<Option<[u8; 32]>> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let hash: Option<Vec<u8>> = conn
            .query_row(
                "SELECT content_hash FROM items WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(hash.and_then(|v| {
            if v.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                Some(out)
            } else {
                None
            }
        }))
    }

    /// Set (or clear) the starred flag on every entry whose content hash equals
    /// `hash` (HIST-4 star sync). Returns the number of rows updated (0 when no
    /// row matches). Idempotent: re-applying the same value is a harmless no-op
    /// that still reports the matching row count.
    pub fn set_starred_by_hash(&self, hash: &[u8; 32], starred: bool) -> Result<u64> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n = conn.execute(
            "UPDATE items SET starred = ?1 WHERE content_hash = ?2",
            params![starred as i64, &hash[..]],
        )?;
        Ok(n as u64)
    }

    /// Delete a single entry. Returns whether a row matched.
    pub fn delete(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n = conn.execute("DELETE FROM items WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Delete all entries (including starred). Returns the number removed.
    pub fn delete_all(&self) -> Result<u64> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n = conn.execute("DELETE FROM items", [])?;
        Ok(n as u64)
    }

    /// Age-based retention sweep (HIST-2): delete every non-starred entry
    /// whose `ts_ms` is older than `retention` relative to `now_ms`. Starred
    /// entries are exempt. Returns the number removed.
    pub fn sweep(&self, retention: Duration, now_ms: u64) -> Result<u64> {
        let cutoff = now_ms.saturating_sub(retention.as_millis() as u64) as i64;
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n = conn.execute(
            "DELETE FROM items WHERE starred = 0 AND ts_ms < ?1",
            params![cutoff],
        )?;
        if n > 0 {
            tracing::debug!(removed = n, "history retention sweep");
        }
        Ok(n as u64)
    }

    /// Total number of entries currently stored.
    pub fn count(&self) -> Result<u64> {
        let conn = self.conn.lock().expect("history mutex poisoned");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

/// Fetch the 32-byte DB key, generating and persisting one on first use.
fn get_or_create_key(keystore: &dyn KeyStore) -> Result<[u8; 32]> {
    if let Some(bytes) = keystore
        .get(DB_KEY_NAME)
        .map_err(|e| Error::KeyStore(e.to_string()))?
    {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "expected 32 bytes, found {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    keystore
        .set(DB_KEY_NAME, &key)
        .map_err(|e| Error::KeyStore(e.to_string()))?;
    Ok(key)
}

/// Apply schema migrations, tracked via `PRAGMA user_version`.
fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS items (
                 id           INTEGER PRIMARY KEY,
                 ts_ms        INTEGER NOT NULL,
                 origin_id    TEXT    NOT NULL,
                 origin_name  TEXT    NOT NULL,
                 kind         TEXT    NOT NULL,
                 content      TEXT,
                 content_hash BLOB    NOT NULL,
                 byte_len     INTEGER NOT NULL,
                 width        INTEGER,
                 height       INTEGER,
                 starred      INTEGER NOT NULL DEFAULT 0,
                 created_ms   INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_items_ts   ON items(ts_ms);
             CREATE INDEX IF NOT EXISTS idx_items_hash ON items(content_hash);",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

fn row_to_entry(row: &Row) -> rusqlite::Result<HistoryEntry> {
    let hash_vec: Vec<u8> = row.get(6)?;
    let mut content_hash = [0u8; 32];
    if hash_vec.len() == 32 {
        content_hash.copy_from_slice(&hash_vec);
    }
    Ok(HistoryEntry {
        id: row.get(0)?,
        ts_ms: row.get::<_, i64>(1)? as u64,
        origin_id: row.get(2)?,
        origin_name: row.get(3)?,
        kind: row.get(4)?,
        content: row.get(5)?,
        content_hash,
        byte_len: row.get::<_, i64>(7)? as u64,
        width: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
        height: row.get::<_, Option<i64>>(9)?.map(|v| v as u32),
        starred: row.get::<_, i64>(10)? != 0,
        created_ms: row.get::<_, i64>(11)? as u64,
    })
}

/// Escape `%`, `_`, and the escape char itself so a search term matches
/// literally under `LIKE ... ESCAPE '\'`.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use ucb_crypto::FileKeyStore;

    /// Fresh, isolated temp directory for a test.
    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ucb-history-test-{}-{}-{}-{}",
            tag,
            std::process::id(),
            n,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A store backed by a never-interactive `FileKeyStore` (never the OS
    /// keyring), plus its db path. Returns the dirs so callers can reopen.
    fn open_store(dir: &Path) -> (History, FileKeyStore) {
        let ks = FileKeyStore::new(dir.join("keys"));
        let db = dir.join("history.db");
        let hist = History::open(&db, &ks).unwrap();
        (hist, ks)
    }

    fn text_item(text: &str, ts: u64, origin: u8) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Text(text.into()),
            ts_ms: ts,
            origin: DeviceId([origin; 32]),
        }
    }

    fn html_item(html: &str, alt: &str, ts: u64) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Html {
                html: html.into(),
                alt_text: alt.into(),
            },
            ts_ms: ts,
            origin: DeviceId([1; 32]),
        }
    }

    fn image_item(w: u32, h: u32, ts: u64) -> ClipboardItem {
        ClipboardItem {
            payload: ClipboardPayload::Image {
                width: w,
                height: h,
                rgba: vec![0u8; (w * h * 4) as usize],
            },
            ts_ms: ts,
            origin: DeviceId([1; 32]),
        }
    }

    const DAY_MS: u64 = 86_400_000;

    #[test]
    fn record_and_list_roundtrip_all_kinds() {
        let dir = temp_dir("roundtrip");
        let (hist, _ks) = open_store(&dir);

        hist.record(&text_item("hello", 100, 1), "laptop").unwrap();
        hist.record(&html_item("<b>hi</b>", "hi", 200), "laptop").unwrap();
        hist.record(&image_item(2, 3, 300), "laptop").unwrap();

        let entries = hist.list(HistoryQuery::default()).unwrap();
        assert_eq!(entries.len(), 3);

        // Newest first.
        let img = &entries[0];
        assert_eq!(img.kind, "image");
        assert_eq!(img.content, None);
        assert_eq!(img.width, Some(2));
        assert_eq!(img.height, Some(3));
        assert_eq!(img.byte_len, 2 * 3 * 4);

        let html = &entries[1];
        assert_eq!(html.kind, "html");
        assert_eq!(html.content.as_deref(), Some("hi")); // alt text stored

        let text = &entries[2];
        assert_eq!(text.kind, "text");
        assert_eq!(text.content.as_deref(), Some("hello"));
        assert_eq!(text.origin_name, "laptop");
    }

    #[test]
    fn encryption_engaged_and_wrong_key_fails() {
        let dir = temp_dir("encryption");
        let db = dir.join("history.db");
        {
            let ks = FileKeyStore::new(dir.join("keys"));
            let hist = History::open(&db, &ks).unwrap();
            hist.record(&text_item("top secret", 1, 1), "laptop").unwrap();
        } // drop closes the connection

        // File must not be a plaintext SQLite database.
        let bytes = std::fs::read(&db).unwrap();
        assert!(bytes.len() >= 16);
        assert_ne!(&bytes[..16], b"SQLite format 3\0", "db header is plaintext!");

        // Reopening with a different (wrong) key must fail.
        let wrong_ks = FileKeyStore::new(dir.join("other-keys"));
        let err = History::open(&db, &wrong_ks);
        assert!(matches!(err, Err(Error::WrongKey)), "wrong key must not open");
    }

    #[test]
    fn dedupe_bumps_timestamp() {
        let dir = temp_dir("dedupe");
        let (hist, _ks) = open_store(&dir);

        let id1 = hist.record(&text_item("same", 1000, 1), "a").unwrap();
        let id2 = hist.record(&text_item("same", 2000, 1), "a").unwrap();
        assert_eq!(id1, id2, "duplicate must reuse the newest row");
        assert_eq!(hist.count().unwrap(), 1);

        let entries = hist.list(HistoryQuery::default()).unwrap();
        assert_eq!(entries[0].ts_ms, 2000, "ts must be bumped");

        // A different content inserts a new row and is not deduped against a
        // non-newest match.
        hist.record(&text_item("other", 3000, 1), "a").unwrap();
        hist.record(&text_item("same", 4000, 1), "a").unwrap();
        assert_eq!(hist.count().unwrap(), 3);
    }

    #[test]
    fn search_escapes_like_wildcards() {
        let dir = temp_dir("search");
        let (hist, _ks) = open_store(&dir);
        hist.record(&text_item("100%", 1, 1), "a").unwrap();
        hist.record(&text_item("a_b", 2, 1), "a").unwrap();
        hist.record(&text_item("axb", 3, 1), "a").unwrap();
        hist.record(&text_item("abc", 4, 1), "a").unwrap();

        let found = |term: &str| {
            hist.list(HistoryQuery {
                text_search: Some(term.into()),
                ..Default::default()
            })
            .unwrap()
        };

        // Spec case: "0%" matches only "100%".
        let r = found("0%");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].content.as_deref(), Some("100%"));

        // Bare "%" is literal, not "match everything".
        let r = found("%");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].content.as_deref(), Some("100%"));

        // "_" is literal: "a_b" matches only itself, not "axb".
        let r = found("a_b");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].content.as_deref(), Some("a_b"));

        // Ordinary substring still works: only "abc" contains literal "ab".
        let r = found("ab");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].content.as_deref(), Some("abc"));
    }

    #[test]
    fn origin_filter() {
        let dir = temp_dir("origin");
        let (hist, _ks) = open_store(&dir);
        hist.record(&text_item("from-1", 1, 1), "a").unwrap();
        hist.record(&text_item("from-2", 2, 2), "b").unwrap();
        hist.record(&text_item("from-1-again", 3, 1), "a").unwrap();

        let r = hist
            .list(HistoryQuery {
                origin: Some(DeviceId([1; 32])),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.origin_id == DeviceId([1; 32]).to_string()));
    }

    #[test]
    fn starred_only_filter() {
        let dir = temp_dir("starred");
        let (hist, _ks) = open_store(&dir);
        let id1 = hist.record(&text_item("one", 1, 1), "a").unwrap();
        hist.record(&text_item("two", 2, 1), "a").unwrap();
        assert!(hist.set_starred(id1, true).unwrap());

        let r = hist
            .list(HistoryQuery {
                starred_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, id1);
        assert!(r[0].starred);
    }

    #[test]
    fn pagination_before_ts_and_limit() {
        let dir = temp_dir("pagination");
        let (hist, _ks) = open_store(&dir);
        hist.record(&text_item("t10", 10, 1), "a").unwrap();
        hist.record(&text_item("t20", 20, 1), "a").unwrap();
        hist.record(&text_item("t30", 30, 1), "a").unwrap();

        let r = hist
            .list(HistoryQuery {
                before_ts: Some(25),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.ts_ms < 25));

        // Limit returns only the newest.
        let r = hist
            .list(HistoryQuery {
                limit: 1,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].ts_ms, 30);
    }

    #[test]
    fn set_starred_delete_and_delete_all() {
        let dir = temp_dir("mutations");
        let (hist, _ks) = open_store(&dir);
        let id1 = hist.record(&text_item("a", 1, 1), "a").unwrap();
        let id2 = hist.record(&text_item("b", 2, 1), "a").unwrap();
        hist.record(&text_item("c", 3, 1), "a").unwrap();

        assert!(hist.set_starred(id1, true).unwrap());
        assert!(!hist.set_starred(9999, true).unwrap(), "no such row");

        assert!(hist.delete(id2).unwrap());
        assert!(!hist.delete(id2).unwrap(), "already gone");
        assert_eq!(hist.count().unwrap(), 2);

        let removed = hist.delete_all().unwrap();
        assert_eq!(removed, 2);
        assert_eq!(hist.count().unwrap(), 0);
    }

    #[test]
    fn set_starred_by_hash_matches_content_and_reports_count() {
        let dir = temp_dir("star-by-hash");
        let (hist, _ks) = open_store(&dir);

        // Two rows with distinct content; capture their hashes.
        let id_a = hist.record(&text_item("alpha", 1, 1), "a").unwrap();
        hist.record(&text_item("beta", 2, 1), "a").unwrap();
        let hash_a = hist.starred_hash_of(id_a).unwrap().expect("hash for alpha");

        // Starring by hash flips exactly the matching row.
        assert_eq!(hist.set_starred_by_hash(&hash_a, true).unwrap(), 1);
        let starred = hist
            .list(HistoryQuery { starred_only: true, ..Default::default() })
            .unwrap();
        assert_eq!(starred.len(), 1);
        assert_eq!(starred[0].id, id_a);

        // Idempotent: applying again still reports the matching row count.
        assert_eq!(hist.set_starred_by_hash(&hash_a, true).unwrap(), 1);

        // Unstar by hash clears it.
        assert_eq!(hist.set_starred_by_hash(&hash_a, false).unwrap(), 1);
        assert!(hist
            .list(HistoryQuery { starred_only: true, ..Default::default() })
            .unwrap()
            .is_empty());

        // No-match hash updates nothing.
        assert_eq!(hist.set_starred_by_hash(&[0xAB; 32], true).unwrap(), 0);
    }

    #[test]
    fn set_starred_by_hash_updates_all_duplicate_content_rows() {
        let dir = temp_dir("star-dupes");
        let (hist, _ks) = open_store(&dir);

        // Same content, non-adjacent (a different clip between) so both rows
        // persist rather than dedupe.
        hist.record(&text_item("dup", 10, 1), "a").unwrap();
        hist.record(&text_item("mid", 20, 1), "a").unwrap();
        hist.record(&text_item("dup", 30, 1), "a").unwrap();
        assert_eq!(hist.count().unwrap(), 3);

        let hash = text_item("dup", 0, 1).content_hash();
        assert_eq!(hist.set_starred_by_hash(&hash, true).unwrap(), 2, "both dup rows star");
    }

    #[test]
    fn starred_hash_of_none_for_missing_row() {
        let dir = temp_dir("hash-of");
        let (hist, _ks) = open_store(&dir);
        assert!(hist.starred_hash_of(9999).unwrap().is_none());
    }

    #[test]
    fn sweep_deletes_old_unstarred_keeps_starred_and_recent() {
        let dir = temp_dir("sweep");
        let (hist, _ks) = open_store(&dir);
        let now = 1_000_000_000_000u64;

        let old_unstarred = hist
            .record(&text_item("old", now - 40 * DAY_MS, 1), "a")
            .unwrap();
        let old_starred = hist
            .record(&text_item("old-star", now - 41 * DAY_MS, 1), "a")
            .unwrap();
        let recent = hist.record(&text_item("recent", now - DAY_MS, 1), "a").unwrap();
        assert!(hist.set_starred(old_starred, true).unwrap());

        let removed = hist.sweep(Duration::from_millis(30 * DAY_MS), now).unwrap();
        assert_eq!(removed, 1, "only the old unstarred item");
        assert_eq!(hist.count().unwrap(), 2);

        let ids: Vec<i64> = hist
            .list(HistoryQuery::default())
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert!(ids.contains(&old_starred));
        assert!(ids.contains(&recent));
        assert!(!ids.contains(&old_unstarred));
    }

    #[test]
    fn reopen_persists_data() {
        let dir = temp_dir("persist");
        let db = dir.join("history.db");
        let keys = dir.join("keys");
        {
            let ks = FileKeyStore::new(&keys);
            let hist = History::open(&db, &ks).unwrap();
            hist.record(&text_item("first", 1, 1), "a").unwrap();
            hist.record(&text_item("second", 2, 1), "a").unwrap();
        }
        // Same keystore dir -> same key -> same data.
        let ks = FileKeyStore::new(&keys);
        let hist = History::open(&db, &ks).unwrap();
        assert_eq!(hist.count().unwrap(), 2);
        let entries = hist.list(HistoryQuery::default()).unwrap();
        assert_eq!(entries[0].content.as_deref(), Some("second"));
    }

    #[test]
    fn history_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<History>();
    }

    #[test]
    fn entry_debug_redacts_content() {
        let dir = temp_dir("redact");
        let (hist, _ks) = open_store(&dir);
        hist.record(&text_item("hunter2-super-secret", 1, 1), "a").unwrap();
        let entries = hist.list(HistoryQuery::default()).unwrap();
        let dbg = format!("{:?}", entries[0]);
        assert!(!dbg.contains("hunter2"), "Debug leaked content: {dbg}");
        assert!(dbg.contains("redacted"));
    }
}
