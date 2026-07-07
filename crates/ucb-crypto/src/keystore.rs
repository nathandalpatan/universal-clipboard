//! Secret storage abstraction (SEC-1).
//!
//! The private static key is stored via the OS keyring by default, with a
//! plaintext-file fallback (mode `0600`) for headless Linux. Both back the
//! same [`KeyStore`] trait so callers pick a policy at construction time.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Service name used for all keyring entries (matches ARCHITECTURE.md).
pub const KEYRING_SERVICE: &str = "dev.ucb.universal-clipboard";

/// Storage for named secret byte blobs.
///
/// Implementations must treat a missing entry as `Ok(None)`, reserving `Err`
/// for genuine storage failures, so callers can implement get-or-create.
pub trait KeyStore {
    /// Fetch the secret stored under `name`, or `None` if absent.
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;

    /// Store `secret` under `name`, overwriting any existing value.
    fn set(&self, name: &str, secret: &[u8]) -> Result<()>;
}

/// OS keyring backed store (macOS Keychain / Windows Credential Manager /
/// Linux Secret Service).
///
/// WARNING: on macOS accessing this may pop an interactive prompt. Never use
/// it in automated tests — use [`FileKeyStore`] there.
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    /// Create a store under the default `dev.ucb.universal-clipboard` service.
    pub fn new() -> Self {
        Self { service: KEYRING_SERVICE.to_string() }
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for KeyringStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let entry = keyring::Entry::new(&self.service, name)?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Keyring(e)),
        }
    }

    fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, name)?;
        entry.set_secret(secret)?;
        Ok(())
    }
}

/// Plaintext-file store under a caller-supplied directory.
///
/// Each secret is one file named after its key. On unix the directory is
/// created `0700` and every secret file is written `0600`.
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// Create a store rooted at `dir`. The directory is created lazily on the
    /// first [`set`](KeyStore::set).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Resolve `name` to a path, rejecting anything that isn't a plain file
    /// name (guards against path traversal via `..` or separators).
    fn path_for(&self, name: &str) -> Result<PathBuf> {
        let is_plain = !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && Path::new(name).file_name() == Some(std::ffi::OsStr::new(name));
        if !is_plain {
            return Err(Error::InvalidKeyMaterial(format!("illegal key name: {name:?}")));
        }
        Ok(self.dir.join(name))
    }
}

impl KeyStore for FileKeyStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(name)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
        let path = self.path_for(name)?;
        std::fs::create_dir_all(&self.dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Tighten the containing directory to owner-only.
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }

        // Create the file with owner-only permissions from the outset on unix.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;

        use std::io::Write as _;
        file.write_all(secret)?;
        file.flush()?;

        #[cfg(unix)]
        {
            // Enforce 0600 even if the file already existed with looser bits.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}
