//! Device identity: the X25519 static keypair used directly as the Noise
//! static key (PAIR-1). `DeviceId = BLAKE3(public_key)`.

use std::fmt;

use ucb_core::DeviceId;

use crate::error::{Error, Result};
use crate::keystore::KeyStore;
use crate::noise::noise_params;

/// Key-store entry name under which the static keypair is persisted.
const IDENTITY_KEY_NAME: &str = "static-identity";

/// Length of the persisted blob: 32-byte private key || 32-byte public key.
const STORED_LEN: usize = 64;

/// A device's long-term X25519 identity.
///
/// The private key never leaves the struct except into the Noise handshake;
/// it is deliberately excluded from the [`Debug`] representation (SEC-2).
pub struct Identity {
    private: Vec<u8>,
    public: [u8; 32],
    device_id: DeviceId,
}

impl Identity {
    fn from_parts(private: Vec<u8>, public: [u8; 32]) -> Self {
        let device_id = DeviceId::from_public_key(&public);
        Self { private, public, device_id }
    }

    /// Load the persisted identity from `store`, generating and persisting a
    /// fresh Noise-compatible keypair on first run.
    ///
    /// The keypair is produced by snow's `Builder::generate_keypair` so it is
    /// guaranteed usable as the Noise static key.
    pub fn load_or_generate(store: &dyn KeyStore) -> Result<Self> {
        if let Some(bytes) = store.get(IDENTITY_KEY_NAME)? {
            if bytes.len() != STORED_LEN {
                return Err(Error::InvalidKeyMaterial(format!(
                    "stored identity is {} bytes, expected {STORED_LEN}",
                    bytes.len()
                )));
            }
            let private = bytes[..32].to_vec();
            let mut public = [0u8; 32];
            public.copy_from_slice(&bytes[32..64]);
            return Ok(Self::from_parts(private, public));
        }

        let keypair = snow::Builder::new(noise_params()).generate_keypair()?;
        if keypair.public.len() != 32 {
            return Err(Error::InvalidKeyMaterial(format!(
                "generated public key is {} bytes, expected 32",
                keypair.public.len()
            )));
        }
        let mut public = [0u8; 32];
        public.copy_from_slice(&keypair.public);

        let mut blob = Vec::with_capacity(STORED_LEN);
        blob.extend_from_slice(&keypair.private);
        blob.extend_from_slice(&keypair.public);
        // A malformed private length would break the handshake later; guard now.
        if blob.len() != STORED_LEN {
            return Err(Error::InvalidKeyMaterial(format!(
                "generated keypair blob is {} bytes, expected {STORED_LEN}",
                blob.len()
            )));
        }
        store.set(IDENTITY_KEY_NAME, &blob)?;

        Ok(Self::from_parts(keypair.private, public))
    }

    /// This device's stable identifier: `BLAKE3(public_key)`.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The 32-byte X25519 static public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Crate-internal access to the raw private key for the Noise builder.
    pub(crate) fn private_key(&self) -> &[u8] {
        &self.private
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SEC-2: never expose the private key. Only id + public key are shown.
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .field("public_key", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}
