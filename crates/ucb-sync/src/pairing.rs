//! Interactive pairing flow (PAIR-2 verification + PAIR-4 allowlist write).
//!
//! Both sides run the Noise XX handshake, derive the same 6-digit
//! [`pairing_code`], exchange `Hello` so each learns the other's
//! [`DeviceInfo`], then ask the caller to confirm the code matches. On
//! confirmation the peer is added to the local allowlist.
//!
//! The confirmation callback receives the code and the peer's `DeviceInfo`; the
//! CLI displays them and reads a y/N answer from the user.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use ucb_core::{DeviceInfo, Platform, WireMessage, PROTOCOL_VERSION};
use ucb_crypto::{handshake_initiator, handshake_responder, pairing_code, Identity, SecureChannel};

use crate::allowlist::{Allowlist, TrustedDevice};
use crate::error::{Error, Result};
use crate::now_ms;

/// How the caller confirms a pairing: given the 6-digit code and the peer's
/// device info, return `true` to trust the peer.
pub trait ConfirmPairing {
    fn confirm(&mut self, code: &str, peer: &DeviceInfo) -> bool;
}

impl<F: FnMut(&str, &DeviceInfo) -> bool> ConfirmPairing for F {
    fn confirm(&mut self, code: &str, peer: &DeviceInfo) -> bool {
        self(code, peer)
    }
}

/// Accept one inbound pairing connection on `listener` (responder side).
///
/// On success the peer is written to the allowlist at `allowlist_path` and the
/// resulting [`TrustedDevice`] is returned.
pub async fn pair_listen(
    listener: TcpListener,
    identity: &Identity,
    allowlist_path: impl Into<std::path::PathBuf>,
    local_name: &str,
    platform: Platform,
    confirm: impl ConfirmPairing,
) -> Result<TrustedDevice> {
    let (stream, _addr) = listener.accept().await?;
    let chan = handshake_responder(stream, identity).await?;
    finish_pairing(chan, identity, allowlist_path.into(), local_name, platform, confirm).await
}

/// Dial `addr` and pair with the device listening there (initiator side).
pub async fn pair_dial(
    addr: &str,
    identity: &Identity,
    allowlist_path: impl Into<std::path::PathBuf>,
    local_name: &str,
    platform: Platform,
    confirm: impl ConfirmPairing,
) -> Result<TrustedDevice> {
    let stream = TcpStream::connect(addr).await?;
    let chan = handshake_initiator(stream, identity).await?;
    finish_pairing(chan, identity, allowlist_path.into(), local_name, platform, confirm).await
}

/// Shared tail of both pairing directions: derive the code, exchange `Hello`,
/// confirm, and persist trust.
async fn finish_pairing<S>(
    mut chan: SecureChannel<S>,
    identity: &Identity,
    allowlist_path: std::path::PathBuf,
    local_name: &str,
    platform: Platform,
    mut confirm: impl ConfirmPairing,
) -> Result<TrustedDevice>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let peer_pubkey = chan.remote_static_pubkey();
    let peer_id = chan.remote_device_id();
    let code = pairing_code(&identity.public_key(), &peer_pubkey);

    // Exchange Hello so each side learns the other's display name / platform.
    chan.send(&WireMessage::Hello {
        version: PROTOCOL_VERSION,
        device: DeviceInfo {
            id: identity.device_id(),
            name: local_name.to_string(),
            platform,
        },
    })
    .await?;

    let peer_info = match chan.recv().await? {
        WireMessage::Hello { version, device } => {
            if version != PROTOCOL_VERSION {
                return Err(Error::VersionMismatch {
                    local: PROTOCOL_VERSION,
                    remote: version,
                });
            }
            device
        }
        WireMessage::Reject { reason } => return Err(Error::Rejected(reason)),
        _ => return Err(Error::UnexpectedMessage),
    };

    if !confirm.confirm(&code, &peer_info) {
        return Err(Error::PairingDeclined);
    }

    let mut allowlist = Allowlist::load(&allowlist_path)?;
    allowlist.add(peer_id, peer_info.name.clone(), &peer_pubkey, now_ms())?;

    Ok(TrustedDevice {
        device_id: peer_id,
        name: peer_info.name,
        static_pubkey: peer_pubkey,
        added_ts_ms: now_ms(),
    })
}
