//! Async Noise XX handshake and the post-handshake [`SecureChannel`]
//! (PAIR-3, CRYPTO-1).
//!
//! ## Framing
//!
//! Every wire unit is a length-prefixed frame: a `u32` big-endian byte length
//! followed by that many payload bytes. Frames larger than [`MAX_FRAME_LEN`]
//! (16 MiB) are rejected on both read and write.
//!
//! Handshake frames carry raw Noise messages. Post-handshake, a single logical
//! [`WireMessage`] becomes one outer frame whose payload is:
//!
//! ```text
//! u32 chunk_count
//! repeated chunk_count times:
//!     u32 chunk_ciphertext_len
//!     chunk_ciphertext (Noise-encrypted, <= 65535 bytes)
//! ```
//!
//! The plaintext is split into `<= 65519`-byte chunks before encryption so no
//! individual Noise message exceeds snow's 65535-byte limit; the receiver
//! concatenates the decrypted chunks back into the bincode-encoded message.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ucb_core::{DeviceId, WireMessage};

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::noise::{
    noise_params, MAX_FRAME_LEN, MAX_NOISE_MESSAGE, MAX_PLAINTEXT_CHUNK,
};

/// Write one length-prefixed frame.
async fn write_frame<W>(w: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge { size: payload.len(), max: MAX_FRAME_LEN });
    }
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame, rejecting oversize declarations before
/// allocating.
async fn read_frame<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge { size: len, max: MAX_FRAME_LEN });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Extract the 32-byte remote static key from a finished handshake state.
fn remote_static_array(remote: Option<&[u8]>) -> Result<[u8; 32]> {
    let remote = remote.ok_or(Error::MissingRemoteStatic)?;
    if remote.len() != 32 {
        return Err(Error::InvalidKeyMaterial(format!(
            "remote static key is {} bytes, expected 32",
            remote.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(remote);
    Ok(out)
}

/// Drive the initiator side of the Noise XX handshake, returning an
/// established [`SecureChannel`].
///
/// XX message flow: `-> e`, `<- e, ee, s, es`, `-> s, se`.
pub async fn handshake_initiator<S>(mut stream: S, identity: &Identity) -> Result<SecureChannel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut hs = snow::Builder::new(noise_params())
        .local_private_key(identity.private_key())?
        .build_initiator()?;

    let mut buf = vec![0u8; MAX_NOISE_MESSAGE];

    // -> e
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    // <- e, ee, s, es
    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;

    // -> s, se
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    let remote_static = remote_static_array(hs.get_remote_static())?;
    let transport = hs.into_transport_mode()?;
    Ok(SecureChannel::new(stream, transport, remote_static))
}

/// Drive the responder side of the Noise XX handshake, returning an
/// established [`SecureChannel`].
pub async fn handshake_responder<S>(mut stream: S, identity: &Identity) -> Result<SecureChannel<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut hs = snow::Builder::new(noise_params())
        .local_private_key(identity.private_key())?
        .build_responder()?;

    let mut buf = vec![0u8; MAX_NOISE_MESSAGE];

    // -> e
    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;

    // <- e, ee, s, es
    let n = hs.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n]).await?;

    // -> s, se
    let msg = read_frame(&mut stream).await?;
    hs.read_message(&msg, &mut buf)?;

    let remote_static = remote_static_array(hs.get_remote_static())?;
    let transport = hs.into_transport_mode()?;
    Ok(SecureChannel::new(stream, transport, remote_static))
}

/// An encrypted, authenticated session over an async byte stream.
///
/// Wraps snow's transport mode. `send`/`recv` transparently chunk large
/// payloads (see the module docs) so callers can exchange arbitrarily large
/// [`WireMessage`]s up to the 16 MiB frame ceiling.
pub struct SecureChannel<S> {
    stream: S,
    transport: snow::TransportState,
    remote_static: [u8; 32],
}

impl<S> SecureChannel<S> {
    fn new(stream: S, transport: snow::TransportState, remote_static: [u8; 32]) -> Self {
        Self { stream, transport, remote_static }
    }

    /// The peer's 32-byte static public key, revealed by the XX handshake.
    pub fn remote_static_pubkey(&self) -> [u8; 32] {
        self.remote_static
    }

    /// The peer's device id, derived from its static public key.
    pub fn remote_device_id(&self) -> DeviceId {
        DeviceId::from_public_key(&self.remote_static)
    }

    /// Consume the channel and return the underlying stream (e.g. to reclaim
    /// a socket after teardown).
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> SecureChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Encode, encrypt (in chunks) and send one [`WireMessage`].
    pub async fn send(&mut self, msg: &WireMessage) -> Result<()> {
        let plaintext = msg.encode().map_err(Error::Core)?;

        // Assemble the outer frame payload: chunk_count then (len, ciphertext).
        let mut frame = Vec::new();
        // chunks() on an empty slice yields zero chunks; WireMessage encodings
        // are never empty in practice, but the zero-chunk case round-trips.
        let chunks: Vec<&[u8]> = if plaintext.is_empty() {
            Vec::new()
        } else {
            plaintext.chunks(MAX_PLAINTEXT_CHUNK).collect()
        };

        frame.extend_from_slice(&(chunks.len() as u32).to_be_bytes());

        let mut cipher = vec![0u8; MAX_NOISE_MESSAGE];
        for chunk in chunks {
            let n = self.transport.write_message(chunk, &mut cipher)?;
            frame.extend_from_slice(&(n as u32).to_be_bytes());
            frame.extend_from_slice(&cipher[..n]);
        }

        write_frame(&mut self.stream, &frame).await
    }

    /// Receive, decrypt and decode one [`WireMessage`].
    pub async fn recv(&mut self) -> Result<WireMessage> {
        let frame = read_frame(&mut self.stream).await?;

        let mut cursor = FrameCursor::new(&frame);
        let chunk_count = cursor.read_u32()?;

        let mut plaintext = Vec::new();
        let mut plain = vec![0u8; MAX_NOISE_MESSAGE];
        for _ in 0..chunk_count {
            let clen = cursor.read_u32()? as usize;
            if clen > MAX_NOISE_MESSAGE {
                return Err(Error::MalformedFrame(format!(
                    "chunk ciphertext len {clen} exceeds {MAX_NOISE_MESSAGE}"
                )));
            }
            let ct = cursor.read_bytes(clen)?;
            let n = self.transport.read_message(ct, &mut plain)?;
            plaintext.extend_from_slice(&plain[..n]);
        }

        if !cursor.is_empty() {
            return Err(Error::MalformedFrame("trailing bytes after final chunk".into()));
        }

        WireMessage::decode(&plaintext).map_err(Error::Core)
    }
}

/// Bounds-checked reader over an in-memory frame; never panics on bad input.
struct FrameCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| Error::MalformedFrame(format!(
                "need {n} bytes at offset {} but frame is {} bytes",
                self.pos,
                self.buf.len()
            )))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}
