//! ucb-crypto — see ARCHITECTURE.md for the contract this crate implements.
//!
//! Device identity (PAIR-1), pairing codes (PAIR-2), the async Noise XX
//! handshake and session AEAD (PAIR-3, CRYPTO-1), replay/skew guards
//! (CRYPTO-2/3) and secret storage (SEC-1). The private key never appears in
//! any `Debug` output (SEC-2).

mod channel;
mod error;
mod guard;
mod identity;
mod keystore;
mod noise;
mod pairing;

pub use channel::{handshake_initiator, handshake_responder, SecureChannel};
pub use error::{Error, Result};
pub use guard::{check_clock_skew, ReplayGuard, CLOCK_SKEW_TOLERANCE_MS};
pub use identity::{migrate_identity, migrate_secret, Identity};
pub use keystore::{FileKeyStore, KeyStore, KeyringStore, KEYRING_SERVICE};
pub use noise::{MAX_FRAME_LEN, NOISE_PATTERN};
pub use pairing::pairing_code;

#[cfg(test)]
mod tests {
    use super::*;
    use ucb_core::{
        ClipboardItem, ClipboardPayload, DeviceInfo, Platform, WireMessage, PROTOCOL_VERSION,
    };

    /// Unique, isolated on-disk key store for a test — never touches the OS
    /// keychain (which would prompt interactively on macOS).
    fn temp_store(tag: &str) -> (FileKeyStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ucb-crypto-test-{}-{}-{}-{}",
            tag,
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        (FileKeyStore::new(dir.clone()), dir)
    }

    fn sample_hello(id_byte: u8) -> WireMessage {
        WireMessage::Hello {
            version: PROTOCOL_VERSION,
            device: DeviceInfo {
                id: ucb_core::DeviceId([id_byte; 32]),
                name: format!("dev-{id_byte}"),
                platform: Platform::Linux,
            },
        }
    }

    // ---- PAIR-2: pairing code -------------------------------------------

    #[test]
    fn pairing_code_is_symmetric_and_six_digits() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let code_ab = pairing_code(&a, &b);
        let code_ba = pairing_code(&b, &a);
        assert_eq!(code_ab, code_ba, "pairing code must be order-independent");
        assert_eq!(code_ab.len(), 6, "code must be exactly six characters");
        assert!(code_ab.chars().all(|c| c.is_ascii_digit()), "code must be numeric: {code_ab}");
    }

    #[test]
    fn pairing_code_differs_for_different_keys() {
        let a = [9u8; 32];
        let b = [8u8; 32];
        let c = [7u8; 32];
        // Not a security property, just a sanity check the derivation varies.
        assert_ne!(pairing_code(&a, &b), pairing_code(&a, &c));
    }

    // ---- PAIR-1 / SEC-1 / SEC-2: identity -------------------------------

    #[test]
    fn identity_persists_same_device_id() {
        let (store, _dir) = temp_store("persist");
        let first = Identity::load_or_generate(&store).unwrap();
        let second = Identity::load_or_generate(&store).unwrap();
        assert_eq!(first.device_id(), second.device_id());
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn distinct_stores_yield_distinct_identities() {
        let (s1, _d1) = temp_store("distinct-a");
        let (s2, _d2) = temp_store("distinct-b");
        let a = Identity::load_or_generate(&s1).unwrap();
        let b = Identity::load_or_generate(&s2).unwrap();
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn device_id_is_blake3_of_public_key() {
        let (store, _dir) = temp_store("devid");
        let id = Identity::load_or_generate(&store).unwrap();
        assert_eq!(id.device_id(), ucb_core::DeviceId::from_public_key(&id.public_key()));
    }

    #[test]
    fn identity_debug_never_leaks_private_key() {
        let (store, _dir) = temp_store("debug");
        let id = Identity::load_or_generate(&store).unwrap();
        let dbg = format!("{id:?}");
        let private_hex = hex::encode(id.private_key());
        assert!(
            !dbg.contains(&private_hex),
            "Debug leaked private key bytes: {dbg}"
        );
        // Public material is fine to show.
        assert!(dbg.contains(&id.device_id().short()));
    }

    #[cfg(unix)]
    #[test]
    fn file_key_store_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = temp_store("perms");
        Identity::load_or_generate(&store).unwrap();
        // The identity file is named "static-identity".
        let mode = std::fs::metadata(dir.join("static-identity"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret file must be owner-only");
    }

    // ---- CRYPTO-2: replay guard -----------------------------------------

    #[test]
    fn replay_guard_accepts_increasing_rejects_replays() {
        let mut guard = ReplayGuard::new();
        assert!(guard.check(0).is_ok());
        assert!(guard.check(1).is_ok());
        assert!(guard.check(5).is_ok());
        // Equal to last-seen -> rejected.
        assert!(matches!(guard.check(5), Err(ucb_core::Error::Replay { .. })));
        // Below last-seen -> rejected.
        assert!(matches!(guard.check(3), Err(ucb_core::Error::Replay { .. })));
        // Advancing again -> accepted.
        assert!(guard.check(6).is_ok());
    }

    // ---- CRYPTO-3: clock skew -------------------------------------------

    #[test]
    fn clock_skew_within_and_beyond_tolerance() {
        let now = 1_000_000_000u64;
        assert!(check_clock_skew(now, now).is_ok());
        assert!(check_clock_skew(now - 120_000, now).is_ok());
        assert!(check_clock_skew(now + 120_000, now).is_ok());
        // Just past tolerance either direction.
        assert!(matches!(
            check_clock_skew(now - 120_001, now),
            Err(ucb_core::Error::ClockSkew { .. })
        ));
        assert!(matches!(
            check_clock_skew(now + 120_001, now),
            Err(ucb_core::Error::ClockSkew { .. })
        ));
    }

    // ---- PAIR-3 / CRYPTO-1: handshake + secure channel ------------------

    #[tokio::test]
    async fn handshake_roundtrip_both_directions() {
        let (store_i, _di) = temp_store("hs-init");
        let (store_r, _dr) = temp_store("hs-resp");
        let id_i = Identity::load_or_generate(&store_i).unwrap();
        let id_r = Identity::load_or_generate(&store_r).unwrap();
        let init_devid = id_i.device_id();
        let resp_devid = id_r.device_id();

        let (client, server) = tokio::io::duplex(64 * 1024);

        let init_task = tokio::spawn(async move {
            let mut chan = handshake_initiator(client, &id_i).await.unwrap();
            // Initiator sees responder's id.
            assert_eq!(chan.remote_device_id(), resp_devid);
            chan.send(&sample_hello(1)).await.unwrap();
            let got = chan.recv().await.unwrap();
            match got {
                WireMessage::Hello { device, .. } => device.id,
                other => panic!("expected Hello, got {other:?}"),
            }
        });

        let resp_task = tokio::spawn(async move {
            let mut chan = handshake_responder(server, &id_r).await.unwrap();
            // Responder sees initiator's id.
            assert_eq!(chan.remote_device_id(), init_devid);
            let got = chan.recv().await.unwrap();
            chan.send(&sample_hello(2)).await.unwrap();
            match got {
                WireMessage::Hello { device, .. } => device.id,
                other => panic!("expected Hello, got {other:?}"),
            }
        });

        let seen_by_init = init_task.await.unwrap();
        let seen_by_resp = resp_task.await.unwrap();
        assert_eq!(seen_by_init.0, [2u8; 32]);
        assert_eq!(seen_by_resp.0, [1u8; 32]);
    }

    #[tokio::test]
    async fn large_message_chunks_roundtrip() {
        let (store_i, _di) = temp_store("big-init");
        let (store_r, _dr) = temp_store("big-resp");
        let id_i = Identity::load_or_generate(&store_i).unwrap();
        let id_r = Identity::load_or_generate(&store_r).unwrap();

        let (client, server) = tokio::io::duplex(1024 * 1024);

        // ~200 KiB of text -> multiple Noise chunks.
        let big_text: String = "abcdefghij".repeat(20_000);
        assert!(big_text.len() > 65_535);
        let expected = big_text.clone();

        let send_msg = WireMessage::Clip {
            seq: 42,
            item: ClipboardItem {
                payload: ClipboardPayload::Text(big_text),
                ts_ms: 123,
                origin: ucb_core::DeviceId([3u8; 32]),
            },
        };

        let init_task = tokio::spawn(async move {
            let mut chan = handshake_initiator(client, &id_i).await.unwrap();
            chan.send(&send_msg).await.unwrap();
        });

        let resp_task = tokio::spawn(async move {
            let mut chan = handshake_responder(server, &id_r).await.unwrap();
            match chan.recv().await.unwrap() {
                WireMessage::Clip { seq, item } => {
                    assert_eq!(seq, 42);
                    match item.payload {
                        ClipboardPayload::Text(t) => assert_eq!(t, expected),
                        other => panic!("expected Text, got {other:?}"),
                    }
                }
                other => panic!("expected Clip, got {other:?}"),
            }
        });

        init_task.await.unwrap();
        resp_task.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_to_decrypt() {
        // Establish a channel, then feed the receiver a corrupted frame.
        let (store_i, _di) = temp_store("tamper-init");
        let (store_r, _dr) = temp_store("tamper-resp");
        let id_i = Identity::load_or_generate(&store_i).unwrap();
        let id_r = Identity::load_or_generate(&store_r).unwrap();

        let (client, server) = tokio::io::duplex(64 * 1024);

        let resp_task = tokio::spawn(async move {
            let mut chan = handshake_responder(server, &id_r).await.unwrap();
            // Expect a decryption failure, not a successful decode.
            chan.recv().await
        });

        let init_task = tokio::spawn(async move {
            let chan = handshake_initiator(client, &id_i).await.unwrap();
            // Craft one structurally-valid outer frame whose single chunk is
            // bogus ciphertext: the AEAD tag check must fail on decrypt.
            let mut frame = Vec::new();
            frame.extend_from_slice(&1u32.to_be_bytes()); // chunk_count = 1
            let bogus = vec![0xABu8; 48]; // not a valid Noise/AEAD ciphertext
            frame.extend_from_slice(&(bogus.len() as u32).to_be_bytes());
            frame.extend_from_slice(&bogus);

            let mut raw = chan.into_inner();
            use tokio::io::AsyncWriteExt;
            raw.write_all(&(frame.len() as u32).to_be_bytes()).await.unwrap();
            raw.write_all(&frame).await.unwrap();
            raw.flush().await.unwrap();
        });

        init_task.await.unwrap();
        let result = resp_task.await.unwrap();
        assert!(result.is_err(), "tampered ciphertext must not decrypt");
    }
}
