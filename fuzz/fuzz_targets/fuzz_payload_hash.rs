#![no_main]
//! TEST-4: fuzz the clipboard payload hashing + redacted Debug paths.
//!
//! Feed arbitrary bytes to `WireMessage::decode`; whenever they decode into a
//! message that carries a `ClipboardItem` (a `Clip`), exercise the two
//! content-derived paths that must be total and side-effect-free:
//!   - `content_hash()` over the payload (SYNC-2 echo prevention input), and
//!   - the SEC-2 redacting `Debug` impl (must never panic while formatting,
//!     and — by contract — must never echo raw content; here we only assert it
//!     does not panic).
//! Neither may panic on any decodable input.

use libfuzzer_sys::fuzz_target;
use ucb_core::WireMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = WireMessage::decode(data) {
        // Debug-format the whole message (redaction path for every variant).
        let _ = format!("{msg:?}");

        if let WireMessage::Clip { item, .. } = msg {
            // Content hashing must be total over any decoded payload.
            let _ = item.content_hash();
            let _ = item.payload.content_hash();
            let _ = item.payload.byte_len();
            // Redacted Debug of the payload specifically.
            let _ = format!("{:?}", item.payload);
        }
    }
});
