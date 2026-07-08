#![no_main]
//! TEST-4: fuzz the wire-message parser.
//!
//! `WireMessage::decode` must be total over arbitrary bytes — it may return
//! `Err`, but it must NEVER panic, overflow, or run out of memory on
//! attacker-controlled input (this is the untrusted post-handshake decode
//! path). libfuzzer flags any panic/abort as a crash.

use libfuzzer_sys::fuzz_target;
use ucb_core::WireMessage;

fuzz_target!(|data: &[u8]| {
    // Only contract: decoding never panics. An Err result is fine.
    let _ = WireMessage::decode(data);
});
