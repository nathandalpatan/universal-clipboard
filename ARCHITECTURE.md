# Universal Clipboard — architecture

End-to-end encrypted LAN clipboard sync. Rust workspace; desktop first
(macOS/Linux/Windows), CLI daemon before any GUI shell.

## Crates

| Crate | Responsibility | Backlog tickets |
|---|---|---|
| `ucb-core` | Shared types, wire protocol, conflict rules. No IO. | SYNC-3, SYNC-6, SEC-2 |
| `ucb-crypto` | Device identity, keyring storage, Noise handshake, session AEAD, replay/skew checks, pairing codes | PAIR-1, PAIR-2 (code), PAIR-3, CRYPTO-1/2/3, SEC-1, SEC-2 |
| `ucb-discovery` | mDNS advertise + continuous browse, peer up/down events | DISC-1, DISC-4 (events) |
| `ucb-clipboard` | OS clipboard watch/write, echo-loop prevention | SYNC-2 |
| `ucb-sync` | Engine: transport, pairing/allowlist, session mgmt, conflict resolution, rate limiting | SYNC-1/3/6, PAIR-4/5/6, SEC-3, DISC-4 (reconnect) |
| `ucb-daemon` | `ucb` binary: `init`, `pair`, `trust`, `devices`, `revoke`, `run` | CLI surface |

Dependency direction: everything may depend on `ucb-core`; `ucb-sync` may
depend on `ucb-crypto`/`ucb-discovery`/`ucb-clipboard`; `ucb-daemon` on all.
Never sideways or upward.

## Fixed protocol decisions (do not re-decide)

- **Identity (PAIR-1):** X25519 static keypair, used directly as the Noise
  static key. `DeviceId = BLAKE3(static_pubkey)`. Private key stored via the
  `keyring` crate (SEC-1), with a plaintext-file fallback under the config
  dir (0600) behind an explicit opt-out flag for headless Linux.
- **Handshake (PAIR-3):** Noise `Noise_XX_25519_ChaChaPoly_BLAKE2s` via the
  `snow` crate, over TCP. XX gives mutual static-key authentication; trust
  is decided against the allowlist after the handshake reveals the remote
  static key.
- **Pairing verification (PAIR-2):** short authentication string — 6-digit
  numeric code derived from `BLAKE3(sorted(pubkey_a, pubkey_b))`, displayed
  on both devices; user confirms match before the peer is added to the
  allowlist.
- **Session encryption (CRYPTO-1):** use snow transport mode
  (ChaCha20-Poly1305) after handshake. One handshake per TCP connection;
  rekey = reconnect.
- **Framing:** length-prefixed frames, `u32` big-endian length then payload.
  Handshake frames are raw Noise messages; post-handshake frames are
  Noise-encrypted `WireMessage` (bincode). Max frame 16 MiB.
- **Replay (CRYPTO-2):** per-session monotonic `seq` in `WireMessage::Clip`;
  receiver rejects `seq <= last_seen`. (Noise nonces already prevent
  transport-level replay; this guards the application layer.)
- **Clock skew (CRYPTO-3):** reject clips with `|now - ts_ms| > 120_000`.
- **Version (SYNC-6):** first post-handshake message each way is
  `Hello { version, device }`; mismatch → `Reject` + close.
- **Echo prevention (SYNC-2):** before writing a received clip to the OS
  clipboard, record its content hash; when the watcher observes a change
  whose hash equals the last-written hash, do not rebroadcast.
- **Conflict (SYNC-3):** `ClipboardItem::wins_over` — timestamp then
  device-ID tiebreak. Applied when a received clip races a local copy.
- **Discovery (DISC-1):** mDNS service `_ucb._tcp.local.` via `mdns-sd`.
  Instance name = `DeviceId::short()`. TXT records: `id` (full hex device
  id), `name`, `v` (protocol version). Browse continuously; emit
  `PeerFound/PeerLost` events on a `tokio::sync::mpsc` channel.
- **Rate limiting (SEC-3):** max 5 handshake attempts per source IP per
  minute; token-bucket in `ucb-sync`'s listener.
- **Allowlist (PAIR-4):** JSON file `trusted.json` in the config dir
  (`directories::ProjectDirs` for "dev.ucb.universal-clipboard"), mapping
  device id → { name, static_pubkey, added_ts }. Cap 3 including self
  (PAIR-5).

## Conventions

- Async: tokio. Errors: `thiserror` in libs, `anyhow` in the daemon.
  Logging: `tracing` (never log clipboard content — SEC-2).
- Every crate: unit tests in-file; `cargo test -p <crate>` must pass.
- Workspace deps only (`{ workspace = true }`); add new deps to the root
  `[workspace.dependencies]` first.
