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

## Wave 2 (build/expansion) — additional crates and decisions

| Crate | Responsibility | Backlog tickets |
|---|---|---|
| `ucb-files` | Transport-agnostic file transfer: chunking, BLAKE3, sender/receiver state machines, resume, temp storage + cleanup | FILE-1 (partial: CLI-initiated), FILE-2/4/5/6/7 (FILE-3 satisfied by session AEAD) |
| `ucb-history` | Encrypted local history: SQLCipher storage, retention sweep, search/star/delete API | HIST-1/2, HIST-3 backend |

- **Protocol v2** (`PROTOCOL_VERSION = 2`): payload variants `Html`/`Image`,
  `Revoke`, and `FileOffer/FileAccept/FileReject/FileChunk/FileDone`.
  v1 peers are rejected at Hello (SYNC-6 working as designed).
- **Payload size:** clips larger than `MAX_CLIP_BYTES` (8 MiB) are not sent
  inline — skip with a `tracing::warn`. Files use `FILE_CHUNK_BYTES`
  (256 KiB) chunks multiplexed through the session channel.
- **Revocation propagation (PAIR-7):** `ucb revoke` records the revoked id
  in a `revoked.json` tombstone list next to `trusted.json`. The engine
  broadcasts `Revoke` to connected peers at session start and when the
  daemon revokes live; on receiving `Revoke` from a *trusted* peer, remove
  the device from the local allowlist, add a tombstone, and drop its
  session. Tombstoned ids may never be re-added without `ucb revoke --forget`.
- **Offline queue (SYNC-5):** per-peer FIFO, cap 20 items / 24 h age,
  persisted as JSON next to the allowlist; drained in order on reconnect,
  then normal live flow. UX-4: on drain, log a "synced N items while away"
  info line.
- **Manual peers (DISC-3):** `static_peers: [\"ip:port\", ...]` in
  config.json; the daemon synthesizes discovery events for them and they
  are dialed regardless of the device-id dial-direction rule (with backoff).
- **History (HIST-1):** SQLCipher via `rusqlite` (bundled-sqlcipher);
  database key is a 32-byte secret in the KeyStore under "history-db-key".
  Every applied clip (local and remote) is recorded. Retention: sweep on
  startup and every hour, delete items older than 30 days unless starred
  (HIST-2). Text payloads store full content; images store dimensions +
  hash only (space).
- **Desktop service (BG-1/BG-6):** `ucb service install|uninstall|status`
  writes a launchd plist (macOS) / systemd user unit (Linux) running
  `ucb run`; Windows deferred.
- **Status IPC (UX-1):** `ucb run` serves a JSON status snapshot on a unix
  socket in the runtime dir; `ucb status` reads it.

## Wave 3 (build/expansion) — closing notes

- **QR pairing (DISC-3/PAIR):** `ucb pair --listen` prints a `ucb://ip:port`
  URI and a scannable terminal QR (suppressed off a TTY or with `--no-qr`);
  `--connect` accepts either the bare `ip:port` or the URI. Lives in
  `ucb-daemon/src/pairing.rs`.
- **Auto file sync (FILE-1):** opt-in via `auto_file_sync` in `config.json`
  (toggle with `ucb config set-auto-file-sync true|false`; `ucb config show`
  dumps the config). When on, files copied to the clipboard are offered to
  peers and inbound offers are accepted into the received dir, capped by
  `max_auto_file_bytes` (default 100 MiB). Off by default.
- **Windows service (BG-1):** `ucb service install|uninstall|status` on
  Windows registers/manages the daemon with the SCM via the `windows-service`
  crate (target-specific dep on `ucb-daemon`), replacing the previous
  "unsupported" error. The launchd/systemd path is unchanged. Windows is
  compile-checked by a `windows-latest` CI job (`cargo check` +
  release build); the pure launch-arg/identifier logic is unit-tested
  cross-platform.
- **Named test cases (TEST-3):** `crates/ucb-sync/tests/named_cases.rs` makes
  the four canonical scenarios explicit and canonical: `unpaired_device_rejection`,
  `transfer_resume_after_interrupt`, `conflict_resolution_convergence`,
  `clock_skew_rejection`.
- **Netem harness (TEST-2):** `scripts/harness-test.sh --netem` re-runs the
  two-device sync check under `latency` (200ms±50ms) and `loss` (10%) `tc`
  presets in addition to the baseline.
- **Protocol v3 (HIST-4):** `PROTOCOL_VERSION = 3` adds
  `WireMessage::Star { content_hash, starred, ts_ms }`. v2 (and v1) peers are
  rejected at the Hello version check (SYNC-6 as designed) — this is an
  accepted, breaking bump; all devices must be on v3 to sync.
- **Star sync (HIST-4):** starring a history entry propagates by content hash.
  `History::set_starred_by_hash(hash, starred)` applies to every matching row;
  `History::starred_hash_of(id)` lets the daemon learn a just-starred row's
  hash. `SyncEngine::broadcast_star(hash, starred)` sends `Star` to all live
  sessions; an inbound `Star` from a trusted session applies
  `set_starred_by_hash` via `spawn_blocking` and is **never** re-broadcast, so
  no loop forms. The daemon's IPC `history_star` calls `broadcast_star` after a
  successful local star (the engine holds the `Arc`); the bare `ucb history
  star|unstar` CLI has no daemon/engine and stars only the local DB.
- **New engine surfaces (GUI wave, additive):** `SyncEngine::discovered()`
  returns `Vec<DiscoveredPeer>` — every mDNS-discovered peer (trusted or not,
  connected or not; names/endpoints for untrusted peers are now retained in the
  peers map). `SyncEngine::subscribe_transfers()` returns a
  `broadcast::Receiver<TransferEvent>` carrying recv/send lifecycle events
  (Started/Progress/Completed) emitted from the existing transfer paths — names,
  sizes, chunk counts, and paths only, never file contents (SEC-2). Neither
  changes `PeerStatus`/`status()`.

## Wave 4 (build/expansion) — the GUI as the complete front door

Goal: a user installs, pairs, and syncs entirely from the desktop GUI, never
touching the CLI. The daemon stays the single engine process; the GUI is a thin
unix-socket frontend.

- **Live trust (kills the restart-after-pairing papercut):**
  `SyncEngine::trust_peer(device: DeviceInfo, static_pubkey) -> Result<()>` adds a
  peer to the running engine's allowlist (reloading `trusted.json` from disk so it
  stays coherent with the pairing flow's write; honoring MAX_DEVICES + tombstones)
  and, if discovery already knows the peer's endpoint, **eagerly dials it** so a
  session forms with no daemon restart. The eager dial ignores the id-ordering
  rule for its one dial.
- **Simultaneous-open tiebreak (new invariant):** because the eager dial (and the
  peer's own dial) can open two TCP connections at once, `run_session` now keeps
  exactly one connection per peer, chosen deterministically: the *canonical*
  connection is the one dialed by the numerically smaller `DeviceId`. Both ends
  compute this identically (`(self_id < peer_id) == dialed`), so a simultaneous
  open never collapses the live session — only a canonical connection may evict a
  non-canonical duplicate; any other duplicate is dropped. Normal (id-ordered)
  dialing is unaffected.
- **Fixed pairing port:** GUI-initiated pairing binds `listen_port + 1` (default
  **48522**) so a peer can dial it knowing only the IP; falls back to an ephemeral
  port if taken (the streamed `pairing` URI carries the actual port either way).
  `ucb pair --listen` is unchanged. On a successful `pair_listen_start` **or**
  `pair_connect`, the daemon calls `trust_peer` so sync starts immediately.
- **New IPC commands** (newline-JSON, same conventions):
  - `{"cmd":"discovered"}` → `{"peers":[{id_short,id,name,addrs,port,trusted,connected}]}`
    from `SyncEngine::discovered()`.
  - `{"cmd":"pair_connect","addr":"ip:port|ucb://…"}` → streams a `code` line,
    waits for `{"cmd":"pair_confirm","accept":bool}` on the same connection, then a
    `result` line; on success writes the allowlist AND `trust_peer`s live. Shares
    the one-pairing-at-a-time slot with `pair_listen_start`.
  - `{"cmd":"transfers_subscribe"}` → long-lived stream of serde-tagged
    `TransferEvent` JSON lines (`recv_started`/`recv_progress`/`recv_completed`/
    `send_progress`/`send_completed`), device ids as short+full, path as string,
    never file contents (SEC-2). Stays open until the client disconnects.
  - `config_set` extended with `max_auto_file_bytes` (u64) alongside
    `auto_file_sync`.
- **IPC test determinism:** the daemon test harness now retries the socket connect
  (5×100ms) and re-sends on an EOF-before-first-line, removing the known
  parallel-load flake (`config_ipc_commands`, named cases).
- **GUI (`apps/ucb-gui`, standalone Tauri v2 project):**
  - **Onboarding wizard (first run):** when the socket is absent, the GUI offers to
    set everything up — locates the `ucb` binary (`UCB_BIN` → next to the GUI exe →
    `target/{release,debug}/ucb` above it → PATH), runs `ucb init --name <name>` if
    `config.json` is missing, then either spawns a **managed** `ucb run` child
    (killed on GUI quit) or, with "Keep syncing in background", runs
    `ucb service install --activate`. Header shows a status dot + Start/Stop sync.
  - **One-click pairing:** the Devices view lists **Nearby devices** (`discovered`,
    polled 3s); an unpaired peer's **Pair** button dials `ip:(advertised_port+1)`
    via `pair_connect` and opens a modal with the 6-digit code + Confirm/Reject.
    **Show pairing code** runs `pair_listen_start` (URI + QR + code) in the same
    modal; **Add by address** covers cross-subnet. After success the peer appears
    paired & connected within seconds (live `trust_peer`) with a success toast.
  - **Transfers + toasts:** subscribes to `transfers_subscribe` (reconnects on
    drop); active transfers render progress bars (percent from chunk counts, name,
    direction, smoothed speed) shown only past 350ms; completion/failure toasts; a
    received-file toast has **Show in folder** (`reveal_in_folder`, no plugin —
    shells out to `open -R`/`explorer /select`/`xdg-open`); a "synced N clips while
    away" toast fires when >3 clips land within 5s of a peer connecting.
  - **Settings:** auto-file-sync toggle + max-file-size input (MiB → bytes via
    `config_set`) with a restart-required banner and one-click **Restart sync**
    (GUI-managed daemon only); the HIST-5/6/7 protections are unchanged.

- **Packaging & auto-update (REL-1):** the GUI is an installable, self-updating
  app; the `ucb` daemon ships **inside** the bundle.
  - **Sidecar:** `ucb` is a Tauri v2 `externalBin` sidecar
    (`tauri.conf.json` → `binaries/ucb`). `scripts/prepare-sidecar.sh` copies the
    release daemon into `apps/ucb-gui/binaries/ucb-<target-triple>` (the bundler
    strips the triple, landing it at `…/Contents/MacOS/ucb`). `binaries/` is
    git-ignored. `locate_ucb()` now resolves the **sidecar first** (next to the
    GUI exe → wins in a real install), then the dev fallbacks
    (`UCB_BIN` → `target/{release,debug}/ucb` → `PATH`); a dev checkout finds no
    sidecar so behaviour there is unchanged.
  - **Bundle:** productName "Universal Clipboard", identifier
    `dev.ucb.universal-clipboard`, version `0.1.0`. Targets: macOS `.app`/`.dmg`,
    Windows `.msi`/NSIS, Linux `.deb`/`.AppImage`. Real icon set generated by
    `scripts/gen-icons.py` (committed). macOS signing identity is `"-"` (ad-hoc,
    **not notarized** — documented Gatekeeper caveat).
  - **Updater:** `tauri-plugin-updater` (capability `updater:default` in
    `capabilities/default.json`) checks the GitHub-releases `latest.json`
    (`…/releases/latest/download/latest.json`). Silent auto-check on launch →
    toast + Install button only if an update exists; manual **Check for updates**
    in Settings. Two Rust commands: `check_for_update` (stashes the `Update`
    handle, returns version) and `install_update` (download+verify+install, then
    `app.restart()`), driven from the no-npm frontend via `invoke`. The updater
    **public key** is in `tauri.conf.json`; the **private key**
    (`apps/ucb-gui/.updater-key`, git-ignored, never committed) must be stored as
    the `TAURI_SIGNING_PRIVATE_KEY` GitHub Actions secret.
  - **Release CI:** `.github/workflows/release.yml` on a `v*` tag — matrix
    (macOS aarch64 + x86_64, Ubuntu, Windows) builds the daemon, stages the
    sidecar, and runs `tauri-action` (build → sign updater artifacts → assemble
    `latest.json` → upload to the draft release). `ci.yml` gained a macOS-only
    GUI `build/clippy/test` job.

## Conventions

- Async: tokio. Errors: `thiserror` in libs, `anyhow` in the daemon.
  Logging: `tracing` (never log clipboard content — SEC-2).
- Every crate: unit tests in-file; `cargo test -p <crate>` must pass.
- Workspace deps only (`{ workspace = true }`); add new deps to the root
  `[workspace.dependencies]` first.
