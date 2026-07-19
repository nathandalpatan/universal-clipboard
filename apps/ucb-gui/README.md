# ucb-gui — Universal Clipboard desktop shell

A Tauri v2 tray application that is a **frontend** for the running
`ucb` daemon. It does not embed the sync engine: it opens the daemon's
existing unix-socket IPC (`<config-dir>/daemon.sock`, newline-delimited JSON)
and relays commands. The daemon stays the single engine process.

Tickets covered: **HIST-3** (history GUI), **UX-2** (devices + pair CTA),
**PAIR-2** (on-screen QR pairing), **UX-3/UX-4** (spinner threshold, transfer
progress, toasts), the history-protection trio **HIST-5** (biometric gate),
**HIST-6** (sensitive-content blur), **HIST-7** (screenshot/recording
exclusion), and the **Wave-4 "front door"**: a first-run onboarding wizard,
one-click nearby-device pairing (live trust, no restart), and managed-daemon
start/stop.

## The front door (Wave 4)

The GUI is meant to be the *only* thing a user touches — install, pair, sync,
no CLI. It still speaks to the daemon over the unix socket, but it can also
**set up and manage the daemon for you**:

- **First-run onboarding.** If the socket is absent, an overlay offers to set up
  this device: it locates the `ucb` binary, runs `ucb init` if `config.json` is
  missing, then starts syncing. "Keep syncing in the background" installs a login
  service (`ucb service install --activate`); otherwise the GUI spawns a
  **managed** `ucb run` child that it kills when the app quits.
- **Binary search order** (documented, used by onboarding + `ucb_binary_path`):
  **bundled sidecar** (`ucb` next to the GUI executable — where the Tauri bundler
  places the `externalBin`, so it wins in a real install) → `UCB_BIN` → 
  `target/{release,debug}/ucb` above the executable (dev checkout) → bare `ucb`
  on `PATH`. In a dev checkout the sidecar step finds nothing (the GUI's own
  `target/` has no `ucb` beside `ucb-gui`), so the dev fallbacks apply as before.
- **Header sync control.** A status dot + "Sync on · N/M connected" label and a
  **Start/Stop sync** button (Stop only shown for a GUI-managed daemon; a
  background-service daemon is left alone).
- **One-click pairing.** The Devices view's **Nearby devices** section lists
  discovered-but-unpaired peers (`discovered`, polled every 3 s). **Pair** dials
  the peer's pairing port (its advertised sync port + 1) via `pair_connect` and
  opens a modal with the 6-digit code + Confirm/Reject. **Show pairing code** runs
  `pair_listen_start` (URI + QR + code) in the same modal, and **Add by address**
  handles cross-subnet peers. After confirmation the peer is paired *and*
  connected within seconds — no restart — thanks to live `trust_peer`, with a
  success toast.
- **Transfers + toasts.** The GUI subscribes to `transfers_subscribe` (reconnects
  on drop). Active transfers show a progress bar (percent from chunk counts, file
  name, direction ↑/↓, smoothed speed) that only appears past 350 ms; completion
  and failure raise toasts; a received-file toast has a **Show in folder** action
  (`reveal_in_folder`); a "synced N clips while away" toast fires when more than 3
  clips land within 5 s of a peer connecting.
- **Settings.** Automatic-file-sync toggle + max-file-size input (MiB, written as
  bytes via `config_set`), with a restart-required banner and a one-click
  **Restart sync** (only for a GUI-managed daemon).

## How to run

The GUI needs a running daemon:

```sh
# 1. In one terminal — start (or already have) the engine running:
ucb run

# 2. In another terminal — launch the GUI (its own standalone cargo project):
cd apps/ucb-gui
cargo run
```

By default the GUI looks for the daemon socket at the platform config dir
(`ProjectDirs("dev","ucb","universal-clipboard")/daemon.sock`), matching the
daemon. To point it at a sandboxed daemon, set either:

- `UCB_SOCKET=/path/to/daemon.sock`, or
- `UCB_CONFIG_DIR=/path/to/config-dir` (socket assumed at `.../daemon.sock`).

This crate is intentionally **not** a member of the root cargo workspace (it
carries an empty `[workspace]` table, like `fuzz/`). That keeps the heavy Tauri
dependency tree out of `cargo build --workspace` at the repo root.

## What works

- **Tray icon + menu**: Open, a live daemon/sync status line (updated by polling
  `status` every 3 s), and Quit.
- **Devices view (UX-2)**: peer list from `status` polled every 2 s, with
  connected/offline badges and a per-peer **Revoke** button (live PAIR-7
  revocation over IPC). Clear empty states: "daemon not running → run `ucb run`"
  when the socket is absent, and a "Pair a device" call-to-action when no peers
  are paired.
- **Pair view (PAIR-2)**: **Start pairing** opens a `pair_listen_start` stream,
  renders the `ucb://ip:port` URI (with Copy) and the terminal QR as a `<pre>`,
  then shows the 6-digit code and the peer's name with **Confirm / Reject**. The
  daemon binds a fresh ephemeral port for pairing (the sync port is held by the
  engine), so the peer dials that address with
  `ucb pair --connect ucb://ip:port`.
- **History view (HIST-3)**: entries from `history_list` with a search box, a
  device filter (populated from the current peers), a starred-only toggle,
  per-entry star/unstar and delete, and **Load more** pagination via `before_ts`.
- **UX-3 groundwork**: status/history calls only reveal a spinner if the call
  exceeds 350 ms (JS timer in `withSpinner`).

## History-protection features (HIST-5 / HIST-6 / HIST-7)

### HIST-7 — screenshot & screen-sharing exclusion

The GUI window is excluded from screen captures, screen recording, and screen
sharing. Applied **ON by default at window creation** (secure default) and
re-applied live from the **Settings** toggle *"Hide window from screenshots &
screen sharing"* (persisted in `localStorage`, no restart needed).

| Platform | Mechanism | Status |
|----------|-----------|--------|
| macOS | `NSWindow.sharingType = .none` (via `objc2` + `objc2-app-kit`, pulled from Tauri's window handle) | Enforced by the WindowServer |
| Windows | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` (`windows` crate) | **cfg-gated, compile-checked only** — no Windows host in CI |
| Linux | none | **Not enforceable** — X11 has no primitive and Wayland capture policy is compositor-specific. Documented no-op; the Settings toggle notes it has no effect. |

### HIST-5 — biometric gate on History

On macOS the **History** view is gated behind Touch ID via `LocalAuthentication`
(`objc2-local-authentication`, `LAContext.evaluatePolicy`). It prefers
`DeviceOwnerAuthenticationWithBiometrics` and falls back to
`DeviceOwnerAuthentication` (biometrics-or-password) so password-only Macs and
Macs without an enrolled fingerprint still work.

- First navigation to History runs the check. Success unlocks it for **5
  minutes** (JS timer), or until the **window stays unfocused for over a
  minute**, whichever comes first.
- Failure / cancel shows a **locked state with an Unlock (Retry)** button.

| Platform | Status |
|----------|--------|
| macOS (Touch ID or password) | Gated |
| Windows / Linux | **No support today** — the `authenticate` command returns `{ supported: false }`, and the GUI shows History **without a gate** plus a subtle *"biometric lock unavailable on this platform"* note in Settings. **Never a fake lock.** |

### HIST-6 — sensitive-content blur

History entries that look like secrets are rendered **blurred** with a
`sensitive` badge; **click-and-hold** on the content or the **👁 Reveal** button
uncovers them (Reveal shows for 10 s). Applies to the History list only.

The heuristic is a **pure Rust module** (`src/sensitive.rs`, unit-tested with
`cargo test`), exposed as the `is_sensitive` / `is_sensitive_batch` tauri
commands — the frontend calls the batch command once per page and only owns the
blur/reveal UX (no duplicated logic). An entry is flagged if it contains a
password-ish keyword (`password` / `passwd` / `secret` / `token` / `bearer` /
`api[_-]?key`), a private-key header (`-----BEGIN`), a Luhn-valid credit-card
number, or a high-entropy token (≥ 20 chars, mixed classes, Shannon entropy ≥
3.5 bits/char). The heuristic errs toward hiding.

## Frontend

Plain static HTML/CSS/JS under `dist/` — **no npm / node / bundler**.
`tauri.conf.json` sets `build.frontendDist = "./dist"` and
`app.withGlobalTauri = true`, so the frontend uses `window.__TAURI__.core.invoke`
and `window.__TAURI__.event.listen` directly. The pairing QR is rendered as the
daemon-provided Unicode `<pre>` (a client-side visual QR generator was not added
to avoid a JS dependency; the `<pre>` is scannable).

## IPC commands used

All are newline-delimited JSON on the daemon socket (see
`crates/ucb-daemon/src/ipc.rs`):

`status`, `history_list`, `history_star`, `history_delete`, `config_get`,
`config_set` (now also `max_auto_file_bytes`), `revoke`, `discovered`,
`pair_listen_start` + `pair_confirm`, `pair_connect`, `transfers_subscribe`.

The pairing and transfer commands are streamed over a persistent connection and
surfaced to the frontend as `pair://event` and `transfer://event` events.

## Local tauri commands (no daemon socket)

These run inside the GUI process:

- `platform_capabilities() -> { os, capture_protection, biometrics }` — what
  this platform+device can enforce, so the frontend never shows a fake lock or a
  dead toggle.
- `set_capture_protection(enabled)` — HIST-7 toggle (see matrix above).
- `authenticate(reason) -> { supported, success, error }` — HIST-5 biometric
  prompt (macOS only; `supported: false` elsewhere).
- `is_sensitive(text) -> bool` and `is_sensitive_batch(texts) -> [bool]` —
  HIST-6 classification (heuristics in `src/sensitive.rs`).
- `ucb_binary_path()`, `ucb_is_initialized()`, `daemon_is_managed()` — onboarding
  probes.
- `onboard(name, keep_background)` — first-run setup (init if needed, then start
  syncing as a managed child or a background service).
- `daemon_start()` / `daemon_stop()` / `daemon_restart()` — manage the GUI-owned
  `ucb run` child.
- `reveal_in_folder(path)` — "Show in folder" (shells out to
  `open -R` / `explorer /select,` / `xdg-open`; no Tauri plugin required).
- `check_for_update()` → `{ available, version?, notes? }` and `install_update()`
  — REL-1 auto-updater (wraps `tauri-plugin-updater`; download is signature-
  verified, then the app relaunches). Called from the frontend so the no-npm UI
  needs no JS plugin bindings.

## Packaging, install & auto-update (REL-1)

The GUI ships as a real installable app with the `ucb` daemon bundled inside it,
plus a GitHub-releases-backed auto-updater.

### The `ucb` sidecar

The daemon binary is shipped **inside** the app bundle as a Tauri v2
[sidecar](https://v2.tauri.app/develop/sidecar/) (`bundle.externalBin` in
`tauri.conf.json` → `binaries/ucb`). Tauri sidecars must be suffixed with the
Rust target triple so a build can pick the right one; the bundler strips the
suffix again when it copies the file next to the app executable
(`…/Contents/MacOS/ucb`). Stage it before any bundle build:

```sh
cargo build --release -p ucb-daemon        # from the repo root
bash scripts/prepare-sidecar.sh            # copies target/release/ucb → apps/ucb-gui/binaries/ucb-<triple>
# scripts/prepare-sidecar.sh <triple>      # override the triple for cross/CI builds
```

`binaries/` is git-ignored — it is a build output, regenerated per platform.

### Icons

`scripts/gen-icons.py` (Pillow + `iconutil`) renders the clipboard glyph and
writes the full set into `icons/` — `32x32.png`, `128x128.png`,
`128x128@2x.png`, `512x512.png`, `icon.png` (1024²), `icon.icns` (macOS),
`icon.ico` (Windows). The outputs are committed; regenerate with
`python3 scripts/gen-icons.py`.

### Building installers

```sh
cargo install tauri-cli --version '^2' --locked   # one-time
cargo build --release -p ucb-daemon               # repo root
bash scripts/prepare-sidecar.sh
cd apps/ucb-gui && cargo tauri build              # → target/release/bundle/
```

Configured bundle targets: macOS `.app` + `.dmg`, Windows `.msi` + NSIS,
Linux `.deb` + `.AppImage` (Tauri only builds the targets valid for the host).
`productName` "Universal Clipboard", identifier `dev.ucb.universal-clipboard`,
version `0.1.0` (kept in sync with the crate version).

### macOS signing & notarization

`bundle.macOS.signingIdentity` is `"-"` (**ad-hoc** signing) — the app is signed
but with no Apple Developer ID, so it is **not notarized**. Users will see
Gatekeeper's "unidentified developer" warning and must right-click → **Open** on
first launch. For real distribution, set the `APPLE_SIGNING_IDENTITY` /
`APPLE_CERTIFICATE` and notarization env vars (`APPLE_ID`, `APPLE_PASSWORD`,
`APPLE_TEAM_ID`) so `tauri build` signs with your Developer ID and notarizes.

### Auto-updater & signing key

The app uses `tauri-plugin-updater`, pointed at the GitHub "latest release"
`latest.json` convention:

```
https://github.com/nathandalpatan/universal-clipboard/releases/latest/download/latest.json
```

On launch the GUI **silently** checks for an update (`check_for_update` command)
and only raises a toast — with an **Install & restart** button — if one exists.
**Settings → Software updates → Check for updates** runs the same check manually
and always reports the result (including "up to date"). Downloads are verified
against the updater **public key** embedded in `tauri.conf.json`
(`plugins.updater.pubkey`) before install.

The matching **private key** lives at `apps/ucb-gui/.updater-key` (generated with
`cargo tauri signer generate`). **It is git-ignored and must NEVER be committed.**
The updater will only trust artifacts signed with it, so:

1. Store the private key as a GitHub Actions secret named
   **`TAURI_SIGNING_PRIVATE_KEY`** (paste the *contents* of
   `apps/ucb-gui/.updater-key`):
   ```sh
   gh secret set TAURI_SIGNING_PRIVATE_KEY < apps/ucb-gui/.updater-key
   ```
   The key here has an **empty password**; if you regenerate it with a password,
   also set `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
2. Keep a secure backup of `apps/ucb-gui/.updater-key`. **If you lose it you can
   never sign a compatible update again** — every installed client is pinned to
   the public key baked into its binary.

To regenerate the keypair (rotates the pubkey → breaks updates for already-shipped
clients until they reinstall):

```sh
cargo tauri signer generate --ci -p "" -w apps/ucb-gui/.updater-key -f
# then copy the printed public key into tauri.conf.json → plugins.updater.pubkey
```

### Release CI

`.github/workflows/release.yml` runs on a `v*` tag: a matrix of
macOS (aarch64 + x86_64), Ubuntu, and Windows builds the daemon, stages the
sidecar, and hands off to `tauri-apps/tauri-action`, which builds the installers,
signs the updater artifacts with `TAURI_SIGNING_PRIVATE_KEY`, assembles
`latest.json`, and uploads everything to the (draft) GitHub release for the tag.
Publish the draft to make the update live. `ci.yml` additionally builds + clippy
+ tests the GUI on `macos-latest` on every push/PR.

## Not done yet (future work)

- **Windows/named-pipe client**: the IPC client is unix-socket only; on Windows
  the commands return an "unsupported" error (the daemon speaks named pipes
  there — a small client addition would close this).
- `config_set` changes require a daemon restart to take effect; the reply reports
  `restart_required: true`, and the Settings **Restart sync** button applies it
  in one click for a GUI-managed daemon. Hot-reload is still future work.
- **Nearby "Pair" requires the peer to be listening**: one-click pairing dials the
  peer's pairing port, so the other device must have "Show pairing code" (or
  `ucb pair --listen`) active. A future rendezvous/notify step could remove this.
- **Discovered peers carry no platform**: mDNS TXT records don't include the OS,
  so the Nearby list shows name + IP (not platform).
