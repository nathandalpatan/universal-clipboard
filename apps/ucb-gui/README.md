# ucb-gui — Universal Clipboard desktop shell

A Tauri v2 tray application that is a **frontend** for the running
`ucb` daemon. It does not embed the sync engine: it opens the daemon's
existing unix-socket IPC (`<config-dir>/daemon.sock`, newline-delimited JSON)
and relays commands. The daemon stays the single engine process.

Tickets covered: **HIST-3** (history GUI), **UX-2** (devices + pair CTA),
**PAIR-2** (on-screen QR pairing), **UX-3** groundwork (350 ms spinner
threshold), and the history-protection trio **HIST-5** (biometric gate),
**HIST-6** (sensitive-content blur), **HIST-7** (screenshot/recording
exclusion).

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
`config_set`, `revoke`, `pair_listen_start` + `pair_confirm`.

## Local tauri commands (no daemon)

These run entirely inside the GUI process (they do not touch the daemon socket):

- `platform_capabilities() -> { os, capture_protection, biometrics }` — what
  this platform+device can enforce, so the frontend never shows a fake lock or a
  dead toggle.
- `set_capture_protection(enabled)` — HIST-7 toggle (see matrix above).
- `authenticate(reason) -> { supported, success, error }` — HIST-5 biometric
  prompt (macOS only; `supported: false` elsewhere).
- `is_sensitive(text) -> bool` and `is_sensitive_batch(texts) -> [bool]` —
  HIST-6 classification (heuristics in `src/sensitive.rs`).

## Not done yet (future work)

- **REL-1**: bundling, code-signing, and the auto-updater. Right now this is
  `cargo run` only; no `.app`/`.dmg`/`.deb` packaging and no updater are wired.
  The `bundle` section in `tauri.conf.json` and the placeholder `icons/` exist
  as a starting point, but real icon assets and signing config are still needed.
- **UX-3 completion**: only the spinner threshold is in place. Toast
  notifications, richer error surfacing, and optimistic updates remain.
- **Windows/named-pipe client**: the IPC client is unix-socket only; on Windows
  the commands return an "unsupported" error (the daemon speaks named pipes
  there — a small client addition would close this).
- `config_set` changes (e.g. `auto_file_sync`) require a daemon restart to take
  effect; the reply reports `restart_required: true`. Hot-reload is future work.
