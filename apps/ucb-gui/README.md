# ucb-gui — Universal Clipboard desktop shell

A Tauri v2 tray application that is a **frontend** for the running
`ucb` daemon. It does not embed the sync engine: it opens the daemon's
existing unix-socket IPC (`<config-dir>/daemon.sock`, newline-delimited JSON)
and relays commands. The daemon stays the single engine process.

Tickets covered: **HIST-3** (history GUI), **UX-2** (devices + pair CTA),
**PAIR-2** (on-screen QR pairing), **UX-3** groundwork (350 ms spinner
threshold).

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
