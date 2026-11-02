# Universal Clipboard

Copy on one computer, paste on another. Universal Clipboard syncs your
clipboard between your devices on the same local network, encrypted end to
end. There is no cloud, no account and no server in the middle.

Runs on macOS, Linux and Windows. Up to 3 devices per group.

> **Status:** pre-release (`0.1.0`). There are no published installers yet;
> build from source below. macOS builds are ad-hoc signed, not notarized, so
> Gatekeeper will warn on first launch.

## Features

- **Clipboard sync:** text, HTML and images, applied to every paired device.
  Conflicts resolve the same way everywhere (newest copy wins).
- **Offline catch-up:** clips copied while a device is away are queued and
  delivered when it reconnects.
- **File transfer:** `ucb send <file>`, or opt-in automatic sync of copied
  files, with resume after an interrupted transfer.
- **Encrypted history:** searchable local history (SQLCipher), stars synced
  across devices, 30-day retention for unstarred items.
- **Desktop app:** tray app with one-click pairing, transfer progress, and a
  history view that blurs likely secrets, can require Touch ID (macOS) and is
  hidden from screen capture (macOS/Windows).
- **Runs in the background:** installs as a login service (launchd, systemd
  user unit, or a Windows login entry).

## How it works

Each device has its own keypair, and its device ID is derived from that key.
Devices find each other with mDNS and connect over TCP using the
[Noise](https://noiseprotocol.org/) protocol (`Noise_XX_25519_ChaChaPoly_BLAKE2s`),
so every connection is mutually authenticated and encrypted. A device only
talks to peers you paired with explicitly, and pairing makes you confirm the
same 6-digit code on both screens. A paired device can be revoked at any time,
and the revocation propagates to your other devices.

For the full design, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start (CLI)

Build the `ucb` binary (needs a stable [Rust](https://rustup.rs/) toolchain):

```sh
cargo build --release -p ucb-daemon   # → target/release/ucb
```

Then, on each device:

```sh
ucb init                     # create this device's identity
ucb pair --listen            # on the first device
ucb pair --connect <addr>    # on the second; confirm the 6-digit codes match
ucb run                      # on both devices: start syncing
```

Copy text on one device and it lands on the other's clipboard. Useful extras:

```sh
ucb guide                    # plain-language walkthrough of every command
ucb status                   # who's connected
ucb send <file>              # send a file to a connected peer
ucb history list             # browse clipboard history
ucb service install          # start syncing automatically at login
```

The daemon listens on TCP port `48521` (pairing from the app uses `48522`),
so allow those through your firewall.

## Desktop app

The GUI in [`apps/ucb-gui`](apps/ucb-gui) is a Tauri v2 front end for the
daemon. It can set up and start the daemon for you on first run.

```sh
cd apps/ucb-gui && cargo run
```

See [apps/ucb-gui/README.md](apps/ucb-gui/README.md) for building installers
and signing updates.

## Project layout

| Path | What it is |
|---|---|
| `crates/ucb-core` | Shared types and the wire protocol |
| `crates/ucb-crypto` | Device identity, Noise handshake, encrypted channel, pairing codes |
| `crates/ucb-discovery` | mDNS discovery |
| `crates/ucb-clipboard` | OS clipboard watching and writing |
| `crates/ucb-sync` | The sync engine: sessions, trust, conflicts, offline queue, transfers |
| `crates/ucb-files` | Chunked, resumable file transfer |
| `crates/ucb-history` | Encrypted clipboard history |
| `crates/ucb-daemon` | The `ucb` CLI and background daemon |
| `apps/ucb-gui` | Desktop app (separate Cargo workspace) |
| `scripts/` | Test harnesses and build helpers ([README](scripts/README.md)) |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs both on every pull request, plus a Windows build and a macOS GUI
check. `main` is protected: changes land through pull requests.

## License

[MIT](LICENSE)
