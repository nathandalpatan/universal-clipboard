# Infrastructure & test tooling

Test/CI infrastructure for universal-clipboard. Everything here lives outside
the Rust crates: CI, the Docker multi-device harness, netem fault injection,
and the cargo-fuzz project.

| Ticket | What | Where |
|---|---|---|
| REL-1 (partial) | CI: build/test/lint/artifact on Linux + macOS | `.github/workflows/ci.yml` |
| TEST-1 | Two-device Docker integration harness | `docker/`, `scripts/harness-test.sh` |
| TEST-2 | netem fault injection presets | `scripts/netem.sh` |
| TEST-4 | cargo-fuzz targets for the wire parser | `fuzz/` |

## Docker harness (TEST-1)

Spins up two ucb daemons (`alpha`, `beta`) as containers on one bridge network,
pairs them, runs both in headless file-backed clipboard mode, and checks that a
clip written on one device propagates to the other in both directions.

```sh
scripts/harness-test.sh              # build image, run baseline sync checks
scripts/harness-test.sh --netem      # also run checks under latency + loss
scripts/harness-test.sh --no-build   # reuse an already-built image
scripts/harness-test.sh --keep       # leave containers up after (debugging)
```

The script always tears containers down on exit (`docker compose down -v`) via
a trap, even on failure, unless `--keep` is given. It prints `PASS`/`FAIL` per
check and exits non-zero if any check fails.

### How it drives the daemon

Container paths: config dir `/data/cfg`, headless dir `/data/head`, port
`48521`. The harness expects this daemon CLI contract:

- `ucb --config-dir <dir> init --name <n> --file-keystore --print-id` — creates
  the identity, prints device info as JSON to stdout.
- `ucb --config-dir <dir> pair --listen --yes` / `pair --connect <host:port>
  --yes` — pair two devices; `--yes` auto-confirms the verification code.
- `ucb --config-dir <dir> peer add <host:port>` — add a static peer to dial
  directly (used because mDNS multicast is unreliable on the docker bridge).
- `ucb --config-dir <dir> run --headless-dir <dir>` — headless file-backed
  clipboard: text written into `<dir>/clip-in` is broadcast; applied remote
  clips appear in `<dir>/clip-out`; a JSONL event log is at
  `<dir>/clip-log.jsonl`.

### Images

`docker/Dockerfile` is multi-stage: a `rust:1-bookworm` builder (same apt deps
as CI) compiles `ucb-daemon` in release, then a `debian:bookworm-slim` runtime
carries the binary plus `libdbus-1-3` (keyring backend) and `iproute2` (netem).
`docker/docker-compose.yml` defines the two services; both get `NET_ADMIN` so
`tc` can apply netem qdiscs. The build context is the repo root so the
Dockerfile can copy `Cargo.toml`/`Cargo.lock`/`crates/`.

## netem fault injection (TEST-2)

```sh
scripts/netem.sh <alpha|beta> <preset>
```

| Preset | tc qdisc | Effect |
|---|---|---|
| `latency` | `netem delay 200ms 50ms` | 200ms ±50ms delay |
| `loss` | `netem loss 10%` | 10% packet loss |
| `reorder` | `netem delay 50ms reorder 25% 50%` | 25% of packets reordered |
| `clear` | `tc qdisc del ... root` | remove netem, restore normal |

Applied to the container's `eth0` egress via `docker compose exec`. Override the
interface with `NETEM_IFACE` if needed. `harness-test.sh --netem` uses the
`latency` and `loss` presets automatically.

## Fuzzing (TEST-4)

cargo-fuzz project targeting `ucb-core`'s untrusted decode path. It's a
standalone cargo project (detached from the workspace via an empty
`[workspace]` table in `fuzz/Cargo.toml`) and only depends on `ucb-core`, so it
builds even while the rest of the workspace is churning.

One-time setup:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run a target (from the repo root):

```sh
cargo +nightly fuzz run fuzz_wire_decode  -- -max_total_time=60
cargo +nightly fuzz run fuzz_payload_hash -- -max_total_time=60
```

| Target | Exercises | Invariant |
|---|---|---|
| `fuzz_wire_decode` | `WireMessage::decode(data)` | never panics; `Err` only |
| `fuzz_payload_hash` | decoded `ClipboardItem` → `content_hash()` + redacted `Debug` | never panics; SEC-2 redaction path |

Any crash is written to `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`. The
corpus accumulates under `fuzz/corpus/<target>/`.

## CI notes (REL-1, partial)

`.github/workflows/ci.yml` runs on every push and PR across `ubuntu-latest` and
`macos-latest`:

1. (Linux only) apt-install `libdbus-1-dev pkg-config libxcb1-dev
   libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev` — dbus for the
   keyring secret-service backend, xcb libs for `arboard`.
2. Install stable Rust (`dtolnay/rust-toolchain`) + clippy, cache with
   `Swatinem/rust-cache`.
3. `cargo test --workspace`
4. `cargo clippy --workspace --all-targets -- -D warnings`
5. `cargo build --release -p ucb-daemon`
6. Upload the `ucb` binary as an artifact.

**Future work (not in this workflow):** signed release publishing via the
tauri-updater / signed-manifest pipeline (code-signing, notarization, hosted
update manifest) is not wired up yet — CI only uploads an unsigned build
artifact.
