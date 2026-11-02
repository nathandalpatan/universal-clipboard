#!/usr/bin/env bash
# Stage the `ucb` daemon as a Tauri v2 sidecar (REL-1).
#
# Tauri's `externalBin` mechanism requires each sidecar binary to be suffixed
# with the Rust *target triple* (e.g. `ucb-aarch64-apple-darwin`) so a build can
# pick the right one per platform; the bundler strips the suffix again when it
# copies the file next to the app executable. This script copies the release
# `ucb` built at the workspace root into apps/ucb-gui/binaries/ with that suffix.
# On Windows it also stages `ucbw`, the windowless launcher used by the login
# autostart entry (bundled via tauri.windows.conf.json).
#
# Usage:
#   scripts/prepare-sidecar.sh                 # auto-detect the host target triple
#   scripts/prepare-sidecar.sh <target-triple> # override (cross-compile / CI)
#
# Run `cargo build --release -p ucb-daemon` first; CI does this per matrix leg.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$REPO_ROOT/apps/ucb-gui/binaries"

# Resolve the target triple: explicit arg wins, else ask rustc for the host.
if [[ $# -ge 1 && -n "$1" ]]; then
  TRIPLE="$1"
else
  TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
fi
if [[ -z "$TRIPLE" ]]; then
  echo "error: could not determine the target triple" >&2
  exit 1
fi

# Windows binaries carry a .exe extension on both source and sidecar name.
EXT=""
BINS=(ucb)
case "$TRIPLE" in
  *windows*) EXT=".exe"; BINS=(ucb ucbw) ;;
esac

mkdir -p "$BIN_DIR"
for BIN in "${BINS[@]}"; do
  SRC="$REPO_ROOT/target/release/${BIN}${EXT}"
  if [[ ! -f "$SRC" ]]; then
    echo "error: $SRC not found — run 'cargo build --release -p ucb-daemon' first" >&2
    exit 1
  fi
  DEST="$BIN_DIR/${BIN}-${TRIPLE}${EXT}"
  cp -f "$SRC" "$DEST"
  chmod +x "$DEST"
  echo "staged sidecar: $DEST"
done
