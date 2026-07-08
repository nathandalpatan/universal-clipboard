# TEST-1: multi-stage image for the ucb daemon, used by the Docker multi-device
# integration harness (see scripts/harness-test.sh).
#
# Stage 1 builds the release `ucb` binary with the same system deps CI uses.
# Stage 2 is a slim runtime carrying only what the daemon needs at run time
# plus iproute2 for the netem fault-injection presets (see scripts/netem.sh).

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS build

# Same apt deps as CI: libdbus for the keyring secret-service backend,
# xcb/xorg dev libs for arboard, pkg-config to locate them.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libdbus-1-dev \
        pkg-config \
        libxcb1-dev \
        libxcb-render0-dev \
        libxcb-shape0-dev \
        libxcb-xfixes0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the whole workspace and build just the daemon in release mode.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p ucb-daemon

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Runtime deps:
#   - libdbus-1-3: shared lib the keyring backend links against
#   - iproute2:    `tc` for netem latency/loss/reorder injection
#   - ca-certificates: general good hygiene for a networked daemon
RUN apt-get update && apt-get install -y --no-install-recommends \
        libdbus-1-3 \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/ucb /usr/local/bin/ucb

# Per-container state lives here; the harness mounts/uses subdirs of this.
RUN mkdir -p /data
ENV UCB_DATA=/data

# Keep the container alive; the harness drives `ucb` via `docker compose exec`.
CMD ["sleep", "infinity"]
