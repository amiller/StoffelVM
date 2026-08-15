# syntax=docker/dockerfile:1.4
# dstack TEE node image for the attestation-gated Stoffel MPC committee
# (spec task W5 — dstack packaging + staging CVM bring-up).
#
# This image is what runs inside each dstack confidential VM (CVM). It is the
# slim W1 node build (`stoffel-run`, no compiler) compiled WITH the
# `attestation-dstack` feature so that:
#
#   * every node can VERIFY its peers' real Intel TDX quotes (W3
#     `DstackAttestor` -> `dcap-qvl`, wired in W5), and
#   * every node can OBTAIN its own quote from the dstack device manager
#     (`/var/run/dstack.sock`) bound to its TLS identity, to present at
#     admission (`obtain_dstack_evidence`).
#
# Build C deps with CC=clang: gcc 9.x trips aws-lc's memcmp guard
# (see tasks/mpc-node-attestation-spec.md). The same flag is mandatory at
# runtime-image build time.
#
# Build:
#   docker build -f docker/dstack.Dockerfile -t stoffel-dstack-node:dev .
# On a staging CVM the image is launched by dstack against the app manifest in
# dstack/stoffel-node.yaml (N replicas), not by plain `docker run`.

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
        pkg-config \
        libssl-dev \
        git \
        clang \
    && rm -rf /var/lib/apt/lists/*

# aws-lc-sys MUST be compiled with clang, not gcc 9.x (aws-lc memcmp guard).
ENV CC=clang
ENV CXX=clang++

# Cap build parallelism: un-capped rustc has OOM-frozen both build hosts.
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

WORKDIR /build
COPY . .

RUN printf '%s\n' '[net]' 'git-fetch-with-cli = true' '' > /build/.cargo/config.toml
RUN mkdir -p ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Build the slim node binary WITH real-TDX attestation. Only -p stoffel-vm-runner
# is needed (it does not pull the off-chain coordinator git deps). The compiler
# crate (stoffellang) stays a dev-dependency and is excluded from this build
# (W1 node slimming).
RUN --mount=type=ssh \
    cargo build --release \
        --package stoffel-vm-runner --bin stoffel-run \
        --features attestation-dstack && \
    strip target/release/stoffel-run

# Also compile (do not run) the lib test binary with the feature so the staging
# image can self-prove its verifier against a real Intel-issued TDX quote
# vector on boot (see docker/test-dstack-attestation.sh).
#
# Ask cargo where it put the executable rather than globbing a layout. Current
# nightly emits unittest binaries under target/release/build/<pkg>/<hash>/out/,
# not target/release/deps/, so a glob of deps/ silently matches nothing and the
# image build dies several stages later with a bare `cp: cannot stat ''`.
RUN --mount=type=ssh \
    cargo test --release -p stoffel-vm --features attestation-dstack --lib --no-run \
        --message-format=json > /tmp/test-build.json && \
    exe="$(grep -o '"executable":"[^"]*"' /tmp/test-build.json | tail -n1 | cut -d'"' -f4)" && \
    if [ -z "$exe" ]; then echo "no test executable reported by cargo" >&2; exit 1; fi && \
    cp "$exe" /build/w5_attestation_test

# W7: Build the StoffelLang compiler (dev-dependency, not included in slim node
# build) to compile the demo program from source during image build. This ensures
# reproducibility — the demo bytecode is derived from the committed source.
RUN --mount=type=ssh \
    cargo build --release --package stoffellang && \
    strip target/release/stoffellang

# W7: Compile the demo program from source (docker/programs/demo_program.stfl).
# The resulting bytecode is baked into the image at /app/programs/program.stflb.
RUN --mount=type=ssh \
    ./target/release/stoffellang -b docker/programs/demo_program.stfl \
        -o /tmp/program.stflb

# ============================================================================
# Stage 2: Runtime (slim)
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
        net-tools \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Slim node binary (no compiler — W1).
COPY --from=builder /build/target/release/stoffel-run /app/stoffel-run

# W7: Demo program (AVSS keygen using Share.random, no client inputs).
# Compiled from source in the builder stage (docker/programs/demo_program.stfl).
COPY --from=builder /tmp/program.stflb /app/programs/program.stflb

# W5 real-TDX attestation test binary (stable path). The builder already
# resolved its location, so this is a plain copy.
COPY --from=builder /build/w5_attestation_test /usr/local/bin/w5_attestation_test

# Default environment. STOFFEL_ATTESTATION_* are overridden per-replica by the
# dstack app manifest (dstack/stoffel-node.yaml). MODE=dstack selects real TDX;
# the allowlist pins the expected image measurement so a wrong/tampered image is
# refused admission.
#
# W7: Committee defaults. n=2 t=0 is the smallest valid committee that
# satisfies the HoneyBadger constraint (n >= 3t + 1). This works for
# demo purposes and is the easiest to test locally with docker-compose.
ENV STOFFEL_BIND_ADDR="0.0.0.0:9000"
ENV STOFFEL_N_PARTIES="4"
ENV STOFFEL_THRESHOLD="1"
ENV STOFFEL_ROLE="party"
ENV STOFFEL_PARTY_ID="0"
ENV STOFFEL_BOOTSTRAP_ADDR=""
ENV STOFFEL_PROGRAM="/app/programs/program.stflb"
ENV STOFFEL_ENTRY="main"
ENV RUST_LOG="stoffel::attestation=info,info"
# Real TDX attestation admission gate (W3 admission layer over W5 DstackAttestor).
ENV STOFFEL_ATTESTATION_MODE="dstack"
# Comma-separated hex of expected 32-byte image measurements. REQUIRED when
# MODE=dstack; left empty here and set by the manifest / staging env so a bare
# `docker run` fails closed rather than admit unattested peers.
ENV STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS=""
# PCCS used by `obtain_dstack_evidence` to fetch DCAP collateral. Default is the
# public Phala PCCS; staging may point this at a local/cached PCCS.
ENV STOFFEL_DSTACK_PCCS_URL="https://pccs.phala.network"
# W6 HTTP observability server. The dstack-webhost `tee-daemon` HTTP-proxies
# exactly ONE image_port per app; this is it. GET /health is the liveness
# probe and GET /attestation reports this node's own attested measurement once
# obtained (the "stoffel running attested on the dstack pod" report). The
# submission RPC (16180) is a SEPARATE, non-proxied port.
ENV STOFFEL_HTTP_ADDR="0.0.0.0:8090"

# 8090  = W6 HTTP observability (the dstack-proxied image_port)
# 9000  = bootnode coordination (leader)
# 10000 = party-to-party MPC traffic
# 16180 = submission RPC (W4) — NOT proxied; reached directly
EXPOSE 8090 9000 10000 16180

COPY docker/entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
