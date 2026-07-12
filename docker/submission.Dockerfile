# syntax=docker/dockerfile:1.4
# Test image for the W4 program-submission endpoint (spec task W4).
#
# Builds the stoffel-vm test binary and runs the W4 integration test, which
# proves the full submit → sync-by-hash → committee-run → result flow plus the
# tampered-program rejection, entirely inside the container (no TEE required).
#
# CC=clang is mandatory: gcc 9.x trips aws-lc's memcmp guard
# (see tasks/mpc-node-attestation-spec.md, "build C deps with CC=clang").

FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
        pkg-config \
        libssl-dev \
        git \
        clang \
    && rm -rf /var/lib/apt/lists/*

# aws-lc-sys must be compiled with clang, not gcc 9.x.
ENV CC=clang
ENV CXX=clang++

WORKDIR /build
COPY . .

RUN printf '%s\n' '[net]' 'git-fetch-with-cli = true' '' > /build/.cargo/config.toml
RUN mkdir -p ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Compile the W4 integration test binary without running it. Only -p stoffel-vm
# is needed (it does not pull the off-chain coordinator git deps).
RUN --mount=type=ssh \
    cargo test -p stoffel-vm --features hb_itest --lib --no-run \
        submission_endpoint_runs_committee_and_rejects_tampered_program

# ---------------------------------------------------------------------------
# Runtime: a slim image that executes the prebuilt W4 test binary.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# cargo emits the lib-unit-test executable as target/debug/deps/stoffel_vm-<hash>.
# Copy it to a stable path.
RUN --mount=from=builder,source=/build/target,target=/tmp/target \
    cp "$(ls -t /tmp/target/debug/deps/stoffel_vm-* | grep -vE '\.(d|so)$' | head -n1)" \
       /usr/local/bin/w4_submission_test

ENV RUST_BACKTRACE=1
# The test binds ephemeral loopback QUIC/TCP ports and needs a multi-thread
# runtime; --test-threads=1 keeps the HB committee harness deterministic.
# Use the full module path with --exact so the filter is unambiguous.
ENTRYPOINT ["/usr/local/bin/w4_submission_test", "tests::program_submission_integration::submission_endpoint_runs_committee_and_rejects_tampered_program", "--exact", "--nocapture", "--test-threads", "1"]
