# syntax=docker/dockerfile:1.4
# Test image for W5 dstack real-TDX attestation verification (spec task W5).
#
# Builds the stoffel-vm test binary WITH the attestation-dstack feature and runs
# the real-TDX attestation tests, which exercise the genuine Intel DCAP trust
# chain against a real (Intel-issued) TDX quote + collateral vector. This is the
# CI-runnable proof that the W3 DstackAttestor is wired to real TDX (W5), and
# the "capture attestation logs showing measurement match" artifact — no TEE
# hardware is required because it verifies a recorded quote.
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

ENV CC=clang
ENV CXX=clang++

WORKDIR /build
COPY . .

RUN printf '%s\n' '[net]' 'git-fetch-with-cli = true' '' > /build/.cargo/config.toml
RUN mkdir -p ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null || true

# Compile the lib test binary (with the feature) without running it. We pass the
# four real-TDX test filters at runtime in the ENTRYPOINT below.
RUN --mount=type=ssh \
    cargo test -p stoffel-vm --features attestation-dstack --lib --no-run

# ---------------------------------------------------------------------------
# Runtime: slim image that runs the prebuilt W5 attestation tests with logging.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# cargo emits the lib-unit-test executable as target/debug/deps/stoffel_vm-<hash>.
RUN --mount=from=builder,source=/build/target,target=/tmp/target \
    cp "$(ls -t /tmp/target/debug/deps/stoffel_vm-* | grep -vE '\.(d|so)$' | head -n1)" \
       /usr/local/bin/w5_attestation_test

ENV RUST_BACKTRACE=1
# Run the four real-TDX verification tests with logging so the measurement-match
# line is captured. libtest takes the filters positionally and the flags once;
# the full module path (net::attestation::tests::...) is required with --exact.
ENTRYPOINT ["/usr/local/bin/w5_attestation_test", \
    "--exact", "--nocapture", "--test-threads", "1", \
    "net::attestation::tests::verify_dstack_quote_extracts_measurement_and_cert_binding", \
    "net::attestation::tests::dstack_admission_admits_real_tdx_quote_with_matching_measurement", \
    "net::attestation::tests::dstack_admission_rejects_unallowlisted_measurement", \
    "net::attestation::tests::dstack_admission_rejects_cert_binding_mismatch"]
