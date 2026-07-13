#!/usr/bin/env bash
# W5 dstack real-TDX attestation verification wrapper (spec task W5).
#
# Runs the W5 real-TDX attestation tests in a container against a real,
# Intel-issued TDX quote + DCAP collateral vector. This is the CI-runnable
# proof that the W3 DstackAttestor is wired to real TDX (W5), and captures the
# attestation log line showing the measurement match.
#
# No TEE hardware required: the tests verify a recorded real TDX quote rather
# than minting a fresh one, so this runs anywhere docker does.
#
# Usage:
#   ./docker/test-dstack-attestation.sh           # build + run in docker
#   ./docker/test-dstack-attestation.sh --native  # run locally with cargo (needs CC=clang)
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--native" ]]; then
    # Native run: requires clang (gcc 9.x trips aws-lc memcmp guard).
    export CC="${CC:-clang}"
    export CXX="${CXX:-clang++}"
    exec cargo test -p stoffel-vm --features attestation-dstack --lib -- \
        --exact --nocapture --test-threads 1 \
        net::attestation::tests::verify_dstack_quote_extracts_measurement_and_cert_binding \
        net::attestation::tests::dstack_admission_admits_real_tdx_quote_with_matching_measurement \
        net::attestation::tests::dstack_admission_rejects_unallowlisted_measurement \
        net::attestation::tests::dstack_admission_rejects_cert_binding_mismatch
fi

echo "Building + running the W5 dstack real-TDX attestation tests in Docker..."
docker compose -f docker-compose.dstack.yml up --build --exit-code-from dstack-attestation-test
