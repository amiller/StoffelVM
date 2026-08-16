#!/bin/bash
# Run cargo inside a memory-capped container. USE THIS INSTEAD OF BARE CARGO.
#
# Bare cargo has OOM-frozen this host more than once, taking ssh with it. The
# cap is not a formality — an un-capped rustc on this workspace will use every
# byte available and the machine stops answering.
#
#   ./scripts/agent-build.sh check -p stoffel-vm --features attestation-dstack
#   ./scripts/agent-build.sh test  -p stoffel-vm --features attestation-dstack --lib net::lobby
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$HOME/cargo-targets/$(basename "$REPO")}
mkdir -p "$TARGET"
exec docker run --rm \
  --memory=8g --cpus=2 \
  -e CARGO_BUILD_JOBS=2 -e CC=clang -e CXX=clang++ \
  -e CARGO_TARGET_DIR=/target \
  -v "$REPO":/build -v "$TARGET":/target -w /build \
  --entrypoint /bin/bash rustlang/rust:nightly-bookworm -c "
    if ! command -v clang >/dev/null; then
      apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq clang >/dev/null 2>&1
    fi
    cargo $(printf '%q ' "$@")
  "
