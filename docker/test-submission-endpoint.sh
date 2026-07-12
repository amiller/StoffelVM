#!/usr/bin/env bash
# W4 program-submission endpoint integration test (spec task W4).
#
# Builds the stoffel-vm test image (CC=clang, see submission.Dockerfile) and
# runs the W4 integration test inside it. Asserts:
#   - the committee runs the submitted program and reveals the expected result;
#   - the submission job id equals the program's blake3 id (sync-by-hash);
#   - a tampered program (wrong claimed id) is rejected as ProgramTampered.
#
# Usage:
#   ./docker/test-submission-endpoint.sh
#
# No TEE, no external services — the HoneyBadger committee runs over loopback
# QUIC inside the container.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.submission.yml"
PROJECT_NAME="${PROJECT_NAME:-stoffel-w4-submission}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-600}"
CONTAINER="stoffel-w4-submission-test"

compose() {
    docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
}

cleanup() {
    compose down --remove-orphans -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

compose down --remove-orphans -v >/dev/null 2>&1 || true

echo "== W4: building submission test image (CC=clang) =="
compose build

echo "== W4: running program-submission integration test =="
compose up --no-build -d

# Wait for the one-shot test container to finish.
start_ts="$(date +%s)"
while true; do
    status="$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || echo missing)"
    if [[ "${status}" == "exited" || "${status}" == "missing" ]]; then
        break
    fi
    if (( "$(date +%s)" - start_ts >= WAIT_TIMEOUT_SECS )); then
        echo "Timed out after ${WAIT_TIMEOUT_SECS}s waiting for the W4 test container" >&2
        compose logs "${CONTAINER}" >&2 || true
        exit 1
    fi
    sleep 3
done

exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${CONTAINER}" 2>/dev/null || echo 1)"
logs="$(compose logs --no-color submission-test 2>/dev/null || true | sed 's/\x1b\[[0-9;]*m//g')"

if [[ "${exit_code}" != "0" ]]; then
    echo "W4 test container exited with ${exit_code}" >&2
    echo "${logs}" >&2
    exit 1
fi

require_log() {
    local needle="$1"
    local description="$2"
    if ! grep -Fq "${needle}" <<<"${logs}"; then
        echo "Missing ${description}: ${needle}" >&2
        echo "${logs}" >&2
        exit 1
    fi
}

# Prove the test actually ran (libtest exits 0 even when a filter matches
# nothing, so we must assert a positive test count).
require_log "test result: ok. 1 passed" "W4 test executed exactly one test"
require_log "committee revealed result: 375" "committee run result (15 * 25)"
require_log "=== W4 program submission endpoint test PASSED ===" "W4 test pass banner"
# The tampered-program rejection is asserted inside the test itself:
# submit_tcp(...) for a wrong claimed id must return ProgramTampered, and the
# test panics if the committee runner is ever invoked for a tampered request.
# A clean exit 0 + the pass banner therefore proves the rejection path.

echo "== W4 program-submission endpoint test PASSED =="
echo "  - client submitted a program over the submission TCP endpoint"
echo "  - committee synced the program by blake3 hash and ran it"
echo "  - result (375 = 15 * 25) returned to the client"
echo "  - tampered program (wrong claimed id) rejected as ProgramTampered"
