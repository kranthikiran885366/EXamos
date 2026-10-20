#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-e1-consent-test.XXXXXX")"
ARTIFACT_DIR="${EXAMOS_E1_ARTIFACT_DIR:-$WORKSPACE/artifacts/e1}"
trap 'rm -rf "$TEST_DIR"' EXIT

cc -std=c11 -Wall -Wextra -Werror \
    -Wformat=2 -Wformat-security -I"$WORKSPACE/server/include" \
    "$WORKSPACE/server/environment/e1_consent.c" \
    "$WORKSPACE/server/events/event_chain.c" \
    "$WORKSPACE/tests/e1/e1_consent_test.c" \
    -lssl -lcrypto -lpthread \
    -o "$TEST_DIR/e1-consent-test"
"$TEST_DIR/e1-consent-test"

COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
DIRTY_COUNT="$(git -C "$WORKSPACE" status --porcelain=v1 | wc -l | tr -d '[:space:]')"
TREE_STATE="CLEAN"
[ "$DIRTY_COUNT" -eq 0 ] || TREE_STATE="DIRTY"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
ENGINE_SHA256="$(sha256sum "$WORKSPACE/server/environment/e1_consent.c" | cut -d' ' -f1)"
HEADER_SHA256="$(sha256sum "$WORKSPACE/server/include/e1_consent.h" | cut -d' ' -f1)"
CHAIN_SHA256="$(sha256sum "$WORKSPACE/server/events/event_chain.c" | cut -d' ' -f1)"
MAIN_SHA256="$(sha256sum "$WORKSPACE/server/main.c" | cut -d' ' -f1)"
TEST_SHA256="$(sha256sum "$WORKSPACE/tests/e1/e1_consent_test.c" | cut -d' ' -f1)"
RUNNER_SHA256="$(sha256sum "$WORKSPACE/tests/e1/e1-consent-test.sh" | cut -d' ' -f1)"

mkdir -p "$ARTIFACT_DIR"
cat > "$ARTIFACT_DIR/consent-event-unit-test.json" <<EOF
{
  "phase": "E1",
  "check": "session_bound_consent_event_chain",
  "status": "PASS",
  "test_kind": "integration_unit",
  "timestamp": "$TIMESTAMP",
  "source_commit": "$COMMIT",
  "source_tree_state": "$TREE_STATE",
  "dirty_path_count": $DIRTY_COUNT,
  "command": "bash tests/e1/e1-consent-test.sh",
  "event_chain": "real repository event_chain.c with temporary test storage",
  "sensor_hardware_test": "NOT_RUN",
  "collection_authorized_or_started": false,
  "covered_behaviors": [
    "required scope fields",
    "duplicate scope rejection",
    "unknown field rejection",
    "session binding",
    "durable event append and chain verification",
    "collection remains disabled by policy"
  ],
  "source_sha256": {
    "server/environment/e1_consent.c": "$ENGINE_SHA256",
    "server/include/e1_consent.h": "$HEADER_SHA256",
    "server/events/event_chain.c": "$CHAIN_SHA256",
    "server/main.c": "$MAIN_SHA256",
    "tests/e1/e1_consent_test.c": "$TEST_SHA256",
    "tests/e1/e1-consent-test.sh": "$RUNNER_SHA256"
  }
}
EOF
