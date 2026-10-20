#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-e1-rf-test.XXXXXX")"
ARTIFACT_DIR="${EXAMOS_E1_ARTIFACT_DIR:-$WORKSPACE/artifacts/e1}"
trap 'rm -rf "$TEST_DIR"' EXIT

cc -std=c11 -Wall -Wextra -Werror -Wformat=2 -Wformat-security \
    "$WORKSPACE/agent/environment/rf_scanner.c" \
    "$WORKSPACE/tests/e1/rf_scanner_test.c" \
    -o "$TEST_DIR/rf-scanner-test"

RESULT="PASS"
"$TEST_DIR/rf-scanner-test" || RESULT="FAIL"

if grep -Eq 'iw[[:space:]]+dev.*[[:space:]]scan|popen[[:space:]]*\(' "$WORKSPACE/agent/environment/rf_scanner.c"; then
    echo "[E1-RF] FAIL: active/external scan execution remains in the collector." >&2
    RESULT="FAIL"
else
    echo "[E1-RF] PASS: collector source contains no active scan invocation."
fi

COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
DIRTY_COUNT="$(git -C "$WORKSPACE" status --porcelain=v1 | wc -l | tr -d '[:space:]')"
TREE_STATE="CLEAN"
[ "$DIRTY_COUNT" -eq 0 ] || TREE_STATE="DIRTY"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SCANNER_SHA256="$(sha256sum "$WORKSPACE/agent/environment/rf_scanner.c" | cut -d' ' -f1)"
HEADER_SHA256="$(sha256sum "$WORKSPACE/agent/include/rf_scanner.h" | cut -d' ' -f1)"
MAIN_SHA256="$(sha256sum "$WORKSPACE/agent/main.c" | cut -d' ' -f1)"
TEST_SHA256="$(sha256sum "$WORKSPACE/tests/e1/rf_scanner_test.c" | cut -d' ' -f1)"
RUNNER_SHA256="$(sha256sum "$WORKSPACE/tests/e1/rf-scanner-test.sh" | cut -d' ' -f1)"

mkdir -p "$ARTIFACT_DIR"
cat > "$ARTIFACT_DIR/rf-scanner-unit-test.json" <<EOF
{
  "phase": "E1",
  "check": "rf_scanner_disabled_state_unit_test",
  "status": "$RESULT",
  "test_kind": "unit",
  "timestamp": "$TIMESTAMP",
  "source_commit": "$COMMIT",
  "source_tree_state": "$TREE_STATE",
  "dirty_path_count": $DIRTY_COUNT,
  "command": "bash tests/e1/rf-scanner-test.sh",
  "observations_collected": false,
  "sensor_hardware_test": "NOT_RUN",
  "covered_behaviors": [
    "unconfigured sources are disabled by policy",
    "disabled is distinct from zero observations",
    "no identifiers or signal measurements are serialized",
    "truncated JSON is reported",
    "active scan invocation is absent"
  ],
  "source_sha256": {
    "agent/environment/rf_scanner.c": "$SCANNER_SHA256",
    "agent/include/rf_scanner.h": "$HEADER_SHA256",
    "agent/main.c": "$MAIN_SHA256",
    "tests/e1/rf_scanner_test.c": "$TEST_SHA256",
    "tests/e1/rf-scanner-test.sh": "$RUNNER_SHA256"
  }
}
EOF

[ "$RESULT" = "PASS" ] || exit 1
