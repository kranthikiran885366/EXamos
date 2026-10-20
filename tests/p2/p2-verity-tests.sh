#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — dm-verity Image Integrity Tests (Layer 5)
# Mandatory: P2-06
#
# Requires artifacts from a completed dm-verity-setup.sh run:
#   SQUASHFS_CLEAN     — path to the clean generated SquashFS
#   VERITY_HASH_FILE   — path to the verity hash tree file
#   VERITY_ROOT_HASH   — the root hash string (from phase2-manifest.json)
#   ARTIFACT_DIR       — output directory
# =============================================================================
set -uo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts/phase2}"
SQUASHFS_CLEAN="${SQUASHFS_CLEAN:-${ARTIFACT_DIR}/examos-root.squashfs}"
VERITY_HASH_FILE="${VERITY_HASH_FILE:-${ARTIFACT_DIR}/examos-root.verity}"
VERITY_ROOT_HASH="${VERITY_ROOT_HASH:-}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/dm-verity-tests.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "[VERITY-PASS]    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "[VERITY-FAIL]    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[VERITY-BLOCKED] ${id}: ${detail}" ;;
    esac
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-VERITY] dm-verity Tests: $(ts) ==="

# Try to read root hash from manifest if not provided
if [ -z "$VERITY_ROOT_HASH" ]; then
    MANIFEST="${ARTIFACT_DIR}/phase2-manifest.json"
    if [ -f "$MANIFEST" ]; then
        VERITY_ROOT_HASH=$(python3 -c "
import json,sys
d=json.load(open('$MANIFEST'))
print(d.get('verityRootHash',''))
" 2>/dev/null || true)
    fi
fi

# Check prerequisites
if ! command -v veritysetup >/dev/null 2>&1; then
    record "P2-06" "BLOCKED" "BLOCKED_ENVIRONMENT: veritysetup not available (install cryptsetup-bin)"
    echo '{"timestamp":"'$(ts)'","pass":0,"fail":0,"blocked":1,"overall":"BLOCKED"}' > "$ARTIFACT_DIR/dm-verity-test-results.json"
    exit 0
fi
if [ ! -f "$SQUASHFS_CLEAN" ]; then
    record "P2-06" "BLOCKED" "BLOCKED_ENVIRONMENT: clean SquashFS not found at ${SQUASHFS_CLEAN}"
    echo '{"timestamp":"'$(ts)'","pass":0,"fail":0,"blocked":1,"overall":"BLOCKED"}' > "$ARTIFACT_DIR/dm-verity-test-results.json"
    exit 0
fi
if [ ! -f "$VERITY_HASH_FILE" ]; then
    record "P2-06" "BLOCKED" "BLOCKED_ENVIRONMENT: verity hash file not found at ${VERITY_HASH_FILE}"
    echo '{"timestamp":"'$(ts)'","pass":0,"fail":0,"blocked":1,"overall":"BLOCKED"}' > "$ARTIFACT_DIR/dm-verity-test-results.json"
    exit 0
fi
if [ -z "$VERITY_ROOT_HASH" ]; then
    record "P2-06" "BLOCKED" "BLOCKED_ENVIRONMENT: VERITY_ROOT_HASH not set and not in manifest"
    echo '{"timestamp":"'$(ts)'","pass":0,"fail":0,"blocked":1,"overall":"BLOCKED"}' > "$ARTIFACT_DIR/dm-verity-test-results.json"
    exit 0
fi

# Run the full corruption test script which handles all evidence recording
SQUASHFS_CLEAN="$SQUASHFS_CLEAN" \
VERITY_HASH_FILE="$VERITY_HASH_FILE" \
VERITY_ROOT_HASH="$VERITY_ROOT_HASH" \
ARTIFACT_DIR="$ARTIFACT_DIR" \
bash "$(dirname "$0")/../../image/scripts/dm-verity-corruption-test.sh"
VERITY_TEST_RC=$?

if [ "$VERITY_TEST_RC" -eq 0 ]; then
    record "P2-06" "PASS" "dm-verity: clean verified + corruption rejected (see ${ARTIFACT_DIR}/dm-verity-*.txt)"
else
    record "P2-06" "FAIL" "dm-verity test failed (rc=${VERITY_TEST_RC})"
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","pass":%d,"fail":%d,"blocked":%d,"overall":"%s"}\n' \
        "$(ts)" "$PASS" "$FAIL" "$BLOCKED" "$(overall_status)"
} > "$ARTIFACT_DIR/dm-verity-test-results.json"

echo ""
echo "=== [P2-VERITY] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
[ "$FAIL" -eq 0 ]
