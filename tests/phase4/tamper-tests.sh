#!/usr/bin/env bash
# =============================================================================
# ExamOS Phase 4 — Tamper Evidence Test Suite
# tests/phase4/tamper-tests.sh
#
# Validates T1-T8 tamper detection rules using the standalone CLI verifier:
# tools/exam-event-verify
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="$WORKSPACE/artifacts/phase4"
VERIFIER_BIN="$WORKSPACE/tools/exam-event-verify"
TMP_STORE=$(mktemp)

mkdir -p "$ARTIFACT_DIR"

trap 'rm -f "$TMP_STORE"' EXIT

echo "[TAMPER-TEST] Building CLI event verifier..."
gcc -Wall -Wextra -O2 "$WORKSPACE/tools/exam-event-verify.c" -o "$VERIFIER_BIN" -lssl -lcrypto

echo "[TAMPER-TEST] Generating synthetic baseline hash-chained event stream..."
# Build 5 valid chained events for session 'tamper-sess-01'
GENESIS="0000000000000000000000000000000000000000000000000000000000000000"

PREV_HASH="$GENESIS"
for SEQ in 1 2 3 4 5; do
    TS="2026-10-08T22:30:0${SEQ}.000Z"
    EVENT_TYPE="FACE_PRESENT"
    PAYLOAD='{"faceCount":1,"confidence":0.95}'
    MODEL="native-vision"
    VERSION="1.0.0"

    CANONICAL=$(printf '{"event_type":"%s","model_name":"%s","model_version":"%s","payload":%s,"previous_hash":"%s","sequence":%d,"server_timestamp":"%s","session_id":"tamper-sess-01","source_timestamp":"%s","source_type":"PRIMARY_CAMERA"}' \
        "$EVENT_TYPE" "$MODEL" "$VERSION" "$PAYLOAD" "$PREV_HASH" "$SEQ" "$TS" "$TS")

    HASH_INPUT="${PREV_HASH}${CANONICAL}"
    EVENT_HASH=$(printf '%s' "$HASH_INPUT" | sha256sum | cut -d' ' -f1)

    printf '{"session_id":"tamper-sess-01","sequence":%d,"server_timestamp":"%s","source_timestamp":"%s","source_type":"PRIMARY_CAMERA","event_type":"%s","payload":%s,"model_name":"%s","model_version":"%s","previous_hash":"%s","event_hash":"%s"}\n' \
        "$SEQ" "$TS" "$TS" "$EVENT_TYPE" "$PAYLOAD" "$MODEL" "$VERSION" "$PREV_HASH" "$EVENT_HASH" >> "$TMP_STORE"

    PREV_HASH="$EVENT_HASH"
done

PASS_COUNT=0
FAIL_COUNT=0

record_t() {
    local tid="$1" name="$2" expected="$3" actual="$4"
    if [ "$expected" = "$actual" ]; then
        echo "[TAMPER-TEST] $tid ($name): PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[TAMPER-TEST] $tid ($name): FAIL (expected $expected, got $actual)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# --- T0: Clean Baseline Chain ---
echo "[T0] Verifying clean unmodified baseline..."
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_STORE" 2>&1 || true)
if echo "$OUT" | grep -q "RESULT: PASS"; then
    record_t "T0" "clean_baseline" "PASS" "PASS"
else
    record_t "T0" "clean_baseline" "PASS" "FAIL"
fi

# --- T1: Payload Modification ---
echo "[T1] Testing payload tampering detection..."
TMP_T1=$(mktemp)
sed 's/"faceCount":1/"faceCount":3/' "$TMP_STORE" > "$TMP_T1"
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_T1" 2>&1 || true)
rm -f "$TMP_T1"
if echo "$OUT" | grep -q "RESULT: FAIL" && echo "$OUT" | grep -q "EVENT_HASH_MISMATCH"; then
    record_t "T1" "payload_tamper_detected" "PASS" "PASS"
else
    record_t "T1" "payload_tamper_detected" "PASS" "FAIL"
fi

# --- T2: Previous Hash Modification ---
echo "[T2] Testing previousHash tampering detection..."
TMP_T2=$(mktemp)
sed 's/0000000000000000000000000000000000000000000000000000000000000000/1111111111111111111111111111111111111111111111111111111111111111/' "$TMP_STORE" > "$TMP_T2"
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_T2" 2>&1 || true)
rm -f "$TMP_T2"
if echo "$OUT" | grep -q "RESULT: FAIL" && echo "$OUT" | grep -q "PREVIOUS_HASH_MISMATCH"; then
    record_t "T2" "prev_hash_tamper_detected" "PASS" "PASS"
else
    record_t "T2" "prev_hash_tamper_detected" "PASS" "FAIL"
fi

# --- T3: Event Deletion (Gap) ---
echo "[T3] Testing event deletion detection..."
TMP_T3=$(mktemp)
sed '2d' "$TMP_STORE" > "$TMP_T3"
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_T3" 2>&1 || true)
rm -f "$TMP_T3"
if echo "$OUT" | grep -q "RESULT: FAIL" && echo "$OUT" | grep -q "SEQUENCE_GAP_OR_REORDER"; then
    record_t "T3" "deletion_detected" "PASS" "PASS"
else
    record_t "T3" "deletion_detected" "PASS" "FAIL"
fi

# --- T4: Event Reordering ---
echo "[T4] Testing event reordering detection..."
TMP_T4=$(mktemp)
awk 'NR==2{line2=$0; next} NR==3{print; print line2; next} {print}' "$TMP_STORE" > "$TMP_T4"
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_T4" 2>&1 || true)
rm -f "$TMP_T4"
if echo "$OUT" | grep -q "RESULT: FAIL"; then
    record_t "T4" "reorder_detected" "PASS" "PASS"
else
    record_t "T4" "reorder_detected" "PASS" "FAIL"
fi

# --- T5: Sequence Manipulation ---
echo "[T5] Testing sequence number manipulation..."
TMP_T5=$(mktemp)
sed 's/"sequence":2/"sequence":99/' "$TMP_STORE" > "$TMP_T5"
OUT=$("$VERIFIER_BIN" --session "tamper-sess-01" --store "$TMP_T5" 2>&1 || true)
rm -f "$TMP_T5"
if echo "$OUT" | grep -q "RESULT: FAIL" && echo "$OUT" | grep -q "SEQUENCE_GAP_OR_REORDER"; then
    record_t "T5" "sequence_tamper_detected" "PASS" "PASS"
else
    record_t "T5" "sequence_tamper_detected" "PASS" "FAIL"
fi

# Write results
cat > "$ARTIFACT_DIR/tamper-test-results.json" <<JSONEOF
{
  "phase": "P4",
  "test_suite": "tamper_matrix",
  "total_tests": 6,
  "passed": $PASS_COUNT,
  "failed": $FAIL_COUNT,
  "status": "$([ $FAIL_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')"
}
JSONEOF

echo ""
echo "[TAMPER-TEST] Completed with $PASS_COUNT PASS, $FAIL_COUNT FAIL"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "[TAMPER-TEST] ALL TAMPER TESTS PASSED"
    exit 0
else
    exit 1
fi
