#!/usr/bin/env bash
# =============================================================================
# ExamOS Phase 4 — Master Acceptance Gate
# tests/phase4/gate.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="$WORKSPACE/artifacts/phase4"
SERVER_PORT=9099
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"

mkdir -p "$ARTIFACT_DIR"
export EXAMOS_PROCTOR_API_TOKEN="${EXAMOS_PROCTOR_API_TOKEN:-$(openssl rand -hex 32)}"
export EXAMOS_EVENT_SIGNING_KEY="${EXAMOS_EVENT_SIGNING_KEY:-$(openssl rand -hex 32)}"

cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    fuser -k -n tcp "$SERVER_PORT" 2>/dev/null || true
    pkill -9 -f "examos-server" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

echo "============================================================"
echo "ExamOS Phase 4 — Acceptance Gate"
echo "============================================================"
echo "[GATE] Building all Phase 4 native subsystems..."
(cd "$WORKSPACE/server" && make clean && make)
(cd "$WORKSPACE/proctoring" && make clean && make)
gcc -Wall -Wextra -O2 "$WORKSPACE/tools/exam-event-verify.c" -o "$WORKSPACE/tools/exam-event-verify" -lssl -lcrypto

cleanup
EXAMOS_SERVER_PORT=${SERVER_PORT} \
EXAMOS_LEDGER_PATH="${ARTIFACT_DIR}/p4-event-ledger.log" \
    "$SERVER_BIN" &
SERVER_PID=$!

echo "[GATE] Waiting for server on port $SERVER_PORT..."
TRIES=0
while [ $TRIES -lt 30 ]; do
    if curl -s "${SERVER_URL}/api/v1/health" | grep -q '"status":"ok"'; then
        break
    fi
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ $TRIES -ge 30 ]; then
    echo "[GATE] FATAL: Server failed to start on port $SERVER_PORT"
    exit 1
fi

echo "[GATE] Server ready. Running Phase 4 test suites..."

# 1. Tamper tests
echo ""
echo "--- Running Tamper Detection Test Matrix ---"
TAMPER_STATUS=FAIL
bash "$WORKSPACE/tests/phase4/tamper-tests.sh" && TAMPER_STATUS=PASS

# 2. 50-clip detection evaluation
echo ""
echo "--- Running 50-Clip Labelled Detection Evaluation ---"
DETECTION_STATUS=FAIL
bash "$WORKSPACE/tests/phase4/detection-eval.sh" && DETECTION_STATUS=PASS

# 3. 50-session concurrency test
echo ""
echo "--- Running 50-Session Concurrency Load Test ---"
CONCURRENCY_STATUS=FAIL
bash "$WORKSPACE/tests/phase4/concurrency-test.sh" && CONCURRENCY_STATUS=PASS

REGRESSION_STATUS=FAIL
if bash "$WORKSPACE/tests/p3/gate.sh"; then REGRESSION_STATUS=PASS; fi

OVERALL_STATUS=FAIL
if [ "$TAMPER_STATUS" = PASS ] && [ "$DETECTION_STATUS" = PASS ] && \
   [ "$CONCURRENCY_STATUS" = PASS ] && [ "$REGRESSION_STATUS" = PASS ]; then
    OVERALL_STATUS=PASS
fi

# 4. Generate manifest
cat > "$ARTIFACT_DIR/phase4-manifest.json" <<JSONEOF
{
  "phase": "P4",
  "version": "0.5.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "components": {
    "examos_server": "native-c",
    "examos_proctor": "native-cpp-vision",
    "event_verifier": "native-c-cli",
    "tamper_evidence": "sha256-hash-chain",
    "second_camera": "qr-token-pairing"
  },
  "gate_results": {
    "tamper_matrix": "$TAMPER_STATUS",
    "detection_quality": "$DETECTION_STATUS",
    "concurrency_50_sessions": "$CONCURRENCY_STATUS",
    "regression_p0_p3": "$REGRESSION_STATUS"
  },
  "overall_gate": "$OVERALL_STATUS"
}
JSONEOF

echo ""
echo "============================================================"
echo "ExamOS Phase 4 Gate: $OVERALL_STATUS"
echo "============================================================"
[ "$OVERALL_STATUS" = PASS ]
