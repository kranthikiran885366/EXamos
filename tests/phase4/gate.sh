#!/usr/bin/env bash
# =============================================================================
# ExamOS Phase 4 — Master Acceptance Gate
# tests/phase4/gate.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
if [ -z "${EXAMOS_P4_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$WORKSPACE/artifacts/phase4/runs"
    ARTIFACT_DIR="$(mktemp -d "$WORKSPACE/artifacts/phase4/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
export EXAMOS_P4_ARTIFACT_DIR="$ARTIFACT_DIR"
BUILD_ROOT="$(mktemp -d /tmp/examos-p4-native-build.XXXXXX)"
SERVER_PORT=9099
SERVER_BIN="$BUILD_ROOT/server/examos-server"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
GATE_SERVER_PID=""

mkdir -p "$ARTIFACT_DIR"
export EXAMOS_PROCTOR_API_TOKEN="${EXAMOS_PROCTOR_API_TOKEN:-$(openssl rand -hex 32)}"
export EXAMOS_EVENT_SIGNING_KEY="${EXAMOS_EVENT_SIGNING_KEY:-$(openssl rand -hex 32)}"

cleanup() {
    if [ -n "$GATE_SERVER_PID" ]; then
        kill -TERM "$GATE_SERVER_PID" 2>/dev/null || true
        wait "$GATE_SERVER_PID" 2>/dev/null || true
    fi
    case "$BUILD_ROOT" in
        /tmp/examos-p4-native-build.*)
            [ -d "$BUILD_ROOT" ] && [ ! -L "$BUILD_ROOT" ] && rm -rf -- "$BUILD_ROOT" ;;
        *) echo "Refusing to remove unexpected native build path: $BUILD_ROOT" >&2 ;;
    esac
}
trap cleanup EXIT

echo "============================================================"
echo "ExamOS Phase 4 — Acceptance Gate"
echo "============================================================"
echo "[GATE] Building Phase 4 native subsystems into isolated run artifacts..."
make -C "$WORKSPACE/server" BUILD_DIR="$BUILD_ROOT/server" all
make -C "$WORKSPACE/proctoring" BUILD_DIR="$BUILD_ROOT/proctoring" all
EXAMOS_P4_VERIFIER="$ARTIFACT_DIR/exam-event-verify" \
    gcc -Wall -Wextra -O2 "$WORKSPACE/tools/exam-event-verify.c" \
    -o "$ARTIFACT_DIR/exam-event-verify" -lssl -lcrypto

EXAMOS_SERVER_PORT=${SERVER_PORT} \
EXAMOS_LEDGER_PATH="${ARTIFACT_DIR}/p4-event-ledger.log" \
    "$SERVER_BIN" &
GATE_SERVER_PID=$!

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
EXAMOS_P4_VERIFIER="$ARTIFACT_DIR/exam-event-verify" \
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
