#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 — 50-Session Concurrency Load Test (Gate P4.3)
#
# Tests that the event ingestion system can sustain 50 concurrent sessions
# with 10 events per session (500 total) with ZERO dropped events.
#
# Uses real HTTP connections to the live examos-server.
# Sequence gaps are detected by the verifier after the test.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/concurrency-results.json"
# PG-42: Support production mode testing (EXAMOS_TEST_MODE=production uses
# EXAMOS_ALLOW_UNPROVISIONED_DEV=0 + EXAMOS_TPM_MODE=production instead of dev mode)
EXAMOS_TEST_MODE="${EXAMOS_TEST_MODE:-dev}"
SERVER_PORT="${EXAMOS_P4_SERVER_PORT:-9101}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
VERIFIER="${EXAMOS_P4_VERIFIER:-$WORKSPACE/tools/exam-event-verify}"
RUN_DIR="$(mktemp -d /tmp/examos-p4-concurrency.XXXXXX)"
EVENT_LOG="${EXAMOS_P4_EVENT_LOG:-$RUN_DIR/events.log}"
TARGET_SESSIONS=50
EVENTS_PER_SESSION=10
PROCTOR_TOKEN=""

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

echo "=== [P4-CONCURRENCY] 50-Session Load Test ==="
echo "  Server: $SERVER_URL"
echo "  Target: $TARGET_SESSIONS sessions × $EVENTS_PER_SESSION events = $((TARGET_SESSIONS * EVENTS_PER_SESSION)) events"
echo ""

# -----------------------------------------------------------------------
# Start server
# -----------------------------------------------------------------------
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_PID=""
if [ -x "$SERVER_BIN" ]; then
    PROCTOR_TOKEN="$(openssl rand -hex 32)"
    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="$RUN_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_CHAIN_PATH="$EVENT_LOG" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_TPM_MODE="${EXAMOS_TPM_MODE:-development}" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV="${EXAMOS_ALLOW_UNPROVISIONED_DEV:-1}" \
    EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
    EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    EXAMOS_SESSION_JOURNAL="$RUN_DIR/sessions.log" \
    EXAMOS_BEHAVIOUR_STORE="$RUN_DIR/behaviour-store" \
    EXAMOS_VIVA_STORE="$RUN_DIR/viva-store" \
    EXAMOS_VARIANT_STORE="$RUN_DIR/variant-store" \
    EXAMOS_DATA_DIR="$RUN_DIR/data" \
        "$SERVER_BIN" &
    SERVER_PID=$!
    for i in $(seq 1 15); do
        curl -sf "${SERVER_URL}/api/v1/health" >/dev/null 2>&1 && break
        sleep 0.5
    done
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$RUN_DIR"
    rm -f /tmp/examos-p4-conc-*.log
}
trap cleanup EXIT

if [ -z "$PROCTOR_TOKEN" ] || [ ${#PROCTOR_TOKEN} -lt 32 ]; then
    echo "  BLOCKED: Cannot start server or get proctor token" >&2
    echo "{\"phase\":\"P4\",\"test\":\"concurrency\",\"status\":\"BLOCKED\",\"reason\":\"server_unavailable\"}" > "$LOG"
    exit 2
fi

# -----------------------------------------------------------------------
# Fire 50 concurrent sessions using background curl processes
# Each session sends 10 sequential events
# -----------------------------------------------------------------------
echo "  Launching $TARGET_SESSIONS concurrent session workers..."
START_TIME=$(date +%s%N)

send_session_events() {
    local session_num=$1
    local session_id="load-test-session-$(printf '%03d' $session_num)"
    for seq in $(seq 1 $EVENTS_PER_SESSION); do
        local event_type
        case $((seq % 3)) in
            0) event_type="FACE_PRESENT" ;;
            1) event_type="HEAD_POSE" ;;
            2) event_type="NO_FACE" ;;
        esac
        curl -s -o /dev/null -w "%{http_code}" \
            -X POST "${SERVER_URL}/api/v1/proctoring/events" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${PROCTOR_TOKEN}" \
            -d "{\"session_id\":\"${session_id}\",\"source_type\":\"PRIMARY_CAMERA\",\"event_type\":\"${event_type}\",\"model_name\":\"p4-load-fixture\",\"model_version\":\"1.0.0\",\"payload\":{\"frameSeq\":${seq},\"session_num\":${session_num}}}" \
            --max-time 5 2>/dev/null
        echo ""
    done
}
export -f send_session_events
export SERVER_URL PROCTOR_TOKEN EVENTS_PER_SESSION

# Launch all sessions in parallel using xargs
PIDS=""
for i in $(seq 1 $TARGET_SESSIONS); do
    send_session_events $i > /tmp/examos-p4-conc-$i.log 2>&1 &
    PIDS="$PIDS $!"
done

# Wait for all workers
FAILURES=0
for pid in $PIDS; do
    wait "$pid" || FAILURES=$((FAILURES + 1))
done

END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

# -----------------------------------------------------------------------
# Verify: count events and detect sequence gaps
# -----------------------------------------------------------------------
echo "  Verifying event counts and sequence integrity..."

TOTAL_EXPECTED=$((TARGET_SESSIONS * EVENTS_PER_SESSION))

# Count events in the log
TOTAL_EVENTS=0
if [ -f "$EVENT_LOG" ]; then
    TOTAL_EVENTS=$(grep -c '"session_id":"load-test-session-' "$EVENT_LOG" 2>/dev/null || true)
    TOTAL_EVENTS=${TOTAL_EVENTS:-0}
fi

DROPPED_EVENTS=$((TOTAL_EXPECTED - TOTAL_EVENTS))

# PG-27: Use exact JSON field matching (Python parser) instead of substring
# grep to avoid false positives when one session_id is a prefix of another.
GAPS_FOUND=0
SESSIONS_WITH_GAPS=0
for i in $(seq 1 $TARGET_SESSIONS); do
    SID="load-test-session-$(printf '%03d' $i)"
    SESSION_EVENTS=$(python3 -c "
import json, sys
count = 0
with open('$EVENT_LOG') as f:
    for line in f:
        try:
            ev = json.loads(line)
            if ev.get('session_id') == '$SID':
                count += 1
        except Exception:
            pass
print(count)
" 2>/dev/null || echo 0)
    SESSION_EVENTS=${SESSION_EVENTS:-0}
    if [ "$SESSION_EVENTS" -ne "$EVENTS_PER_SESSION" ]; then
        SESSIONS_WITH_GAPS=$((SESSIONS_WITH_GAPS + 1))
        GAPS_FOUND=$((GAPS_FOUND + (EVENTS_PER_SESSION - SESSION_EVENTS)))
    fi
done

# Verify every session's hash chain with the independent verifier.
CHAIN_FAILURES=0
if [ -x "$VERIFIER" ] && [ -f "$EVENT_LOG" ]; then
    for i in $(seq 1 $TARGET_SESSIONS); do
        SID="load-test-session-$(printf '%03d' $i)"
        if ! "$VERIFIER" --session "$SID" --store "$EVENT_LOG" 2>&1 | grep -q "CHAIN: VALID"; then
            CHAIN_FAILURES=$((CHAIN_FAILURES + 1))
        fi
    done
else
    CHAIN_FAILURES=$TARGET_SESSIONS
fi

THROUGHPUT=$(echo "scale=2; $TOTAL_EVENTS / ($DURATION_MS / 1000)" | bc 2>/dev/null || echo "N/A")

# Determine status
if [ "$DROPPED_EVENTS" -eq 0 ] && [ "$GAPS_FOUND" -eq 0 ] && [ "$CHAIN_FAILURES" -eq 0 ]; then
    STATUS="PASS"
    OVERALL="PASS"
elif [ "$DROPPED_EVENTS" -eq 0 ] && [ "$CHAIN_FAILURES" -eq 0 ]; then
    STATUS="WARN"
    OVERALL="PASS"
else
    STATUS="FAIL"
    OVERALL="FAIL"
fi

echo ""
echo "  Total events expected: $TOTAL_EXPECTED"
echo "  Total events ingested: $TOTAL_EVENTS"
echo "  Dropped events:        $DROPPED_EVENTS"
echo "  Sequence gaps:         $GAPS_FOUND"
echo "  Sessions with gaps:    $SESSIONS_WITH_GAPS"
echo "  Chain verifier failures: $CHAIN_FAILURES"
echo "  Duration:              ${DURATION_MS}ms"
echo "  Throughput:            $THROUGHPUT events/sec"
echo "  Status:                $STATUS"

# Write JSON
cat > "$LOG" <<EOF
{
  "phase": "P4",
  "test": "concurrency",
  "target_sessions": $TARGET_SESSIONS,
  "events_per_session": $EVENTS_PER_SESSION,
  "total_events_expected": $TOTAL_EXPECTED,
  "total_events_ingested": $TOTAL_EVENTS,
  "total_events_dropped": $DROPPED_EVENTS,
  "sequence_gaps_found": $GAPS_FOUND,
  "sessions_with_gaps": $SESSIONS_WITH_GAPS,
  "chain_verifier_failures": $CHAIN_FAILURES,
  "duration_ms": $DURATION_MS,
  "throughput_events_per_second": "$THROUGHPUT",
  "status": "$STATUS",
  "overall": "$OVERALL",
  "timestamp": "$(ts)"
}
EOF

# Also write CSV
cat > "$ARTIFACT_DIR/concurrency-results.csv" <<EOF
metric,value
target_sessions,$TARGET_SESSIONS
events_per_session,$EVENTS_PER_SESSION
total_expected,$TOTAL_EXPECTED
total_ingested,$TOTAL_EVENTS
dropped,$DROPPED_EVENTS
sequence_gaps,$GAPS_FOUND
sessions_with_gaps,$SESSIONS_WITH_GAPS
chain_verifier_failures,$CHAIN_FAILURES
duration_ms,$DURATION_MS
throughput_eps,$THROUGHPUT
status,$STATUS
EOF

echo ""
echo "=== [P4-CONCURRENCY] $OVERALL ==="

[ "$OVERALL" = "PASS" ]
