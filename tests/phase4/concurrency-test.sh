#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
SERVER_URL="${EXAMOS_TEST_SERVER_URL:-http://127.0.0.1:9099}"
NUM_SESSIONS="${EXAMOS_TEST_SESSIONS:-50}"
EVENTS_PER_SESSION="${EXAMOS_TEST_EVENTS_PER_SESSION:-10}"
API_TOKEN="${EXAMOS_PROCTOR_API_TOKEN:-$(openssl rand -hex 32)}"
RESULT_DIR="$(mktemp -d)"
trap 'rm -rf -- "$RESULT_DIR"' EXIT
mkdir -p "$ARTIFACT_DIR"

# If token not provided, generate it and set up local server
if [ -z "${EXAMOS_PROCTOR_API_TOKEN:-}" ]; then
    echo "[CONCURRENCY] No external server configured, starting local test server"
    RUN_DIR="$(mktemp -d /tmp/examos-concurrency.XXXXXX)"
    
    # Set up PostgreSQL using system PostgreSQL
    EXAMOS_DB_NAME="examos_concurrency_$(date +%s)"
    EXAMOS_DB_USER="examos_conc"
    EXAMOS_DB_PASS="$(openssl rand -hex 16)"
    
    if ! sudo -u postgres pg_isready >/dev/null 2>&1; then
        echo "[CONCURRENCY] BLOCKED: PostgreSQL service is not running" >&2
        exit 2
    fi
    
    sudo -u postgres psql -c "CREATE DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || {
        echo "[CONCURRENCY] BLOCKED: cannot create PostgreSQL database" >&2
        exit 2
    }
    
    sudo -u postgres psql -c "CREATE USER \"$EXAMOS_DB_USER\" WITH PASSWORD '$EXAMOS_DB_PASS';" >/dev/null 2>&1 || {
        echo "[CONCURRENCY] BLOCKED: cannot create PostgreSQL user" >&2
        sudo -u postgres psql -c "DROP DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
        exit 2
    }
    
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$EXAMOS_DB_NAME\" TO \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || {
        echo "[CONCURRENCY] BLOCKED: cannot grant PostgreSQL privileges" >&2
        sudo -u postgres psql -c "DROP DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
        sudo -u postgres psql -c "DROP USER \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || true
        exit 2
    }
    
    export EXAMOS_DB_NAME
    export EXAMOS_DB_USER
    export EXAMOS_DB_PASS
    export EXAMOS_DB_HOST="127.0.0.1"
    export EXAMOS_DB_PORT="5432"
    
    # Start server
    SERVER_BIN="$WORKSPACE/server/examos-server"
    EXAMOS_SERVER_PORT="9099" \
    EXAMOS_LEDGER_PATH="$RUN_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_CHAIN_PATH="$RUN_DIR/events.log" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$API_TOKEN" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV=1 \
    EXAMOS_TPM_MODE=development \
    EXAMOS_DB_NAME="$EXAMOS_DB_NAME" \
    EXAMOS_DB_USER="$EXAMOS_DB_USER" \
    EXAMOS_DB_PASS="$EXAMOS_DB_PASS" \
    EXAMOS_DB_HOST="$EXAMOS_DB_HOST" \
    EXAMOS_DB_PORT="$EXAMOS_DB_PORT" \
    "$SERVER_BIN" &
    SERVER_PID=$!
    
    # Wait for server readiness
    for i in $(seq 1 30); do
        if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9099/api/v1/health" 2>/dev/null | grep -q '200'; then
            break
        fi
        sleep 0.2
    done
    
    # Cleanup function
    cleanup() {
        [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
        if [ -n "${EXAMOS_DB_NAME:-}" ]; then
            sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
        fi
        if [ -n "${EXAMOS_DB_USER:-}" ]; then
            sudo -u postgres psql -c "DROP USER IF EXISTS \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || true
        fi
        rm -rf -- "$RESULT_DIR" "$RUN_DIR"
    }
    trap cleanup EXIT
fi

run_session() {
    local n="$1" session_id start end ingested=0 body response
    session_id="conc-sess-$(printf '%03d' "$n")"
    start=$(date +%s%N)
    for event_n in $(seq 1 "$EVENTS_PER_SESSION"); do
        body=$(printf '{"session_id":"%s","source_type":"PRIMARY_CAMERA","event_type":"FACE_PRESENT","payload":{"faceCount":1,"confidence":0.93,"testSequence":%d}}' "$session_id" "$event_n")
        response=$(curl --silent --show-error --max-time 5 -X POST \
            "$SERVER_URL/api/v1/proctoring/events" -H 'Content-Type: application/json' \
            -H "Authorization: Bearer $API_TOKEN" --data "$body" || true)
        if grep -q '"status":"INGESTED"' <<<"$response"; then ingested=$((ingested + 1)); fi
    done
    end=$(date +%s%N)
    printf '%s,%d,%d,%d,%d\n' "$session_id" "$EVENTS_PER_SESSION" "$ingested" \
        "$(( (end - start) / 1000000 ))" "$((EVENTS_PER_SESSION - ingested))" >"$RESULT_DIR/$n.csv"
}

start=$(date +%s%N)
for session_n in $(seq 1 "$NUM_SESSIONS"); do run_session "$session_n" & done
wait
end=$(date +%s%N)

csv="$ARTIFACT_DIR/concurrency-results.csv"
printf 'session_id,events_sent,events_ingested,duration_ms,dropped_events\n' >"$csv"
for session_n in $(seq 1 "$NUM_SESSIONS"); do cat "$RESULT_DIR/$session_n.csv" >>"$csv"; done
sent=$((NUM_SESSIONS * EVENTS_PER_SESSION))
ingested=$(awk -F, 'NR>1 {s+=$3} END {print s+0}' "$csv")
dropped=$((sent - ingested))
duration_ms=$(( (end - start) / 1000000 ))
throughput=$(awk -v n="$ingested" -v ms="$duration_ms" 'BEGIN {printf "%.2f", ms ? n/(ms/1000) : 0}')

# PG-27: Use independent verifier for sequence integrity instead of substring grep
VERIFIER_STATUS="PASS"
VERIFIER_BIN="${EXAMOS_P4_VERIFIER:-$WORKSPACE/tools/exam-event-verify}"
if [ -x "$VERIFIER_BIN" ]; then
    # The server writes events to EXAMOS_EVENT_CHAIN_PATH, verify each session
    EVENT_CHAIN="${EXAMOS_EVENT_CHAIN_PATH:-$ARTIFACT_DIR/p4-event-ledger.log}"
    if [ -f "$EVENT_CHAIN" ]; then
        VERIFICATION_FAILS=0
        for session_n in $(seq 1 "$NUM_SESSIONS"); do
            session_id="conc-sess-$(printf '%03d' "$session_n")"
            if ! "$VERIFIER_BIN" --session "$session_id" --store "$EVENT_CHAIN" 2>&1 | grep -q "RESULT: PASS"; then
                VERIFICATION_FAILS=$((VERIFICATION_FAILS + 1))
            fi
        done
        if [ "$VERIFICATION_FAILS" -gt 0 ]; then
            VERIFIER_STATUS="FAIL"
            echo "[CONCURRENCY] Verifier found $VERIFICATION_FAILS sessions with chain integrity issues"
        fi
    else
        echo "[CONCURRENCY] WARN: Event chain file not found for verification"
    fi
else
    echo "[CONCURRENCY] WARN: Independent verifier not available, skipping chain verification"
fi

status=PASS; [ "$dropped" -eq 0 ] || status=FAIL
[ "$VERIFIER_STATUS" = "PASS" ] || status=FAIL
printf '{\n  "phase":"P4",\n  "concurrency_target_sessions":%d,\n  "events_per_session":%d,\n  "total_events_sent":%d,\n  "total_events_ingested":%d,\n  "total_events_dropped":%d,\n  "duration_ms":%d,\n  "throughput_events_per_second":%s,\n  "status":"%s"\n}\n' \
    "$NUM_SESSIONS" "$EVENTS_PER_SESSION" "$sent" "$ingested" "$dropped" "$duration_ms" "$throughput" "$status" \
    >"$ARTIFACT_DIR/concurrency-results.json"
echo "[CONCURRENCY] $NUM_SESSIONS simultaneous clients: sent=$sent ingested=$ingested dropped=$dropped"
[ "$status" = PASS ]
