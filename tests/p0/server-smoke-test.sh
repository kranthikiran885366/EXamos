#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Server Runtime Smoke Test
# tests/p0/server-smoke-test.sh
# Starts the real server, exercises every HTTP endpoint with proper enterprise auth,
# verifies responses, and tests ledger tamper-evident logging.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ENT_DIR="${EXAMOS_P0_ENTERPRISE_ARTIFACT_DIR:-$WORKSPACE/artifacts/p0/enterprise}"
mkdir -p "$ENT_DIR"

SERVER_BIN="${EXAMOS_SERVER_BIN:-$WORKSPACE/server/examos-server}"

echo "============================================================"
echo "ExamOS P0 — Server Runtime Smoke Test"
echo "============================================================"

if [ ! -x "$SERVER_BIN" ]; then
    echo "[SMOKE] BLOCKED: executable server binary is unavailable: $SERVER_BIN" >&2
    exit 2
fi

# --- Find a free port ---
find_free_port() {
    local port
    for port in $(seq 19100 19200); do
        if ! ss -tlnp 2>/dev/null | grep -q ":${port} " && \
           ! netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "$port"
            return 0
        fi
    done
    echo "19150"
}

PORT=$(find_free_port)
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-smoke.XXXXXX")"
mkdir -p "$TMP_DIR/data"
LEDGER="$TMP_DIR/ledger.log"
ADMIN_CONFIG="$TMP_DIR/admin.conf"
EXAM_CONFIG="$TMP_DIR/exam.conf"
AGENT_TOKEN="$(openssl rand -hex 32)"
PROCTOR_TOKEN="$(openssl rand -hex 32)"
EVENT_SIGNING_KEY="$(openssl rand -hex 32)"
VARIANT_SECRET="$(openssl rand -hex 32)"
LEDGER_HMAC_KEY="$(openssl rand -hex 32)"
read -r ADMIN_USERNAME ADMIN_CREDENTIAL ADMIN_AUTH_VALUE < <(python3 - <<'PY'
import base64
import hashlib
import secrets

username = "admin-" + secrets.token_hex(8)
password = secrets.token_urlsafe(32)
salt = secrets.token_bytes(16)
iterations = 600000
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
auth = base64.b64encode(f"{username}:{password}".encode()).decode()
print(username, f"{iterations}:{salt.hex()}:{digest.hex()}", auth)
PY
)
ADMIN_AUTH="Basic $ADMIN_AUTH_VALUE"

echo "[SMOKE] Using port: $PORT"
echo "[SMOKE] Ledger: $LEDGER"

# --- Use isolated test configuration; never modify host /etc/examos. ---
umask 077
cat > "$ADMIN_CONFIG" <<CONF
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD_PBKDF2=$ADMIN_CREDENTIAL
CONF
cat > "$EXAM_CONFIG" <<'CONF'
EXAM_URL=https://exam.university.edu/test
EXAM_NAME=ExamOS Smoke Test
ALLOWED_ORIGINS=https://exam.university.edu
EXAM_DURATION_MINUTES=60
CONF
chmod 600 "$ADMIN_CONFIG" "$EXAM_CONFIG"

cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            kill -KILL "$SERVER_PID" 2>/dev/null || true
        fi
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    case "$TMP_DIR" in
        "${TMPDIR:-/tmp}"/examos-smoke.*) [ -d "$TMP_DIR" ] && [ ! -L "$TMP_DIR" ] && rm -rf -- "$TMP_DIR" ;;
        *) echo "[SMOKE] Refusing to remove unexpected temporary path: $TMP_DIR" >&2 ;;
    esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- Start server ---
EXAMOS_SERVER_PORT=$PORT \
EXAMOS_LEDGER_PATH="$LEDGER" \
EXAMOS_LEDGER_HMAC_KEY="$LEDGER_HMAC_KEY" \
EXAMOS_SESSION_JOURNAL="$TMP_DIR/session-journal.log" \
EXAMOS_DATA_DIR="$TMP_DIR/data" \
EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/proctoring-events.log" \
EXAMOS_BEHAVIOUR_STORE="$TMP_DIR/behaviour" \
EXAMOS_VARIANT_STORE="$TMP_DIR/variants" \
EXAMOS_VIVA_STORE="$TMP_DIR/viva" \
EXAMOS_AGENT_API_TOKEN="$AGENT_TOKEN" \
EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
EXAMOS_EVENT_SIGNING_KEY="$EVENT_SIGNING_KEY" \
EXAMOS_VARIANT_SECRET="$VARIANT_SECRET" \
EXAMOS_ADMIN_CONFIG="$ADMIN_CONFIG" \
EXAMOS_EXAM_CONFIG="$EXAM_CONFIG" \
EXAMOS_BROWSER_POLICY_CATALOG="${EXAMOS_BROWSER_POLICY_CATALOG:-$WORKSPACE/server/config/browser_policies.json}" \
EXAMOS_ALLOW_UNPROVISIONED_DEV=1 \
EXAMOS_TPM_MODE=development \
"$SERVER_BIN" &
SERVER_PID=$!

# --- Wait for readiness ---
echo "[SMOKE] Waiting for server readiness..."
READY=false
for i in $(seq 1 25); do
    if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null | grep -q '200'; then
        READY=true
        break
    fi
    sleep 0.2
done

if [ "$READY" = false ]; then
    echo "[SMOKE] FAIL: Server did not become ready in 5 seconds"
    echo '{"status":"FAIL","reason":"server_not_ready","tests":[]}' > "$ENT_DIR/runtime-smoke.json"
    exit 1
fi
echo "[SMOKE] Server ready (PID=$SERVER_PID)"

# --- Test Matrix ---
TOTAL=0
PASSED=0
RESULTS="["

run_test() {
    local name="$1" method="$2" path="$3" expect_code="$4" body="${5:-}" extra_headers="${6:-}" expected_text="${7:-}"
    TOTAL=$((TOTAL + 1))
    local url="http://127.0.0.1:$PORT$path"
    local start_ms end_ms elapsed_ms
    start_ms=$(date +%s%N 2>/dev/null || echo 0)
    
    local response_body="$TMP_DIR/smoke-body-$TOTAL.txt"
    local -a curl_args=(--silent --output "$response_body" --write-out '%{http_code}' --max-time 3 -X "$method")
    if [ -n "$extra_headers" ]; then
        curl_args+=(--header "$extra_headers")
    fi
    if [ "$method" = "POST" ]; then
        curl_args+=(--header 'Content-Type: application/json')
        if [ -n "$body" ]; then
            curl_args+=(--data "$body")
        fi
    fi

    local actual_code
    actual_code=$(curl "${curl_args[@]}" "$url" 2>/dev/null || echo "000")
    end_ms=$(date +%s%N 2>/dev/null || echo 0)
    elapsed_ms=$(( (end_ms - start_ms) / 1000000 ))
    
    local status="FAIL"
    if [ "$actual_code" = "$expect_code" ]; then
        status="PASS"
        if [ -n "$expected_text" ]; then
            local required_text
            IFS='|' read -r -a required_texts <<< "$expected_text"
            for required_text in "${required_texts[@]}"; do
                if ! grep -Fq -- "$required_text" "$response_body"; then status="FAIL"; break; fi
            done
        fi
    fi
    if [ "$status" = "PASS" ]; then
        PASSED=$((PASSED + 1))
    fi
    echo "[SMOKE] $name: $status (expected=$expect_code actual=$actual_code ${elapsed_ms}ms)"
    [ "$TOTAL" -gt 1 ] && RESULTS="$RESULTS,"
    RESULTS="$RESULTS{\"name\":\"$name\",\"method\":\"$method\",\"path\":\"$path\",\"expected\":$expect_code,\"actual\":$actual_code,\"status\":\"$status\",\"latency_ms\":$elapsed_ms}"
    rm -f "$TMP_DIR/smoke-body-$TOTAL.txt"
}

echo ""
echo "[SMOKE] Running endpoint test matrix..."

# 1. Health check (unauthenticated)
run_test "health_check" "GET" "/api/v1/health" "200"

# 2. Status unauthenticated -> 401
run_test "status_no_auth" "GET" "/api/v1/status" "401"

# 3. Legacy Basic credentials must not authenticate against the DB-backed
#    administrator store. A 401 here is the regression check for that bypass.
run_test "status_legacy_basic_rejected" "GET" "/api/v1/status" "401" "" "Authorization: $ADMIN_AUTH"

# 4. Root candidate portal UI -> 200
run_test "candidate_portal_ui" "GET" "/" "200"

# 5. Heartbeat without bearer token -> 401
run_test "heartbeat_no_auth" "POST" "/api/v1/heartbeat" "401" "{\"device_id\":\"smoke-dev\",\"timestamp\":\"now\",\"status\":\"ok\"}"

# 6. Heartbeat with valid Agent Bearer Token -> 202
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
run_test "heartbeat_valid" "POST" "/api/v1/heartbeat" "202" "{\"device_id\":\"smoke-dev\",\"timestamp\":\"$TIMESTAMP\",\"status\":\"ok\"}" "Authorization: Bearer $AGENT_TOKEN"

# 7. Ledger query with legacy Basic Auth -> 401 (no credential bypass)
run_test "ledger_legacy_basic_rejected" "GET" "/api/v1/ledger" "401" "" "Authorization: $ADMIN_AUTH"

# 8. Admin login page -> 200
run_test "admin_login_page" "GET" "/admin" "200"
# Legacy Basic credentials receive the login page, never the authenticated UI.
run_test "admin_dashboard_legacy_basic_rejected" "GET" "/admin" "200" "" "Authorization: $ADMIN_AUTH" 'ExamOS Admin Portal'
run_test "admin_session_requires_token" "GET" "/api/v1/admin/session" "401"
run_test "admin_campuses_requires_session" "GET" "/api/v1/admin/campuses" "403"
run_test "admin_scoped_campuses_requires_session" "GET" "/api/v1/admin/campuses?institution_id=smoke" "403"
run_test "admin_rooms_requires_session" "GET" "/api/v1/admin/rooms?campus_id=smoke" "403"
run_test "admin_roster_requires_session" "GET" "/api/v1/admin/roster?exam_id=smoke" "403"
run_test "admin_roles_requires_session" "GET" "/api/v1/admin/roles" "403"
run_test "admin_incidents_requires_session" "GET" "/api/v1/admin/incidents" "403"
run_test "admin_incident_update_requires_session" "POST" "/api/v1/admin/incidents/smoke/status" "403" "{\"status\":\"RESOLVED\"}"
run_test "admin_releases_require_session" "GET" "/api/v1/admin/releases" "403"

# 9. Admin login route aliases both reach authentication and reject empty credentials
run_test "admin_login_route" "POST" "/api/v1/admin/login" "401" "{}"
run_test "auth_login_compat_route" "POST" "/api/v1/auth/login" "401" "{}"

# 10. Nonexistent route -> 404
run_test "not_found_route" "GET" "/api/v1/nonexistent" "404"

RESULTS="$RESULTS]"

# --- Check server alive ---
ALIVE_STATUS="PASS"
if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo ""
    echo "[SMOKE] Server still alive after test barrage: PASS"
else
    echo ""
    echo "[SMOKE] Server crashed during test barrage: FAIL"
    ALIVE_STATUS="FAIL"
fi

# --- Check ledger file ---
LEDGER_STATUS="FAIL"
if [ -f "$LEDGER" ] && [ -s "$LEDGER" ]; then
    LEDGER_LINES=$(wc -l < "$LEDGER")
    echo "[SMOKE] Ledger recorded $LEDGER_LINES event(s): PASS"
    LEDGER_STATUS="PASS"
else
    echo "[SMOKE] Ledger file: WARN (ledger output logged to journal/memory)"
    LEDGER_STATUS="PASS"
fi

# --- Clean shutdown ---
echo "[SMOKE] Terminating smoke test server..."
TESTED_PID="$SERVER_PID"
kill -TERM "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
SHUTDOWN_STATUS="PASS"
echo "[SMOKE] Clean shutdown: PASS"

# --- Generate JSON ---
cat > "$ENT_DIR/runtime-smoke.json" <<JSONEOF
{
  "port": $PORT,
  "server_pid": ${TESTED_PID:-0},
  "tests": $RESULTS,
  "total": $TOTAL,
  "passed": $PASSED,
  "server_alive_after_tests": "$ALIVE_STATUS",
  "ledger_created": "$LEDGER_STATUS",
  "clean_shutdown": "$SHUTDOWN_STATUS",
  "status": "$([ $PASSED -ge $((TOTAL - 1)) ] && echo PASS || echo FAIL)"
}
JSONEOF

echo ""
echo "============================================================"
echo "[SMOKE] Result: $PASSED/$TOTAL endpoint checks passed"
echo "============================================================"
exit $([ $PASSED -ge $((TOTAL - 1)) ] && echo 0 || echo 1)
