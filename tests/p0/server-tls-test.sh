#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 - In-process TLS and transport-policy regression test
#
# Verifies that:
#   1. HTTPS is served when EXAMOS_TLS_CERT/EXAMOS_TLS_KEY are provisioned.
#   2. HSTS and the hardened security headers are emitted over TLS.
#   3. Cleartext HTTP is not accepted by a TLS listener.
#   4. A cleartext listener on a non-loopback address is refused at startup.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_BIN="${EXAMOS_SERVER_BIN:-$WORKSPACE/server/examos-server}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-tls.XXXXXX")"
PORT="${EXAMOS_TLS_TEST_PORT:-19224}"
FAIL=0

pass() { echo "[TLS-PASS] $1"; }
fail() { echo "[TLS-FAIL] $1" >&2; FAIL=1; }

cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

[ -x "$SERVER_BIN" ] || { echo "[TLS-BLOCKED] server binary unavailable: $SERVER_BIN" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "[TLS-BLOCKED] openssl unavailable" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "[TLS-BLOCKED] curl unavailable" >&2; exit 2; }

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
    -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" >/dev/null 2>&1 \
    || { echo "[TLS-BLOCKED] cannot create test certificate" >&2; exit 2; }
chmod 600 "$TMP_DIR/key.pem"
mkdir -p "$TMP_DIR/data"

start_server() {
    EXAMOS_SERVER_PORT="$PORT" \
    EXAMOS_LEDGER_PATH="$TMP_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_SESSION_JOURNAL="$TMP_DIR/session.log" \
    EXAMOS_DATA_DIR="$TMP_DIR/data" \
    EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/events.log" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV=1 \
    EXAMOS_TPM_MODE=development \
    EXAMOS_TLS_CERT="$TMP_DIR/cert.pem" \
    EXAMOS_TLS_KEY="$TMP_DIR/key.pem" \
    "$SERVER_BIN" >"$TMP_DIR/server.log" 2>&1 &
    SERVER_PID=$!
}

start_server
READY=0
for _ in $(seq 1 30); do
    if curl -sk -o /dev/null "https://127.0.0.1:$PORT/api/v1/health"; then READY=1; break; fi
    sleep 0.2
done
if [ "$READY" -ne 1 ]; then
    fail "HTTPS listener did not become ready"
    tail -20 "$TMP_DIR/server.log" >&2 || true
    exit 1
fi
pass "HTTPS listener ready"

HEADERS="$TMP_DIR/headers.txt"
curl -sk -D "$HEADERS" -o /dev/null "https://127.0.0.1:$PORT/api/v1/health"
grep -qi '^Strict-Transport-Security: .*max-age=' "$HEADERS" \
    && pass "HSTS emitted over TLS" || fail "HSTS header missing"
grep -qi '^Content-Security-Policy: ' "$HEADERS" \
    && pass "CSP emitted" || fail "CSP header missing"
grep -qi '^X-Frame-Options: DENY' "$HEADERS" \
    && pass "frame embedding denied" || fail "X-Frame-Options missing"
grep -qi '^X-Content-Type-Options: nosniff' "$HEADERS" \
    && pass "MIME sniffing denied" || fail "nosniff header missing"
grep -qi '^Referrer-Policy: no-referrer' "$HEADERS" \
    && pass "referrer policy set" || fail "Referrer-Policy missing"

CLEARTEXT_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
    "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null || true)
[ -n "$CLEARTEXT_CODE" ] || CLEARTEXT_CODE=000
if [ "$CLEARTEXT_CODE" = "000" ]; then
    pass "TLS listener rejects cleartext HTTP"
else
    fail "TLS listener answered cleartext HTTP with $CLEARTEXT_CODE"
fi

if echo | openssl s_client -connect "127.0.0.1:$PORT" -tls1_2 2>/dev/null | grep -q 'Protocol *: *TLSv1.2'; then
    pass "TLS 1.2 accepted (minimum supported version)"
else
    fail "TLS 1.2 handshake failed"
fi

# Start refusal check: a second process on a non-loopback address without TLS.
# The timeout prevents a regression from leaving a cleartext listener running.
EXAMOS_SERVER_PORT=$((PORT + 1)) \
EXAMOS_LEDGER_PATH="$TMP_DIR/refuse-ledger.log" \
EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
EXAMOS_SESSION_JOURNAL="$TMP_DIR/refuse-session.log" \
EXAMOS_DATA_DIR="$TMP_DIR/data" \
EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/refuse-events.log" \
EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)" \
EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
EXAMOS_ALLOW_UNPROVISIONED_DEV=1 \
EXAMOS_TPM_MODE=development \
EXAMOS_BIND_ADDR=0.0.0.0 \
timeout 10 "$SERVER_BIN" >"$TMP_DIR/refuse.log" 2>&1
REFUSE_RC=$?
if [ "$REFUSE_RC" -ne 0 ] && grep -q 'refusing a cleartext listener' "$TMP_DIR/refuse.log"; then
    pass "cleartext non-loopback listener refused"
else
    fail "cleartext non-loopback listener was not refused (rc=$REFUSE_RC)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[TLS] RESULT: FAIL" >&2
    exit 1
fi
echo "[TLS] RESULT: PASS"
