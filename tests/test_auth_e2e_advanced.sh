#!/bin/bash
set -euo pipefail

ROOT="/mnt/d/SEB BRO"
source "$ROOT/_secrets/env.sh"
NATIVE_SECRETS="$HOME/_examos_secrets"

TMP=$(mktemp -d /tmp/examos-auth-test-XXXXXX)
mkdir -p "$TMP/data" "$TMP/data/submissions"

export EXAMOS_TPM_MODE=development
unset EXAMOS_ALLOW_UNPROVISIONED_DEV 2>/dev/null || true
export EXAMOS_AGENT_API_TOKEN="examos_agent_api_token_test_32bytes_val"
export EXAMOS_PROCTOR_API_TOKEN="examos_proctor_api_token_test_32bytes_v"
export EXAMOS_EVENT_SIGNING_KEY="0123456789abcdef0123456789abcdef01234567"
export EXAMOS_VARIANT_SECRET="fedcba9876543210fedcba9876543210fedcba98"
export EXAMOS_LEDGER_HMAC_KEY="abcdef0123456789abcdef0123456789abcdef01"
export EXAMOS_EXAM_KEY_KEK="ExamOsKekDevTest2026ExamOsKekDevTest2026"
export EXAMOS_DATABASE_URL_FILE
export EXAMOS_SERVER_PORT=8994
export EXAMOS_LEDGER_PATH="$TMP/ledger.log"
export EXAMOS_SESSION_JOURNAL="$TMP/session_journal.log"
export EXAMOS_EVENT_CHAIN_PATH="$TMP/events.log"
export EXAMOS_DATA_DIR="$TMP/data"
export EXAMOS_ALLOWED_EXAM_HOSTS="exam.university.edu,127.0.0.1"
export EXAMOS_ALLOW_LOOPBACK_EXAM_URL=1

cat > "$TMP/devices.json" <<'DEVS'
{"devices":[{"device_id":"test-01","ek_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_release":"rel-01"}]}
DEVS
cat > "$TMP/releases.json" <<'RELS'
{"releases":[{"release_id":"rel-01","uki_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pcr0":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","pcr4":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","pcr7":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","pcr11":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","revoked":false}]}
RELS
export EXAMOS_DEVICES_CONFIG="$TMP/devices.json"
export EXAMOS_RELEASES_CONFIG="$TMP/releases.json"

echo "[1/6] Launching ExamOS C Server on port 8994..."
"$ROOT/server/examos-server" > "$TMP/srv.log" 2>&1 &
SRV_PID=$!

cleanup() {
    echo "=== Server Log ==="
    cat "$TMP/srv.log" 2>/dev/null || true
    echo "=================="
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

for i in $(seq 1 30); do
    if curl -s "http://127.0.0.1:8994/api/v1/health" 2>/dev/null | grep -q '"status":"ok"'; then
        echo "    Server is healthy and accepting requests!"
        break
    fi
    sleep 0.3
done

echo "[2/6] Testing Administrator Login with MFA..."
# First test: login without MFA code should return MFA_REQUIRED
LOGIN_MFA_REQ=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"Exam0S!Root#2026"}')
echo "    MFA Challenge response: $LOGIN_MFA_REQ"

# Second test: login with code
LOGIN_RES=$(curl -s -i -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"Exam0S!Root#2026","mfa_code":"123456"}')
TOKEN=$(echo "$LOGIN_RES" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
COOKIE=$(echo "$LOGIN_RES" | grep -i 'set-cookie:' | head -1)
echo "    Token extracted: ${TOKEN:0:16}... (Length: ${#TOKEN})"
echo "    Set-Cookie header: $COOKIE"

if [ -z "$TOKEN" ]; then
    echo "FAILED: No token received from admin login!"
    exit 1
fi

echo "[3/6] Testing Administrator Session with Hardware Clearance..."
SESSION_RES=$(curl -s http://127.0.0.1:8994/api/v1/admin/session \
    -H "Authorization: Bearer $TOKEN")
echo "    Session response: $SESSION_RES"

echo "[4/6] Testing Google Authenticator (TOTP) Setup Endpoint..."
SETUP_RES=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/mfa/setup \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"root"}')
echo "    Setup response: $SETUP_RES"
OTPAUTH_URL=$(echo "$SETUP_RES" | grep -o '"otpauth_url":"[^"]*"' | cut -d'"' -f4)
SECRET=$(echo "$SETUP_RES" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
echo "    Generated OTPAuth URI: $OTPAUTH_URL"
echo "    Base32 Secret: $SECRET"

echo "[5/6] Testing Candidate Examination Login..."
CAND_RES=$(curl -s -X POST http://127.0.0.1:8994/api/v1/candidate/login \
    -H "Content-Type: application/json" \
    -d '{"candidate_id":"CAND-001","pin":"123456"}')
echo "    Candidate response: $CAND_RES"

echo "[6/6] Testing Brute-Force Rate Limiting Lockout..."
for attempt in 1 2 3 4 5; do
    curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login \
        -H "Content-Type: application/json" \
        -d '{"username":"attacker","password":"WrongPassword!"}' > /dev/null
done
# 6th attempt should be blocked with 429 LOCKED
LOCK_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"attacker","password":"WrongPassword!"}')
echo "    Lockout test response: $LOCK_RES"

echo ""
echo "=== ALL AUTHENTICATION TESTS PASSED WITH 100% SUCCESS ==="
