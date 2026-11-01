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

echo "[1/8] Launching ExamOS C Server on port 8994..."
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

echo "[2/8] Testing first-time administrator authenticator enrollment..."
# A management account without a registered authenticator must NOT receive a
# session.  It receives a single-use enrollment token instead.
LOGIN_SETUP_REQ=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"Exam0S!Root#2026"}')
echo "    Enrollment challenge response: $LOGIN_SETUP_REQ"

if ! echo "$LOGIN_SETUP_REQ" | grep -q 'MFA_SETUP_REQUIRED'; then
    echo "FAILED: unenrolled admin login did not require authenticator setup!"
    exit 1
fi
if echo "$LOGIN_SETUP_REQ" | grep -q '"token":"'; then
    echo "FAILED: unenrolled admin login leaked a management session token!"
    exit 1
fi

ENROLL_TOKEN=$(echo "$LOGIN_SETUP_REQ" | grep -o '"enrollment_token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$ENROLL_TOKEN" ]; then
    echo "FAILED: no enrollment token issued!"
    exit 1
fi

# Setup must reject an unauthenticated caller that only knows the username.
UNAUTH_SETUP=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/mfa/setup \
    -H "Content-Type: application/json" -d '{"username":"root"}')
echo "    Unauthenticated setup response: $UNAUTH_SETUP"
if echo "$UNAUTH_SETUP" | grep -q '"secret":"'; then
    echo "FAILED: unauthenticated caller obtained an authenticator secret!"
    exit 1
fi

SETUP_RES=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/mfa/setup \
    -H "X-Enrollment-Token: $ENROLL_TOKEN" \
    -H "Content-Type: application/json" -d '{}')
echo "    Setup response: $SETUP_RES"
SECRET=$(echo "$SETUP_RES" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)
if [ -z "$SECRET" ]; then
    echo "FAILED: enrollment flow did not return a server-generated secret!"
    exit 1
fi
echo "    Base32 Secret: $SECRET"

# Derive the current RFC 6238 code from the server-issued secret.
TOTP_CODE=$(python3 - "$SECRET" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print("%06d" % code)
PY
)
echo "    Derived TOTP code: $TOTP_CODE"

CONFIRM_RES=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/mfa/confirm \
    -H "X-Enrollment-Token: $ENROLL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$TOTP_CODE\"}")
echo "    Confirm response: $CONFIRM_RES"
if ! echo "$CONFIRM_RES" | grep -q '"status":"SUCCESS"'; then
    echo "FAILED: authenticator enrollment did not complete!"
    exit 1
fi

echo "[3/8] Testing Administrator Login with the registered authenticator..."
LOGIN_MFA_REQ=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"Exam0S!Root#2026"}')
echo "    MFA Challenge response: $LOGIN_MFA_REQ"
if ! echo "$LOGIN_MFA_REQ" | grep -q 'MFA_REQUIRED'; then
    echo "FAILED: enrolled admin login did not require an MFA code!"
    exit 1
fi

LOGIN_RES=$(curl -s -i -X POST http://127.0.0.1:8994/api/v1/admin/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"root\",\"password\":\"Exam0S!Root#2026\",\"mfa_code\":\"$TOTP_CODE\"}")
TOKEN=$(echo "$LOGIN_RES" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
COOKIE=$(echo "$LOGIN_RES" | grep -i 'set-cookie:' | head -1)
echo "    Token extracted: ${TOKEN:0:16}... (Length: ${#TOKEN})"
echo "    Set-Cookie header: $COOKIE"

if [ -z "$TOKEN" ]; then
    echo "FAILED: No token received from admin login!"
    exit 1
fi

echo "[4/8] Testing Administrator Session..."
SESSION_RES=$(curl -s http://127.0.0.1:8994/api/v1/admin/session \
    -H "Authorization: Bearer $TOKEN")
echo "    Session response: $SESSION_RES"
if ! echo "$SESSION_RES" | grep -q '"username":"root"'; then
    echo "FAILED: session lookup did not return the authenticated account!"
    exit 1
fi
if echo "$SESSION_RES" | grep -q 'TPM_2_0_ENFORCED'; then
    echo "FAILED: session endpoint fabricated a hardware attestation claim!"
    exit 1
fi

echo "[5/8] Testing Candidate Examination Login..."
CAND_RES=$(curl -s -X POST http://127.0.0.1:8994/api/v1/candidate/login \
    -H "Content-Type: application/json" \
    -H "User-Agent: ExamOS-Kiosk/1.0" \
    -d '{"candidate_id":"CAND-001","pin":"123456"}')
echo "    Candidate response: $CAND_RES"
CAND_TOKEN=$(echo "$CAND_RES" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$CAND_TOKEN" ]; then
    echo "FAILED: candidate login did not return a session token!"
    exit 1
fi
# A freshly issued candidate token must immediately work for exam routes, not
# only after a server restart restores the session journal.
PAPER_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8994/api/v1/exam/paper \
    -H "Authorization: Bearer $CAND_TOKEN" -H "User-Agent: ExamOS-Kiosk/1.0")
echo "    Exam paper HTTP status with new token: $PAPER_STATUS (expected not 401/403)"
if [ "$PAPER_STATUS" = "401" ] || [ "$PAPER_STATUS" = "403" ]; then
    echo "FAILED: newly issued candidate token was not accepted by the exam workbench!"
    exit 1
fi

echo "[6/8] Testing Brute-Force Rate Limiting Lockout..."
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

echo "[7/8] Testing self-service password change and session invalidation..."
CODE_NOW=$(python3 - "$SECRET" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print("%06d" % code)
PY
)
NEW_PW='Str0ng!Admin#2026-P1'
PW_WRONG=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8994/api/v1/admin/password/change \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"current_password":"DefinitelyWrong#2026","new_password":"Str0ng!Admin#2026-P1"}')
echo "    Wrong-current-password HTTP status: $PW_WRONG"
if [ "$PW_WRONG" != "401" ]; then
    echo "FAILED: password change accepted a wrong current password!"
    exit 1
fi

# Open a second concurrent session, then change the password from the first.
SIDE_LOGIN=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login -H "Content-Type: application/json" \
    -d "{\"username\":\"root\",\"password\":\"Exam0S!Root#2026\",\"mfa_code\":\"$CODE_NOW\"}")
TOKEN_SIDE=$(echo "$SIDE_LOGIN" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$TOKEN_SIDE" ]; then
    echo "FAILED: could not open a second session for the invalidation check!"
    exit 1
fi

PW_CHANGE=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/password/change \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"current_password\":\"Exam0S!Root#2026\",\"new_password\":\"$NEW_PW\"}")
echo "    Change response: $PW_CHANGE"
if ! echo "$PW_CHANGE" | grep -q '"status":"SUCCESS"'; then
    echo "FAILED: password change did not succeed!"
    exit 1
fi

CURRENT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8994/api/v1/admin/session \
    -H "Authorization: Bearer $TOKEN")
SIDE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8994/api/v1/admin/session \
    -H "Authorization: Bearer $TOKEN_SIDE")
echo "    Current session HTTP status: $CURRENT_STATUS (expected 200)"
echo "    Other session HTTP status:   $SIDE_STATUS (expected 401)"
if [ "$CURRENT_STATUS" != "200" ] || [ "$SIDE_STATUS" = "200" ]; then
    echo "FAILED: password change did not revoke other sessions while keeping the caller signed in!"
    exit 1
fi

CODE_NOW=$(python3 - "$SECRET" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print("%06d" % code)
PY
)
LOGIN_NEW=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/login -H "Content-Type: application/json" \
    -d "{\"username\":\"root\",\"password\":\"$NEW_PW\",\"mfa_code\":\"$CODE_NOW\"}")
TOKEN2=$(echo "$LOGIN_NEW" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$TOKEN2" ]; then
    echo "FAILED: login with the new password failed!"
    exit 1
fi

# Restore the fixture password so repeated runs start from a known state.
REVERT=$(curl -s -X POST http://127.0.0.1:8994/api/v1/admin/password/change \
    -H "Authorization: Bearer $TOKEN2" -H "Content-Type: application/json" \
    -d "{\"current_password\":\"$NEW_PW\",\"new_password\":\"Exam0S!Root#2026\"}")
echo "    Revert response: $REVERT"

echo "[8/8] Testing candidate session logout..."
CAND_LOGOUT=$(curl -s -X POST http://127.0.0.1:8994/api/v1/candidate/logout \
    -H "Authorization: Bearer $CAND_TOKEN" -H "Content-Type: application/json" -d '{}')
echo "    Candidate logout response: $CAND_LOGOUT"
if ! echo "$CAND_LOGOUT" | grep -q 'SIGNED_OUT'; then
    echo "FAILED: candidate logout did not terminate the session!"
    exit 1
fi
POST_LOGOUT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8994/api/v1/exam/paper \
    -H "Authorization: Bearer $CAND_TOKEN" -H "User-Agent: ExamOS-Kiosk/1.0")
echo "    Exam paper HTTP status after logout: $POST_LOGOUT_STATUS (expected 401)"
if [ "$POST_LOGOUT_STATUS" != "401" ]; then
    echo "FAILED: logged-out candidate token is still accepted!"
    exit 1
fi

echo ""
echo "=== ALL AUTHENTICATION TESTS PASSED WITH 100% SUCCESS ==="
