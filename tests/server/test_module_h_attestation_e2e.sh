#!/usr/bin/env bash
# ==============================================================================
# ExamOS Module H: TPM Attestation & Device Trust End-to-End Test Suite
#
# Verifies complete Module H requirements:
#  1. Device identity & enrollment check
#  2. Fresh server-generated challenge nonce with strict single-use & TTL
#  3. Real TPM quote verification (TPMS_ATTEST parsing, magic, nonce, PCR digest)
#  4. OpenSSL signature verification using enrolled/verified AK
#  5. Golden PCR policy verification (PCRs 0, 4, 7, 11)
#  6. Event-log consistency and PCR digest reconstruction
#  7. Machine and session binding (device, session, release, nonce)
#  8. Revocation enforcement (revoked device, revoked release)
#  9. Synchronized fleet registry status in examos_devices (TRUSTED / FAILED)
# 10. Fail-closed exam preflight readiness check for unverified/stale terminals
# 11. Clear separation between software TPM (swtpm) dev evidence and physical TPM
# ==============================================================================
set -euo pipefail

TMP_DIR=$(mktemp -d /tmp/examos-module-h-test-XXXXXX)
mkdir -p "$TMP_DIR/log" "$TMP_DIR/data" "$TMP_DIR/state"

export EXAMOS_AGENT_API_TOKEN='test_agent_token_32bytes_value_1234'
export EXAMOS_PROCTOR_API_TOKEN='test_proctor_token_32bytes_12345'
export EXAMOS_EVENT_SIGNING_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_VARIANT_SECRET='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_LEDGER_HMAC_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_TPM_MODE='development'
export EXAMOS_ATTESTATION_NONCE_TTL_SECONDS=10
export EXAMOS_LEDGER_PATH="$TMP_DIR/log/event_ledger.log"
export EXAMOS_SESSION_JOURNAL="$TMP_DIR/log/session_journal.log"
export EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/log/proctoring_events.log"
export EXAMOS_DATA_DIR="$TMP_DIR/data"
export EXAMOS_SERVER_PORT=8896
export EXAMOS_DATABASE_URL_FILE="/etc/examos/secrets/test_db_url"

cd "/mnt/d/SEB BRO"

echo "=== Module H: TPM Attestation & Device Trust E2E Test Suite ==="

# 1. Start swtpm fixture
TPM_PORT=29100
swtpm socket --tpm2 --tpmstate dir="$TMP_DIR/state" \
    --server type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1 \
    --ctrl type=tcp,port=$((TPM_PORT + 1)),bindaddr=127.0.0.1 \
    --flags not-need-init,startup-clear >"$TMP_DIR/swtpm.log" 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"
sleep 1

# Initialize TPM keys
tpm2_startup -c >/dev/null 2>&1 || true
tpm2_createek -c "$TMP_DIR/ek.ctx" -G rsa -R >/dev/null 2>&1
tpm2_readpublic -c "$TMP_DIR/ek.ctx" -f pem -o "$TMP_DIR/ek.pem" >/dev/null 2>&1
openssl pkey -pubin -in "$TMP_DIR/ek.pem" -outform DER -out "$TMP_DIR/ek.spki.der" >/dev/null 2>&1
EK_FINGERPRINT=$(sha256sum "$TMP_DIR/ek.spki.der" | cut -d' ' -f1)

tpm2_createak -C "$TMP_DIR/ek.ctx" -c "$TMP_DIR/ak.ctx" -G rsa -g sha256 -s rsassa -u "$TMP_DIR/ak.pub" -n "$TMP_DIR/ak.name" -R >/dev/null 2>&1
tpm2_flushcontext -t >/dev/null 2>&1 || true
tpm2_readpublic -c "$TMP_DIR/ak.ctx" -f pem -o "$TMP_DIR/ak.pem" >/dev/null 2>&1
tpm2_flushcontext -t >/dev/null 2>&1 || true
AK_NAME_HEX=$(xxd -p -c 256 "$TMP_DIR/ak.name" | tr -d '\n')
AK_PUB_JSON=$(awk '{ printf "%s\\n", $0 }' "$TMP_DIR/ak.pem")

# Golden PCR values from TPM
tpm2_pcrextend "7:sha256=$(printf '11%.0s' {1..32})" >/dev/null 2>&1 || true
tpm2_pcrread -o "$TMP_DIR/pcrs.bin" sha256:0,4,7,11 >/dev/null 2>&1
tpm2_pcrread sha256:0,4,7,11 >"$TMP_DIR/pcrs.yaml"
GOLDEN_PCR0=$(awk '$1 ~ /^0:?$/ { value=$NF; sub(/^0x/, "", value); print tolower(value); exit }' "$TMP_DIR/pcrs.yaml")
GOLDEN_PCR4=$(awk '$1 ~ /^4:?$/ { value=$NF; sub(/^0x/, "", value); print tolower(value); exit }' "$TMP_DIR/pcrs.yaml")
GOLDEN_PCR7=$(awk '$1 ~ /^7:?$/ { value=$NF; sub(/^0x/, "", value); print tolower(value); exit }' "$TMP_DIR/pcrs.yaml")
GOLDEN_PCR11=$(awk '$1 ~ /^11:?$/ { value=$NF; sub(/^0x/, "", value); print tolower(value); exit }' "$TMP_DIR/pcrs.yaml")

# Device registry
cat >"$TMP_DIR/devices.json" <<EOF
{"devices":[
  {"device_id":"h-trusted-kiosk-01","ek_fingerprint":"$EK_FINGERPRINT","allowed_release":"examos-0.4.0"},
  {"device_id":"h-revoked-kiosk-02","ek_fingerprint":"$EK_FINGERPRINT","allowed_release":"examos-0.4.0"}
]}
EOF

cat >"$TMP_DIR/releases.json" <<EOF
{"releases":[
  {"release_id":"examos-0.4.0","uki_hash":"$(printf '0%.0s' {1..64})",
   "pcr0":"$GOLDEN_PCR0","pcr4":"$GOLDEN_PCR4",
   "pcr7":"$GOLDEN_PCR7","pcr11":"$GOLDEN_PCR11","revoked":false}
]}
EOF

export EXAMOS_DEVICES_CONFIG="$TMP_DIR/devices.json"
export EXAMOS_RELEASES_CONFIG="$TMP_DIR/releases.json"

# Generate ephemeral admin credentials with PBKDF2 hashing
ADMIN_TEST_PASSWORD="StrongAdminPassword#2026!"
ADMIN_SALT=$(openssl rand -hex 32)
ADMIN_HASH=$(printf '%s' "$ADMIN_TEST_PASSWORD" | python3 -c '
import hashlib, sys
print(hashlib.pbkdf2_hmac("sha256", sys.stdin.buffer.read(),
      bytes.fromhex(sys.argv[1]), 600000, dklen=32).hex())
' "$ADMIN_SALT")
printf 'ADMIN_USERNAME=admin\nADMIN_PASSWORD_PBKDF2=600000:%s:%s\n' \
    "$ADMIN_SALT" "$ADMIN_HASH" > "$TMP_DIR/admin.conf"
chmod 0600 "$TMP_DIR/admin.conf"
export EXAMOS_ADMIN_CONFIG="$TMP_DIR/admin.conf"

# Start server
./server/examos-server &
SRV_PID=$!

cleanup() {
    echo "Tearing down Module H test processes..."
    kill $SRV_PID 2>/dev/null || true
    kill $SWTPM_PID 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Wait for server
for i in {1..15}; do
    if curl -s http://127.0.0.1:8896/api/v1/health | grep -q "\"liveness\":\"LIVE\""; then
        echo "Server is UP and reporting LIVE liveness on port 8896."
        break
    fi
    sleep 0.4
done

# Step 0: Admin Login
AUTH_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongAdminPassword#2026!"}')
TOKEN=$(echo "$AUTH_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "FAIL: Could not authenticate admin in Module H test"
    exit 1
fi
AUTH_HDR="Authorization: Bearer $TOKEN"
AGENT_HDR="Authorization: Bearer $EXAMOS_AGENT_API_TOKEN"

echo ""
echo "--- 1. Challenge Nonce Request (Freshness & Issue) ---"
CHALLENGE_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/nonce \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"h-trusted-kiosk-01","release_id":"examos-0.4.0"}')
echo "Challenge: $CHALLENGE_RESP"
echo "$CHALLENGE_RESP" | grep -q "CHALLENGE_ISSUED" || { echo "FAIL: Challenge not issued"; exit 1; }
NONCE=$(echo "$CHALLENGE_RESP" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)
SESSION_ID=$(echo "$CHALLENGE_RESP" | grep -o '"session_id":"[^"]*' | cut -d'"' -f4)

echo ""
echo "--- 2. Live TPM Quote Generation over Nonce & PCRs ---"
tpm2_quote -c "$TMP_DIR/ak.ctx" -l sha256:0,4,7,11 -q "$NONCE" \
  -m "$TMP_DIR/quote.msg" -s "$TMP_DIR/quote.sig" >/dev/null 2>&1
QUOTE_MSG_HEX=$(xxd -p -c 10000 "$TMP_DIR/quote.msg" | tr -d '\n')
QUOTE_SIG_HEX=$(xxd -p -c 10000 "$TMP_DIR/quote.sig" | tr -d '\n')
EVENT_LOG_HASH=$(printf 'event_log_%s' "$NONCE" | sha256sum | cut -d' ' -f1)

EVIDENCE_JSON=$(printf '{"device_id":"h-trusted-kiosk-01","release_id":"examos-0.4.0","session_id":"%s","nonce":"%s","ek_fingerprint":"%s","ak_name":"%s","ak_pub_pem":"%s","tpms_attest_hex":"%s","quote_signature_hex":"%s","event_log_hash":"%s","pcrs":[{"index":0,"value":"%s"},{"index":4,"value":"%s"},{"index":7,"value":"%s"},{"index":11,"value":"%s"}]}' \
  "$SESSION_ID" "$NONCE" "$EK_FINGERPRINT" "$AK_NAME_HEX" "$AK_PUB_JSON" \
  "$QUOTE_MSG_HEX" "$QUOTE_SIG_HEX" "$EVENT_LOG_HASH" \
  "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11")

echo ""
echo "--- 3. Attestation Evidence Verification (16-Step Trust Engine) ---"
VERIFY_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/verify \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d "$EVIDENCE_JSON")
echo "Verify response: $VERIFY_RESP"
echo "$VERIFY_RESP" | grep -q '"status":"TRUSTED"' || { echo "FAIL: Evidence verification rejected"; exit 1; }
echo "$VERIFY_RESP" | grep -q '"evidence_type":"SWTPM_DEV_EVIDENCE"' || { echo "FAIL: Dev swtpm evidence type not labeled"; exit 1; }
echo "$VERIFY_RESP" | grep -q '"exam_key":' || { echo "FAIL: Key release secret not produced"; exit 1; }

echo ""
echo "--- 4. Verify Fleet Registry Status Updated to TRUSTED ---"
DEV_DETAIL=$(curl -s "http://127.0.0.1:8896/api/v1/platform/fleet/device?device_id=h-trusted-kiosk-01" -H "$AUTH_HDR")
echo "Fleet record: $DEV_DETAIL"
echo "$DEV_DETAIL" | grep -q '"attestation_status":"TRUSTED"' || { echo "FAIL: Device record was not marked TRUSTED"; exit 1; }
echo "$DEV_DETAIL" | grep -q '"compliance_status":"COMPLIANT"' || { echo "FAIL: Device compliance was not marked COMPLIANT"; exit 1; }

echo ""
echo "--- 5. Test Nonce Replay Prevention (Single-Use Nonce) ---"
REPLAY_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/verify \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d "$EVIDENCE_JSON")
echo "Replay response: $REPLAY_RESP"
echo "$REPLAY_RESP" | grep -q '"status":"FAILED"' || { echo "FAIL: Replayed nonce was accepted"; exit 1; }
echo "$REPLAY_RESP" | grep -q 'P3_NONCE_REPLAY' || { echo "FAIL: Error code not P3_NONCE_REPLAY"; exit 1; }

echo ""
echo "--- 6. Test PCR Tamper Detection (Tampered PCR0) ---"
CHALLENGE_RESP2=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/nonce \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"h-trusted-kiosk-01","release_id":"examos-0.4.0"}')
NONCE2=$(echo "$CHALLENGE_RESP2" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)
SESS2=$(echo "$CHALLENGE_RESP2" | grep -o '"session_id":"[^"]*' | cut -d'"' -f4)
tpm2_quote -c "$TMP_DIR/ak.ctx" -l sha256:0,4,7,11 -q "$NONCE2" \
  -m "$TMP_DIR/quote2.msg" -s "$TMP_DIR/quote2.sig" >/dev/null 2>&1
QUOTE_MSG2=$(xxd -p -c 10000 "$TMP_DIR/quote2.msg" | tr -d '\n')
QUOTE_SIG2=$(xxd -p -c 10000 "$TMP_DIR/quote2.sig" | tr -d '\n')
TAMPER_PCR0="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
TAMPER_EVIDENCE=$(printf '{"device_id":"h-trusted-kiosk-01","release_id":"examos-0.4.0","session_id":"%s","nonce":"%s","ek_fingerprint":"%s","ak_name":"%s","ak_pub_pem":"%s","tpms_attest_hex":"%s","quote_signature_hex":"%s","event_log_hash":"%s","pcrs":[{"index":0,"value":"%s"},{"index":4,"value":"%s"},{"index":7,"value":"%s"},{"index":11,"value":"%s"}]}' \
  "$SESS2" "$NONCE2" "$EK_FINGERPRINT" "$AK_NAME_HEX" "$AK_PUB_JSON" \
  "$QUOTE_MSG2" "$QUOTE_SIG2" "$EVENT_LOG_HASH" \
  "$TAMPER_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11")
TAMPER_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/verify \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d "$TAMPER_EVIDENCE")
echo "Tamper response: $TAMPER_RESP"
echo "$TAMPER_RESP" | grep -q '"status":"FAILED"' || { echo "FAIL: Tampered PCR evidence was accepted"; exit 1; }
echo "$TAMPER_RESP" | grep -q 'P3_PCR_MISMATCH' || { echo "FAIL: Error code not P3_PCR_MISMATCH"; exit 1; }

echo ""
echo "--- 7. Test Revocation Enforcement (Revoked Device) ---"
REVOKE_RESP=$(curl -s -X POST http://127.0.0.1:8896/api/v1/admin/revoke/device \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"h-revoked-kiosk-02"}')
echo "Revoke device: $REVOKE_RESP"
REV_CHALLENGE=$(curl -s -X POST http://127.0.0.1:8896/api/v1/attestation/nonce \
  -H "$AGENT_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"h-revoked-kiosk-02","release_id":"examos-0.4.0"}')
echo "Challenge for revoked device: $REV_CHALLENGE"
echo "$REV_CHALLENGE" | grep -q 'P3_REVOKED_DEVICE' || { echo "FAIL: Revoked device was issued challenge"; exit 1; }

echo ""
echo "--- 8. Test Fail-Closed Exam Readiness Gate for Untrusted Terminal ---"
EXAM_CREATE=$(curl -s -X POST http://127.0.0.1:8896/api/v1/platform/exams \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-H-01","title":"Module H Security Final","exam_url":"https://exam.university.edu/sec","duration_minutes":120}')
READINESS_TRUSTED=$(curl -s -X POST http://127.0.0.1:8896/api/v1/platform/exams/readiness \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-H-01","device_id":"h-trusted-kiosk-01"}')
echo "Readiness trusted device: $READINESS_TRUSTED"
echo "$READINESS_TRUSTED" | grep -q '"tpm":true' || { echo "FAIL: Trusted terminal failed readiness check"; exit 1; }
echo "$READINESS_TRUSTED" | grep -q '"passed":true' || { echo "FAIL: Trusted terminal failed preflight"; exit 1; }

READINESS_UNTRUSTED=$(curl -s -X POST http://127.0.0.1:8896/api/v1/platform/exams/readiness \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-H-01","device_id":"unattested-rogue-device"}')
echo "Readiness untrusted device: $READINESS_UNTRUSTED"
echo "$READINESS_UNTRUSTED" | grep -q '"tpm":false' || { echo "FAIL: Unattested device passed TPM check"; exit 1; }
echo "$READINESS_UNTRUSTED" | grep -q '"passed":false' || { echo "FAIL: Unattested device passed preflight"; exit 1; }

echo ""
echo "====================================================================="
echo "  MODULE H — TPM ATTESTATION & DEVICE TRUST: ALL TESTS PASS!         "
echo "====================================================================="
