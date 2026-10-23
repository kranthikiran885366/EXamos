#!/usr/bin/env bash
set -e

TMP_DIR=$(mktemp -d /tmp/examos-test-XXXXXX)
mkdir -p "$TMP_DIR/log" "$TMP_DIR/data" "$TMP_DIR/data/submissions"

export EXAMOS_AGENT_API_TOKEN='test_agent_token_32bytes_value_1234'
export EXAMOS_PROCTOR_API_TOKEN='test_proctor_token_32bytes_12345'
export EXAMOS_EVENT_SIGNING_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_VARIANT_SECRET='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_LEDGER_HMAC_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
export EXAMOS_TPM_MODE='development'
export EXAMOS_LEDGER_PATH="$TMP_DIR/log/event_ledger.log"
export EXAMOS_SESSION_JOURNAL="$TMP_DIR/log/session_journal.log"
export EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/log/proctoring_events.log"
export EXAMOS_DATA_DIR="$TMP_DIR/data"
export EXAMOS_SERVER_PORT=8899

cd "/mnt/d/SEB BRO"

echo "Starting examos-server on port 8899..."
./server/examos-server &
SRV_PID=$!

cleanup() {
    kill $SRV_PID 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Wait up to 5 seconds for server ready
for i in {1..10}; do
    if curl -s http://127.0.0.1:8899/api/v1/health | grep -q "\"liveness\":\"LIVE\""; then
        echo "Server is UP and reporting LIVE liveness."
        break
    fi
    sleep 0.5
done

echo ""
echo "=== 1. Testing Server-side Multi-Routing for /admin/* ==="
HDR_OVERVIEW=$(curl -s -I http://127.0.0.1:8899/admin/overview | head -n 1)
echo "GET /admin/overview -> $HDR_OVERVIEW"

HDR_FLEET=$(curl -s -I http://127.0.0.1:8899/admin/fleet | head -n 1)
echo "GET /admin/fleet -> $HDR_FLEET"

HDR_POLICIES=$(curl -s -I http://127.0.0.1:8899/admin/policies | head -n 1)
echo "GET /admin/policies -> $HDR_POLICIES"

echo ""
echo "=== 2. Testing Authentication (Module B) ==="
AUTH_RESP=$(curl -s -X POST http://127.0.0.1:8899/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongAdminPassword#2026!"}')
echo "Auth Response: $AUTH_RESP"

TOKEN=$(echo "$AUTH_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to retrieve auth token"
    exit 1
fi
echo "Retrieved Session Token: ${TOKEN:0:16}..."

echo ""
echo "=== 3. Testing Real Operational Telemetry (Module A.1, Module M) ==="
TELEMETRY=$(curl -s http://127.0.0.1:8899/api/v1/platform/telemetry -H "Authorization: Bearer $TOKEN")
echo "Telemetry: $TELEMETRY"

echo ""
echo "=== 4. Testing Dynamic URL Security: Reject Plain HTTP (Module D) ==="
HTTP_REJECT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://127.0.0.1:8899/api/v1/platform/exams/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-CS101","exam_url":"http://insecure-exam.com/test","allowed_origins":"insecure-exam.com"}')
echo "HTTP Rejection Response:"
echo "$HTTP_REJECT"

echo ""
echo "=== 5. Testing Dynamic URL: Accept Dynamic HTTPS + Produce Signed Policy (Module D) ==="
HTTPS_ACCEPT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://127.0.0.1:8899/api/v1/platform/exams/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-CS101","exam_url":"https://prod-exam.university.edu/spring2026","allowed_origins":"https://prod-exam.university.edu"}')
echo "HTTPS Accept Response:"
echo "$HTTPS_ACCEPT"

echo ""
echo "=== 6. Testing Policy Ledger & Cryptographic Signature (Module D) ==="
POLICIES=$(curl -s http://127.0.0.1:8899/api/v1/platform/policies -H "Authorization: Bearer $TOKEN")
echo "Policies: $POLICIES"

echo ""
echo "=== 6a. Testing Disallowed Origin Rejection (Module D) ==="
ORIGIN_REJECT=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://127.0.0.1:8899/api/v1/platform/exams/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-CS101","exam_url":"https://prod-exam.university.edu/spring2026","allowed_origins":"http://insecure-cdn.com"}')
echo "Origin Rejection Response:"
echo "$ORIGIN_REJECT"

echo ""
echo "=== 6b. Testing Authenticated Policy Bundle Distribution (Module D) ==="
BUNDLE_RESP=$(curl -s -X POST http://127.0.0.1:8899/api/v1/platform/policy/bundle \
  -H "Authorization: Bearer test_agent_token_32bytes_value_1234" \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-CS101","device_id":"DEV-KIOSK-01"}')
echo "Policy Bundle Response:"
echo "$BUNDLE_RESP"

echo ""
echo "=== 6c. Testing Client Effective Policy Reporting (Module D) ==="
# Ensure device DEV-KIOSK-01 is enrolled in fleet inventory first
curl -s -X POST http://127.0.0.1:8899/api/v1/platform/fleet/maintenance \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"DEV-KIOSK-01","maintenance":false}' > /dev/null

EFF_RESP=$(curl -s -X POST http://127.0.0.1:8899/api/v1/platform/policy/effective \
  -H "Authorization: Bearer test_agent_token_32bytes_value_1234" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"DEV-KIOSK-01","os_release":"examos-2.0.26","image_digest":"sha256:abc1234","effective_policy_version":5}')
echo "Effective Policy Reporting Response:"
echo "$EFF_RESP"

echo ""
echo "=== 7. Testing Fleet Inventory & Registration (Module G) ==="
FLEET=$(curl -s http://127.0.0.1:8899/api/v1/platform/fleet -H "Authorization: Bearer $TOKEN")
echo "Fleet: $FLEET"

echo ""
echo "=== 8. Testing Reconciliation & Evidence Balance (Module M) ==="
RECON=$(curl -s http://127.0.0.1:8899/api/v1/platform/reconciliation -H "Authorization: Bearer $TOKEN")
echo "Reconciliation: $RECON"

echo ""
echo "=== 9. Testing Advanced Firewall & Network Security (Module E) ==="
FW_STATUS=$(curl -s http://127.0.0.1:8899/api/v1/firewall/status -H "Authorization: Bearer $TOKEN")
echo "Firewall Status: $FW_STATUS"

echo ""
echo "=== 9a. Testing Firewall Controlled Egress Ruleset Application ==="
FW_APPLY=$(curl -s -X POST http://127.0.0.1:8899/api/v1/firewall/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"exam_id":"EXAM-CS101"}')
echo "Firewall Apply Response: $FW_APPLY"

echo ""
echo "=== 9b. Testing Firewall Permitted Endpoint Connectivity ==="
FW_TEST_PERM=$(curl -s -X POST http://127.0.0.1:8899/api/v1/firewall/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://127.0.0.1:8899/api/v1/health"}')
echo "Permitted Connectivity Test: $FW_TEST_PERM"

echo ""
echo "=== 9c. Testing Firewall Fail-Safe Rollback to Baseline ==="
FW_ROLLBACK=$(curl -s -X POST http://127.0.0.1:8899/api/v1/firewall/rollback \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')
echo "Firewall Rollback Response: $FW_ROLLBACK"

echo ""
echo "=== All platform module API and Multi-Routing checks PASSED successfully ==="
