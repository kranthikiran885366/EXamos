#!/usr/bin/env bash
set -e

TMP_DIR=$(mktemp -d /tmp/examos-fleet-test-XXXXXX)
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
export EXAMOS_SERVER_PORT=8897
export EXAMOS_DATABASE_URL_FILE="/etc/examos/secrets/test_db_url"

cd "/mnt/d/SEB BRO"

echo "=== Module G: Device Enrollment & Fleet Management E2E Test ==="
echo "Starting examos-server on port 8897..."
./server/examos-server &
SRV_PID=$!

cleanup() {
    echo "Stopping test server (PID $SRV_PID)..."
    kill $SRV_PID 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Wait up to 5 seconds for server ready
for i in {1..10}; do
    if curl -s http://127.0.0.1:8897/api/v1/health | grep -q "HEALTHY"; then
        echo "Server is UP and HEALTHY."
        break
    fi
    sleep 0.5
done

# Step 1: Login as administrator
echo ""
echo "--- 1. Authenticating Admin Session ---"
AUTH_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongAdminPassword#2026!"}')
TOKEN=$(echo "$AUTH_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "FAIL: Failed to acquire admin token. Response: $AUTH_RESP"
    exit 1
fi
echo "Admin token acquired."

AUTH_HDR="Authorization: Bearer $TOKEN"

# Step 2: Enroll Institution-Owned Device
echo ""
echo "--- 2. Enrolling Institution-Owned Device (kiosk-g-01) ---"
ENROLL_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/enroll \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{
    "device_id": "kiosk-g-01",
    "hostname": "lab1-pc01.kiosk.internal",
    "group": "PRODUCTION_LAB",
    "ring": "PILOT",
    "ownership_type": "INSTITUTION_OWNED",
    "student_owned": false,
    "hardware_platform": "x86_64 / UEFI TPM 2.0"
  }')
echo "Enroll Response: $ENROLL_RESP"
echo "$ENROLL_RESP" | grep -q "ENROLLMENT_SUBMITTED" || { echo "FAIL: Device enrollment failed"; exit 1; }

# Step 3: Verify Device Detail Retrieval
echo ""
echo "--- 3. Verifying Device Record Retrieval ---"
DEV_RESP=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-01" \
  -H "$AUTH_HDR")
echo "Device Details: $DEV_RESP"
echo "$DEV_RESP" | grep -q "kiosk-g-01" || { echo "FAIL: Device ID not found"; exit 1; }
echo "$DEV_RESP" | grep -q "PRODUCTION_LAB" || { echo "FAIL: Group not matched"; exit 1; }

# Step 4: Device Approval Workflow
echo ""
echo "--- 4. Device Approval Workflow (kiosk-g-02) ---"
curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/enroll \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{
    "device_id": "kiosk-g-02",
    "hostname": "lab1-pc02.kiosk.internal",
    "group": "PRODUCTION_LAB",
    "ring": "PILOT"
  }' > /dev/null

APPROVE_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/approve \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"kiosk-g-02"}')
echo "Approval Response: $APPROVE_RESP"
echo "$APPROVE_RESP" | grep -q "DEVICE_ENROLLMENT_APPROVED" || { echo "FAIL: Approval failed"; exit 1; }

DEV2_RESP=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-02" -H "$AUTH_HDR")
echo "$DEV2_RESP" | grep -q '"enrollment_status":"ENROLLED"' || { echo "FAIL: Device not marked ENROLLED"; exit 1; }

# Step 5: Student-Owned (BYOD) Device with Privacy Scope Guarantee
echo ""
echo "--- 5. Student-Owned (BYOD) Device Enrollment & Privacy Scope ---"
BYOD_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/enroll \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{
    "device_id": "byod-student-42",
    "hostname": "student-macbook.local",
    "group": "REMOTE_CANDIDATES",
    "ring": "GENERAL",
    "ownership_type": "STUDENT_OWNED",
    "student_owned": true,
    "hardware_platform": "Apple Silicon / Secure Enclave"
  }')
echo "BYOD Enroll: $BYOD_RESP"
echo "$BYOD_RESP" | grep -q "ENROLLMENT_SUBMITTED" || { echo "FAIL: BYOD enrollment failed"; exit 1; }

BYOD_DEV=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=byod-student-42" -H "$AUTH_HDR")
echo "BYOD Device Detail: $BYOD_DEV"
echo "$BYOD_DEV" | grep -q '"student_owned":true' || { echo "FAIL: student_owned flag not set"; exit 1; }
echo "$BYOD_DEV" | grep -q "PRIVACY_SCOPE_ENFORCED" || { echo "FAIL: privacy scope not enforced"; exit 1; }

# Step 6: Device Health Telemetry & Heartbeat
echo ""
echo "--- 6. Device Health Telemetry & Heartbeat ---"
HB_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/heartbeat \
  -H "Authorization: Bearer test_agent_token_32bytes_value_1234" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "kiosk-g-01",
    "battery_pct": 92,
    "battery_charging": true,
    "disk_free_mb": 45000,
    "mem_used_mb": 3200,
    "network_state": "CONNECTED",
    "policy_version": 2,
    "session_state": "IDLE"
  }')
echo "Heartbeat Response: $HB_RESP"
echo "$HB_RESP" | grep -q "HEARTBEAT_ACKNOWLEDGED" || { echo "FAIL: Heartbeat failed"; exit 1; }

# Step 7: Authorized Maintenance Mode
echo ""
echo "--- 7. Maintenance Mode Management ---"
MAINT_ON=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/maintenance \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"kiosk-g-01","maintenance":1}')
echo "Maintenance ON: $MAINT_ON"
echo "$MAINT_ON" | grep -q "MAINTENANCE_UPDATED" || { echo "FAIL: Maintenance enable failed"; exit 1; }

DEV1_MAINT=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-01" -H "$AUTH_HDR")
echo "$DEV1_MAINT" | grep -q '"maintenance":true' || { echo "FAIL: maintenance true expected"; exit 1; }

MAINT_OFF=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/maintenance \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"kiosk-g-01","maintenance":0}')
echo "Maintenance OFF: $MAINT_OFF"

# Step 8: Device Quarantine (Lost/Compromised Device Handling)
echo ""
echo "--- 8. Lost/Compromised Device Quarantine ---"
QUAR_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/quarantine \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"kiosk-g-02","reason":"Suspected physical enclosure tampering"}')
echo "Quarantine Response: $QUAR_RESP"
echo "$QUAR_RESP" | grep -q "DEVICE_QUARANTINED" || { echo "FAIL: Quarantine failed"; exit 1; }

DEV2_QUAR=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-02" -H "$AUTH_HDR")
echo "$DEV2_QUAR" | grep -q '"compliance_status":"QUARANTINED"' || { echo "FAIL: Compliance status not QUARANTINED"; exit 1; }

# Step 9: Cryptographic Credential Revocation
echo ""
echo "--- 9. Cryptographic Credential Revocation ---"
REV_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/revoke_credentials \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"kiosk-g-02","reason":"Key leak suspected"}')
echo "Credential Revocation: $REV_RESP"
echo "$REV_RESP" | grep -q "DEVICE_CREDENTIALS_REVOKED" || { echo "FAIL: Credential revocation failed"; exit 1; }

DEV2_REV=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-02" -H "$AUTH_HDR")
echo "$DEV2_REV" | grep -q '"crypto_identity_ref":"REVOKED"' || { echo "FAIL: crypto_identity_ref not REVOKED"; exit 1; }
echo "$DEV2_REV" | grep -q '"attestation_status":"FAILED"' || { echo "FAIL: attestation not FAILED"; exit 1; }

# Step 10: Device Replacement & Re-enrollment
echo ""
echo "--- 10. Device Replacement & Re-enrollment ---"
REPLACE_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/replace \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"old_device_id":"kiosk-g-01","new_device_id":"kiosk-g-01-replacement"}')
echo "Replace Response: $REPLACE_RESP"
echo "$REPLACE_RESP" | grep -q "DEVICE_REPLACED" || { echo "FAIL: Replacement failed"; exit 1; }

OLD_DEV=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-01" -H "$AUTH_HDR")
echo "$OLD_DEV" | grep -q '"enrollment_status":"REPLACED"' || { echo "FAIL: Old device not marked REPLACED"; exit 1; }

NEW_DEV=$(curl -s -X GET "http://127.0.0.1:8897/api/v1/platform/fleet/device?device_id=kiosk-g-01-replacement" -H "$AUTH_HDR")
echo "$NEW_DEV" | grep -q '"replacement_for":"kiosk-g-01"' || { echo "FAIL: New device does not link replacement_for"; exit 1; }

# Step 11: Device Unenrollment with Data Cleanup
echo ""
echo "--- 11. Device Unenrollment & Data Cleanup ---"
UNENR_RESP=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/unenroll \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{"device_id":"byod-student-42","cleanup_data":true}')
echo "Unenroll Response: $UNENR_RESP"
echo "$UNENR_RESP" | grep -q "DEVICE_UNENROLLED" || { echo "FAIL: Unenrollment failed"; exit 1; }
echo "$UNENR_RESP" | grep -q '"data_cleaned":true' || { echo "FAIL: data_cleaned true expected"; exit 1; }

# Step 12: Bulk Actions (Preview and Execution)
echo ""
echo "--- 12. Bulk Fleet Management Actions ---"
# Preview mode
BULK_PREVIEW=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/bulk \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{
    "action_type": "ASSIGN_GROUP",
    "target_group": "PRODUCTION_LAB",
    "param_value": "EXAM_ROOM_101",
    "preview_only": true
  }')
echo "Bulk Preview: $BULK_PREVIEW"
echo "$BULK_PREVIEW" | grep -q '"preview_only":true' || { echo "FAIL: Bulk preview failed"; exit 1; }
echo "$BULK_PREVIEW" | grep -q "PREVIEW_READY" || { echo "FAIL: Preview status expected PREVIEW_READY"; exit 1; }

# Execution mode
BULK_EXEC=$(curl -s -X POST http://127.0.0.1:8897/api/v1/platform/fleet/bulk \
  -H "$AUTH_HDR" -H "Content-Type: application/json" \
  -d '{
    "action_type": "ASSIGN_GROUP",
    "target_group": "PRODUCTION_LAB",
    "param_value": "EXAM_ROOM_101",
    "preview_only": false
  }')
echo "Bulk Execute: $BULK_EXEC"
echo "$BULK_EXEC" | grep -q '"status":"COMPLETED"' || { echo "FAIL: Bulk execute status not COMPLETED"; exit 1; }

# Step 13: Compliance Reporting
echo ""
echo "--- 13. Fleet Compliance & Inventory Reporting ---"
COMP_RESP=$(curl -s -X GET http://127.0.0.1:8897/api/v1/platform/fleet/compliance -H "$AUTH_HDR")
echo "Compliance Report: $COMP_RESP"
echo "$COMP_RESP" | grep -q "total_devices" || { echo "FAIL: total_devices missing"; exit 1; }
echo "$COMP_RESP" | grep -q "student_owned" || { echo "FAIL: student_owned missing"; exit 1; }
echo "$COMP_RESP" | grep -q "institution_owned" || { echo "FAIL: institution_owned missing"; exit 1; }
echo "$COMP_RESP" | grep -q "attestation" || { echo "FAIL: attestation stats missing"; exit 1; }

echo ""
echo "====================================================================="
echo "  MODULE G — DEVICE ENROLLMENT & FLEET MANAGEMENT: ALL TESTS PASS!   "
echo "====================================================================="
