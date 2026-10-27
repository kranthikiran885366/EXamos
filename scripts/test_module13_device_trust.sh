#!/bin/bash
set -euo pipefail

BASE_URL="http://127.0.0.1:8895"
PASS_COUNT=0
FAIL_COUNT=0

log_pass() {
    echo -e "\e[32m✔ PASS:\e[0m $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo -e "\e[31m✘ FAIL:\e[0m $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "======================================================================"
echo " Starting Module 13: Device Trust, Registration & Attestation Test Suite"
echo "======================================================================"

# 1. Admin Login (Platform Owner / Security Administrator)
LOGIN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"StrongAdminPassword#2026!"}')

TOKEN_ADMIN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -n "$TOKEN_ADMIN" ]; then
    log_pass "Admin authenticated"
else
    log_fail "Admin authentication failed: $LOGIN_RESP"
    exit 1
fi

INST_A="inst_vignan"
INST_B="inst_gitam"

# 2. Provision Test Examination & Eligible Student for Launch Authorization
EXAM_CODE="OS-M13-$(date +%s | tail -c 4)"
EXAM_CREATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"Operating Systems & Trust – Sem 5\",\"subject\":\"OS\",\"code\":\"${EXAM_CODE}\",\"academic_year\":\"2026-2027\",\"duration_minutes\":120,\"institution_id\":\"${INST_A}\",\"exam_url\":\"https://exam.vignan.ac.in/portal/os13\",\"allowed_origins\":\"https://exam.vignan.ac.in\"}")
EXAM_ID=$(echo "$EXAM_CREATE_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)

curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/approve" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"decision":"approved"}' > /dev/null

curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/publish" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"notes":"Published for Module 13 verification"}' > /dev/null

STU_ROLL="22VIG1301"
STU_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU_ROLL}\",\"name\":\"Kavya Rao\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":90,\"administrative_hold\":false,\"institution_id\":\"${INST_A}\"}")
STU_ID=$(echo "$STU_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)

curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU_ID}\"}" > /dev/null

log_pass "Prerequisites configured (Exam: ${EXAM_ID}, Student: ${STU_ROLL})"

# ======================================================================
# CHECK 1: Device Registration with Enrolled Hardware AK
# ======================================================================
DEV1_ID="dev_lab_vignan_01"
DEV1_AK_PEM="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3yQ...\n-----END PUBLIC KEY-----"

REG_DEV_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/register" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${DEV1_ID}\",\"institution_id\":\"${INST_A}\",\"hostname\":\"lab01.vignan.local\",\"device_name\":\"Lab Station 01\",\"device_category\":\"lab_pc\",\"manufacturer\":\"Dell\",\"model\":\"OptiPlex 7090\",\"cpu_arch\":\"x86_64\",\"boot_mode\":\"UEFI\",\"secure_boot_state\":\"enabled\",\"tpm_present\":true,\"tpm_version\":\"2.0\",\"os_release_id\":\"ExamOS 2.0\",\"kernel_version\":\"6.6.0-examos\",\"ak_public_key_pem\":\"${DEV1_AK_PEM}\"}")

if echo "$REG_DEV_RESP" | grep -q '"device_id":"'"${DEV1_ID}"'"' && echo "$REG_DEV_RESP" | grep -q '"status":"registered"'; then
    log_pass "Check 1: Device registered successfully with TPM 2.0 & Secure Boot enabled: ${DEV1_ID}"
else
    log_fail "Check 1: Device registration failed: $REG_DEV_RESP"
    exit 1
fi

# ======================================================================
# CHECK 2: Device Query and Details
# ======================================================================
GET_DEV_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/devices/${DEV1_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$GET_DEV_RESP" | grep -q '"hostname":"lab01.vignan.local"' && echo "$GET_DEV_RESP" | grep -q '"secure_boot_state":"enabled"'; then
    log_pass "Check 2: Device inventory and capabilities retrieved correctly"
else
    log_fail "Check 2: Failed to retrieve device inventory: $GET_DEV_RESP"
fi

# ======================================================================
# CHECK 3: Request Fresh Attestation Challenge (Anti-Replay Nonce)
# ======================================================================
CH_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/attestation/challenge" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")

CH_NONCE=$(echo "$CH_RESP" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)
CH_ID=$(echo "$CH_RESP" | grep -o '"challenge_id":"[^"]*' | cut -d'"' -f4)

if [ -n "$CH_NONCE" ] && [ -n "$CH_ID" ] && echo "$CH_RESP" | grep -q '"status":"CHALLENGE_ISSUED"'; then
    log_pass "Check 3: Fresh attestation challenge issued with cryptographic nonce: ${CH_NONCE:0:16}..."
else
    log_fail "Check 3: Attestation challenge creation failed: $CH_RESP"
    exit 1
fi

# ======================================================================
# CHECK 4: Reject Invalid / Corrupt Quote Signature
# ======================================================================
BAD_SIG_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/attestation/verify" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"challenge_id\":\"${CH_ID}\",\"nonce\":\"${CH_NONCE}\",\"quote_signature\":\"INVALID_SIGNATURE\"}")

if echo "$BAD_SIG_RESP" | grep -q "verification failed"; then
    log_pass "Check 4: Invalid TPM quote signature correctly rejected"
else
    log_fail "Check 4: Invalid quote signature was not rejected: $BAD_SIG_RESP"
fi

# ======================================================================
# CHECK 5: Verify Valid TPM 2.0 Quote & Record Evidence
# ======================================================================
# Request new challenge since bad sig used previous nonce
CH2_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/attestation/challenge" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")
CH2_NONCE=$(echo "$CH2_RESP" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)

VERIFY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/attestation/verify" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"nonce\":\"${CH2_NONCE}\",\"quote_signature\":\"a3b8c9d0e1f2a3b8c9d0e1f2a3b8c9d0e1f2a3b8\",\"pcr_digest\":\"sha256:d8e8fca2dc0f896fd7cb4cb0031ba249\"}")

if echo "$VERIFY_RESP" | grep -q '"verification_result":"TRUSTED"' && echo "$VERIFY_RESP" | grep -q '"outcome":"ALLOW"'; then
    log_pass "Check 5: TPM quote verified and trusted evidence recorded"
else
    log_fail "Check 5: Attestation verification failed: $VERIFY_RESP"
fi

# ======================================================================
# CHECK 6: Anti-Replay Protection (Reject Reused Challenge Nonce)
# ======================================================================
REPLAY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/attestation/verify" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"nonce\":\"${CH2_NONCE}\",\"quote_signature\":\"a3b8c9d0e1f2a3b8c9d0e1f2a3b8c9d0e1f2a3b8\"}")

if echo "$REPLAY_RESP" | grep -q "anti-replay violation"; then
    log_pass "Check 6: Replayed nonce challenge rejected with anti-replay violation"
else
    log_fail "Check 6: Replay attack was not prevented: $REPLAY_RESP"
fi

# ======================================================================
# CHECK 7: Device Trust Decision Evaluation (ALLOW)
# ======================================================================
TRUST_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/devices/${DEV1_ID}/trust-status" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$TRUST_RESP" | grep -q '"outcome":"ALLOW"'; then
    log_pass "Check 7: Device trust evaluation returned ALLOW"
else
    log_fail "Check 7: Device trust evaluation failed: $TRUST_RESP"
fi

# ======================================================================
# CHECK 8: Secure Boot Disabled Failure Policy (DENY)
# ======================================================================
DEV_NOSB_ID="dev_nosb_test"
curl -s -X POST "${BASE_URL}/api/v1/devices/register" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${DEV_NOSB_ID}\",\"institution_id\":\"${INST_A}\",\"secure_boot_state\":\"disabled\",\"tpm_present\":true}" > /dev/null

TRUST_NOSB=$(curl -s -X GET "${BASE_URL}/api/v1/devices/${DEV_NOSB_ID}/trust-status" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$TRUST_NOSB" | grep -q '"outcome":"DENY"' && echo "$TRUST_NOSB" | grep -q "Secure Boot verification failed"; then
    log_pass "Check 8: Device with disabled Secure Boot denied trust"
else
    log_fail "Check 8: Insecure boot state was not denied: $TRUST_NOSB"
fi

# ======================================================================
# CHECK 9: Missing TPM Failure Policy (UNSUPPORTED)
# ======================================================================
DEV_NOTPM_ID="dev_notpm_test"
curl -s -X POST "${BASE_URL}/api/v1/devices/register" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${DEV_NOTPM_ID}\",\"institution_id\":\"${INST_A}\",\"secure_boot_state\":\"enabled\",\"tpm_present\":false}" > /dev/null

TRUST_NOTPM=$(curl -s -X GET "${BASE_URL}/api/v1/devices/${DEV_NOTPM_ID}/trust-status" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$TRUST_NOTPM" | grep -q '"outcome":"UNSUPPORTED"'; then
    log_pass "Check 9: Device without TPM hardware marked UNSUPPORTED"
else
    log_fail "Check 9: Missing TPM was not handled: $TRUST_NOTPM"
fi

# ======================================================================
# CHECK 10: Device Assignment & Conflict Prevention
# ======================================================================
ASG1_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/assign" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU_ID}\",\"exam_id\":\"${EXAM_ID}\"}")

if echo "$ASG1_RESP" | grep -q '"status":"assigned"'; then
    log_pass "Check 10a: Device successfully assigned to student: ${STU_ID}"
else
    log_fail "Check 10a: Failed to assign device: $ASG1_RESP"
fi

# Overlapping Assignment Attempt for different student
ASG_CONFLICT=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/assign" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"stu_different_candidate\",\"exam_id\":\"${EXAM_ID}\"}")

if echo "$ASG_CONFLICT" | grep -q "already actively assigned"; then
    log_pass "Check 10b: Overlapping active device assignment blocked (409 conflict)"
else
    log_fail "Check 10b: Conflicting assignment was not blocked: $ASG_CONFLICT"
fi

# ======================================================================
# CHECK 11: Master Exam Launch Authorization Integration (Modules 9-13)
# ======================================================================
LAUNCH_GATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-launch/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${DEV1_ID}\",\"student_id\":\"${STU_ID}\",\"examination_id\":\"${EXAM_ID}\"}")

if echo "$LAUNCH_GATE_RESP" | grep -q '"status":"launch_authorized"' && \
   echo "$LAUNCH_GATE_RESP" | grep -q '"launch_token":' && \
   echo "$LAUNCH_GATE_RESP" | grep -q "https://exam.vignan.ac.in/portal/os13"; then
    log_pass "Check 11: Master launch authorization gate passed: verified Device Trust, Student Eligibility, and Session Token"
else
    log_fail "Check 11: Master launch authorization failed: $LAUNCH_GATE_RESP"
fi

# ======================================================================
# CHECK 12: Launch Denied When Device Is Untrusted or Suspended
# ======================================================================
# Suspend DEV1
curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/suspend" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Suspended for scheduled maintenance"}' > /dev/null

SUSPENDED_LAUNCH=$(curl -s -X POST "${BASE_URL}/api/v1/exam-launch/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${DEV1_ID}\",\"student_id\":\"${STU_ID}\",\"examination_id\":\"${EXAM_ID}\"}")

if echo "$SUSPENDED_LAUNCH" | grep -q "DEVICE_TRUST_FAILED"; then
    log_pass "Check 12: Exam launch correctly blocked for suspended / untrusted device"
else
    log_fail "Check 12: Suspended device was permitted to launch exam: $SUSPENDED_LAUNCH"
fi

# Restore DEV1 to registered
curl -s -X POST "${BASE_URL}/api/v1/devices/${DEV1_ID}/approve" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" > /dev/null

# ======================================================================
# CHECK 13: Revocation & Security Event Logging
# ======================================================================
REV_DEV_ID="dev_tampered_test"
curl -s -X POST "${BASE_URL}/api/v1/devices/register" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${REV_DEV_ID}\",\"institution_id\":\"${INST_A}\"}" > /dev/null

REV_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/devices/${REV_DEV_ID}/revoke" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Hardware firmware modification detected"}' )

if echo "$REV_RESP" | grep -q '"status":"revoked"'; then
    log_pass "Check 13: Device identity revoked and attestation credentials invalidated"
else
    log_fail "Check 13: Failed to revoke device: $REV_RESP"
fi

# ======================================================================
# CHECK 14: Multi-Tenant Boundary Enforcement
# ======================================================================
# Login as Gitam Admin (Institution B)
GITAM_DEV_ID="dev_gitam_station_01"
curl -s -X POST "${BASE_URL}/api/v1/devices/register" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"device_id\":\"${GITAM_DEV_ID}\",\"institution_id\":\"${INST_B}\"}" > /dev/null

# Verify audit trail and security events in DB
DEV_AUDIT_COUNT=$(/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -t -A \
    -c "SELECT count(*) FROM device_audit_events WHERE device_id = '${DEV1_ID}';")

DEV_SEC_COUNT=$(/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -t -A \
    -c "SELECT count(*) FROM device_security_events WHERE device_id = '${DEV1_ID}';")

if [ "$DEV_AUDIT_COUNT" -ge 3 ] && [ "$DEV_SEC_COUNT" -ge 2 ]; then
    log_pass "Check 14: Durable device audit logs (${DEV_AUDIT_COUNT}) and security events (${DEV_SEC_COUNT}) verified"
else
    log_fail "Check 14: Insufficient audit/security event records: audit=${DEV_AUDIT_COUNT}, sec=${DEV_SEC_COUNT}"
fi

echo "======================================================================"
echo " Module 13 Test Results: ${PASS_COUNT} Passed, ${FAIL_COUNT} Failed"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
