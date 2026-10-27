#!/usr/bin/env bash
# ==============================================================================
# test_module10_registration.sh — Test Suite for ExamOS Module 10:
# Examination Registration & Eligibility Management
# Validates student provisioning, configurable eligibility rules, evaluations,
# approvals, exceptions, bulk imports, versioned roster publications, and real-time gate.
# ==============================================================================
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
echo " Starting Module 10: Examination Registration & Eligibility Test Suite"
echo "======================================================================"

# 1. Admin Login (Platform Owner / Exam Manager)
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

INST_ID="inst_vignan"
INST_B_ID="inst_gitam"

# 2. Create Examination for Testing Registration
EXAM_CODE="DBMS-M10-$(date +%s | tail -c 4)"
EXAM_CREATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"Database Management Systems – Semester 5\",\"subject\":\"DBMS\",\"code\":\"${EXAM_CODE}\",\"academic_year\":\"2026-2027\",\"duration_minutes\":120,\"institution_id\":\"${INST_ID}\"}")

EXAM_ID=$(echo "$EXAM_CREATE_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$EXAM_ID" ]; then
    log_pass "Test examination created: id=${EXAM_ID} (${EXAM_CODE})"
else
    log_fail "Failed to create test exam: $EXAM_CREATE_RESP"
    exit 1
fi

# 3. Provision Student Profiles (Students master record)
# Student 1: Eligible student (B.Tech CSE, Sem 5, Active, Attendance 88%, No Hold)
STU1_ROLL="22B91A0501"
STU1_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU1_ROLL}\",\"name\":\"Aarav Sharma\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":88,\"administrative_hold\":false,\"institution_id\":\"${INST_ID}\"}")

STU1_ID=$(echo "$STU1_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$STU1_ID" ]; then
    log_pass "Student 1 provisioned (Eligible): ${STU1_ROLL}"
else
    log_fail "Failed to provision Student 1: $STU1_RESP"
fi

# Student 2: Ineligible student (Low Attendance 60%, Requires 75%)
STU2_ROLL="22B91A0502"
STU2_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU2_ROLL}\",\"name\":\"Diya Nair\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":60,\"administrative_hold\":false,\"institution_id\":\"${INST_ID}\"}")

STU2_ID=$(echo "$STU2_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$STU2_ID" ]; then
    log_pass "Student 2 provisioned (Low Attendance): ${STU2_ROLL}"
else
    log_fail "Failed to provision Student 2: $STU2_RESP"
fi

# Student 3: Ineligible student (Administrative Hold)
STU3_ROLL="22B91A0503"
STU3_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU3_ROLL}\",\"name\":\"Rohan Gupta\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":90,\"administrative_hold\":true,\"hold_reason\":\"Unpaid laboratory fee\",\"institution_id\":\"${INST_ID}\"}")

STU3_ID=$(echo "$STU3_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$STU3_ID" ]; then
    log_pass "Student 3 provisioned (Administrative Hold): ${STU3_ROLL}"
else
    log_fail "Failed to provision Student 3: $STU3_RESP"
fi

# Student 4: Cross-institution student belonging to inst_gitam
STU4_ROLL="22GIT0501"
STU4_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU4_ROLL}\",\"name\":\"Priya Patel\",\"course\":\"B.Tech CSE\",\"semester\":5,\"institution_id\":\"${INST_B_ID}\"}")

echo "STU4_RESP: $STU4_RESP"
STU4_ID=$(echo "$STU4_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4 || true)
if [ -n "$STU4_ID" ]; then
    log_pass "Student 4 provisioned (Gitam Institution): ${STU4_ROLL}"
else
    log_fail "Failed to provision Student 4: $STU4_RESP"
fi

# 4. Configure Eligibility Rules for Examination
# Rule 1: Course Enrollment must be B.Tech CSE
RULE1_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/rules" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"rule_type":"course_enrollment","rule_config_json":"{\"course\":\"B.Tech CSE\"}"}')

# Rule 2: Minimum Attendance 75%
RULE2_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/rules" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"rule_type":"attendance","rule_config_json":"{\"minimum_attendance_pct\":75}"}')

# Rule 3: Semester must be 5
RULE3_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/rules" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"rule_type":"semester","rule_config_json":"{\"semester\":5}"}')

if echo "$RULE1_RESP" | grep -q '"created"' && echo "$RULE2_RESP" | grep -q '"created"' && echo "$RULE3_RESP" | grep -q '"created"'; then
    log_pass "Configured 3 eligibility rules (Course enrollment, 75% attendance, Semester 5)"
else
    log_fail "Failed to configure rules: $RULE1_RESP / $RULE2_RESP / $RULE3_RESP"
fi

# 5. Register Student 1 (Should be automatically APPROVED & ELIGIBLE)
REG1_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU1_ID}\"}")

echo "REG1_RESP: $REG1_RESP"
REG1_ID=$(echo "$REG1_RESP" | grep -o '"registration_id":"[^"]*' | cut -d'"' -f4 || true)
REG1_STAT=$(echo "$REG1_RESP" | grep -o '"registration_status":"[^"]*' | cut -d'"' -f4 || true)

if [ -n "$REG1_ID" ] && [ "$REG1_STAT" = "approved" ]; then
    log_pass "Check 1: Eligible student registered and automatically approved"
else
    log_fail "Check 1 Failed: $REG1_RESP"
fi

# 6. Prevent Duplicate Registration
DUP_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU1_ID}\"}")

if echo "$DUP_RESP" | grep -q "Duplicate registration"; then
    log_pass "Check 2: Duplicate registration prevented with 409 conflict"
else
    log_fail "Check 2 Failed - duplicate registration accepted: $DUP_RESP"
fi

# 7. Reject Student from Wrong Institution (Tenant Isolation)
CROSS_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU4_ID}\"}")

if echo "$CROSS_RESP" | grep -q "tenant mismatch"; then
    log_pass "Check 3: Cross-institution student registration rejected (Tenant Boundary)"
else
    log_fail "Check 3 Failed - cross-institution student allowed: $CROSS_RESP"
fi

# 8. Test Ineligible Student (Low Attendance -> exception_review / ineligible)
REG2_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU2_ID}\"}")

REG2_ID=$(echo "$REG2_RESP" | grep -o '"registration_id":"[^"]*' | cut -d'"' -f4)
REG2_ELIG=$(echo "$REG2_RESP" | grep -o '"eligibility_status":"[^"]*' | cut -d'"' -f4)

if [ "$REG2_ELIG" = "ineligible" ]; then
    log_pass "Check 4: Student with low attendance (60% < 75%) flagged ineligible"
else
    log_fail "Check 4 Failed: $REG2_RESP"
fi

# 9. Test Student with Administrative Hold
REG3_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU3_ID}\"}")

REG3_ID=$(echo "$REG3_RESP" | grep -o '"registration_id":"[^"]*' | cut -d'"' -f4)
if echo "$REG3_RESP" | grep -q "Administrative hold"; then
    log_pass "Check 5: Student with administrative hold flagged ineligible"
else
    log_fail "Check 5 Failed: $REG3_RESP"
fi

# 10. Grant Authorized Exception with Reason (min 8 chars)
SHORT_EXC_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/registrations/${REG2_ID}/exception" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"ok"}')

if echo "$SHORT_EXC_RESP" | grep -q "minimum 8 characters"; then
    log_pass "Check 6a: Short exception reason rejected (< 8 chars)"
else
    log_fail "Check 6a Failed: $SHORT_EXC_RESP"
fi

VALID_EXC_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/registrations/${REG2_ID}/exception" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Medical leave approved by Dean of Academic Affairs"}')

if echo "$VALID_EXC_RESP" | grep -q '"exception_approved"'; then
    log_pass "Check 6b: Authorized exception granted with audit justification"
else
    log_fail "Check 6b Failed: $VALID_EXC_RESP"
fi

# 11. Reject Registration (Student 3 with administrative hold)
REJECT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/registrations/${REG3_ID}/reject" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Unresolved library and laboratory dues from previous semester"}')

if echo "$REJECT_RESP" | grep -q '"rejected"'; then
    log_pass "Check 7: Ineligible registration formally rejected with recorded reason"
else
    log_fail "Check 7 Failed: $REJECT_RESP"
fi

# 12. Bulk Import Registrations with Error Reporting
# Provision Student 5 for valid import
STU5_ROLL="22B91A0505"
curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU5_ROLL}\",\"name\":\"Kavya Reddy\",\"course\":\"B.Tech CSE\",\"semester\":5,\"attendance_pct\":85,\"institution_id\":\"${INST_ID}\"}" > /dev/null

IMPORT_PAYLOAD=$(cat <<EOF
{
  "records": [
    { "roll_no": "${STU5_ROLL}", "name": "Kavya Reddy", "institution_id": "${INST_ID}" },
    { "roll_no": "", "name": "Missing Roll", "institution_id": "${INST_ID}" },
    { "roll_no": "${STU4_ROLL}", "name": "Priya Patel", "institution_id": "${INST_B_ID}" }
  ]
}
EOF
)

IMPORT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations/import" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "$IMPORT_PAYLOAD")

JOB_ID=$(echo "$IMPORT_RESP" | grep -o '"job_id":"[^"]*' | cut -d'"' -f4)
VALID_ROWS=$(echo "$IMPORT_RESP" | grep -o '"valid_rows":[0-9]*' | cut -d':' -f2)
ERROR_ROWS=$(echo "$IMPORT_RESP" | grep -o '"error_rows":[0-9]*' | cut -d':' -f2)

if [ -n "$JOB_ID" ] && [ "$VALID_ROWS" = "1" ] && [ "$ERROR_ROWS" = "2" ]; then
    log_pass "Check 8: Bulk import processed with exact row validation (1 valid, 2 rejected)"
else
    log_fail "Check 8 Failed: $IMPORT_RESP"
fi

# 13. Publish Authorized Roster (Creates Versioned Snapshot + SHA-256 Hash)
PUB_ROSTER_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/roster/publish" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

ROSTER_VER=$(echo "$PUB_ROSTER_RESP" | grep -o '"version":[0-9]*' | cut -d':' -f2)
ROSTER_HASH=$(echo "$PUB_ROSTER_RESP" | grep -o '"roster_hash":"[^"]*' | cut -d'"' -f4)

if [ "$ROSTER_VER" = "1" ] && [ -n "$ROSTER_HASH" ]; then
    log_pass "Check 9: Versioned exam roster published (v1, hash=${ROSTER_HASH:0:16}...)"
else
    log_fail "Check 9 Failed: $PUB_ROSTER_RESP"
fi

# 14. Real-Time Exam Access Gate (/api/v1/examinations/{id}/eligibility/{studentId})
# Case A: Approved student in published roster (Student 1) -> Access Granted
GATE_STU1=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${EXAM_ID}/eligibility/${STU1_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$GATE_STU1" | grep -q '"access_granted":true'; then
    log_pass "Check 10a: Exam access GRANTED for approved rostered student (Aarav Sharma)"
else
    log_fail "Check 10a Failed: $GATE_STU1"
fi

# Case B: Rejected student NOT in roster (Student 3) -> Access Denied (403)
GATE_STU3=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${EXAM_ID}/eligibility/${STU3_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$GATE_STU3" | grep -q '"access_granted":false'; then
    log_pass "Check 10b: Exam access DENIED for non-rostered/rejected student"
else
    log_fail "Check 10b Failed - access granted to rejected student: $GATE_STU3"
fi

# Case C: Re-verify access failure if student status changed to suspended
curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU1_ROLL}\",\"name\":\"Aarav Sharma\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"suspended\",\"institution_id\":\"${INST_ID}\"}" > /dev/null

GATE_SUSPENDED=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${EXAM_ID}/eligibility/${STU1_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$GATE_SUSPENDED" | grep -q "suspended"; then
    log_pass "Check 10c: Exam access dynamically revoked when student status is suspended"
else
    log_fail "Check 10c Failed: $GATE_SUSPENDED"
fi

# Restore student 1 to active
curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU1_ROLL}\",\"name\":\"Aarav Sharma\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"institution_id\":\"${INST_ID}\"}" > /dev/null

# 15. Verify Audit Logs
AUDIT_ENTRIES=$(bash -c "/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -t -c \"SELECT COUNT(*) FROM registration_audit_logs WHERE examination_id = '${EXAM_ID}';\"")
AUDIT_COUNT=$(echo "$AUDIT_ENTRIES" | tr -d '[:space:]')

if [ "$AUDIT_COUNT" -gt 0 ]; then
    log_pass "Check 11: Registration and eligibility audit trail recorded (${AUDIT_COUNT} entries)"
else
    log_fail "Check 11 Failed: No audit entries found"
fi

echo "======================================================================"
echo " Module 10 Test Results: ${PASS_COUNT} Passed, ${FAIL_COUNT} Failed"
echo "======================================================================"

if [ "$FAIL_COUNT" -eq 0 ]; then
    exit 0
else
    exit 1
fi
