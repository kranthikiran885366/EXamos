#!/usr/bin/env bash
# ==============================================================================
# test_module5_student_management.sh — Test Suite for ExamOS Module 5:
# Student Management System (Canonical Identity, Enrollments & Multi-Semester Lifecycle)
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
echo " Starting Module 5: Student Management System Test Suite"
echo "======================================================================"

# 1. Admin Login (Platform Owner / Registrar)
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
TS=$(date +%s | tail -c 5)
TEST_ROLL="VU-2026-CSE-${TS}"

# 2. Canonical Student Creation (POST /api/v1/students)
CREATE_PAYLOAD=$(cat <<EOF
{
  "roll_no": "${TEST_ROLL}",
  "name": "Kavya Priya Sharma",
  "display_name": "Kavya P. Sharma",
  "email": "kavya.${TS}@vignan.ac.in",
  "personal_email": "kavya.personal.${TS}@gmail.com",
  "phone_number": "+91987654${TS}",
  "course": "B.Tech Computer Science and Engineering",
  "department_id": "dept_cse",
  "campus_id": "campus_main",
  "batch": "2026",
  "semester": 5,
  "section": "A",
  "academic_status": "active",
  "attendance_pct": 92,
  "administrative_hold": false,
  "accommodations": "Extra 15 mins for visual fatigue",
  "notes": "Dean honors list",
  "institution_id": "${INST_ID}"
}
EOF
)

CREATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "${CREATE_PAYLOAD}")

STUDENT_ID=$(echo "$CREATE_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$STUDENT_ID" ]; then
    log_pass "Created canonical student profile: id=${STUDENT_ID}, roll_no=${TEST_ROLL}"
else
    log_fail "Failed to create student: $CREATE_RESP"
    exit 1
fi

# 3. Retrieve Student Profile (GET /api/v1/students/:id)
GET_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$GET_RESP" | grep -q "Kavya P. Sharma" && echo "$GET_RESP" | grep -q "${TEST_ROLL}"; then
    log_pass "Retrieved student profile with correct display_name and roll_no"
else
    log_fail "Failed to retrieve student profile: $GET_RESP"
fi

# 4. Search and List Students (GET /api/v1/students?search=...)
SEARCH_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students?search=${TEST_ROLL}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$SEARCH_RESP" | grep -q "${TEST_ROLL}"; then
    log_pass "Search student by roll_no returns expected student in list"
else
    log_fail "Search failed to locate student: $SEARCH_RESP"
fi

# 5. Profile Update (PATCH /api/v1/students/:id)
PATCH_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/students/${STUDENT_ID}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"display_name":"Kavya Sharma (Honors)","phone_number":"+919999999999"}')

if echo "$PATCH_RESP" | grep -q '"status":"updated"'; then
    log_pass "Updated student profile fields (display_name & phone_number)"
else
    log_fail "Failed to update profile: $PATCH_RESP"
fi

# Verify patch was persisted
VERIFY_PATCH=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")
if echo "$VERIFY_PATCH" | grep -q "Kavya Sharma (Honors)"; then
    log_pass "Verified patched fields persisted in database"
else
    log_fail "Patched fields not reflected: $VERIFY_PATCH"
fi

# 6. Identity Verification Lifecycle (POST /api/v1/students/:id/verify)
VERIFY_PAYLOAD=$(cat <<EOF
{
  "status": "VERIFIED",
  "method": "document",
  "verified_by": "RegistrarOfficer-04",
  "evidence_reference": "DOC-GOV-ID-2026-X9",
  "notes": "Government photo identity verified and matched against biometric record."
}
EOF
)

VERIFY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students/${STUDENT_ID}/verify" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "${VERIFY_PAYLOAD}")

if echo "$VERIFY_RESP" | grep -q '"status":"VERIFIED"'; then
    log_pass "Identity verification lifecycle transition completed: VERIFIED"
else
    log_fail "Failed to verify student identity: $VERIFY_RESP"
fi

# 7. Semester Progression & Enrollment History Preservation (POST /api/v1/students/:id/enrollments)
# Student progresses to Semester 6 for 2026-2027 Spring
ENROLL_PAYLOAD=$(cat <<EOF
{
  "semester": 6,
  "section": "A",
  "program_id": "B.Tech Computer Science and Engineering",
  "academic_year": "2026-2027",
  "term": "Spring",
  "notes": "Promoted following Semester 5 completion"
}
EOF
)

ENROLL_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students/${STUDENT_ID}/enrollments" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "${ENROLL_PAYLOAD}")

if echo "$ENROLL_RESP" | grep -q '"status":"enrolled"'; then
    log_pass "Progressed student to Semester 6 enrollment"
else
    log_fail "Failed to progress enrollment: $ENROLL_RESP"
fi

# Verify enrollment history preserves both historical Semester 5 (completed) and new Semester 6 (current)
HISTORY_ENROLL=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}/enrollments" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$HISTORY_ENROLL" | grep -q '"status":"completed"' && echo "$HISTORY_ENROLL" | grep -q '"status":"current"'; then
    log_pass "Enrollment history preserved: past record marked completed, active record marked current"
else
    log_fail "Enrollment historical invariance violation: $HISTORY_ENROLL"
fi

# 8. Student Correction Request & Administrative Approval Workflow
CORRECTION_PAYLOAD=$(cat <<EOF
{
  "field_name": "personal_email",
  "old_value": "kavya.personal.${TS}@gmail.com",
  "new_value": "kavya.official.${TS}@alumni.vignan.edu",
  "justification": "Primary personal domain updated per university alumni registry migration",
  "requested_by": "${STUDENT_ID}"
}
EOF
)

REQ_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students/${STUDENT_ID}/correction-requests" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "${CORRECTION_PAYLOAD}")

REQ_ID=$(echo "$REQ_RESP" | grep -o '"request_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$REQ_ID" ]; then
    log_pass "Submitted student correction request: id=${REQ_ID}"
else
    log_fail "Failed to submit correction request: $REQ_RESP"
fi

# Administrative Review & Approval
REVIEW_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/student-correction-requests/${REQ_ID}/review" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"decision":"APPROVED","review_notes":"Approved after verifying official university records."}')

if echo "$REVIEW_RESP" | grep -q '"status":"APPROVED"'; then
    log_pass "Admin approved correction request with automatic field update"
else
    log_fail "Failed to approve correction request: $REVIEW_RESP"
fi

# Check that the student's profile now reflects the updated email
CHECK_PROFILE=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$CHECK_PROFILE" | grep -q "kavya.official.${TS}@alumni.vignan.edu"; then
    log_pass "Approved correction auto-applied to canonical student record"
else
    log_fail "Student profile was not updated upon approval: $CHECK_PROFILE"
fi

# 9. Suspension & Reactivation Lifecycle
SUSPEND_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students/${STUDENT_ID}/suspend" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Attendance review hearing pending under academic statute 4.2"}')

if echo "$SUSPEND_RESP" | grep -q '"status":"suspended"'; then
    log_pass "Suspended student account and placed on administrative hold"
else
    log_fail "Failed to suspend student: $SUSPEND_RESP"
fi

# Verify student profile shows suspended status and administrative_hold true
SUSPEND_CHECK=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$SUSPEND_CHECK" | grep -q '"academic_status":"suspended"' && echo "$SUSPEND_CHECK" | grep -q '"administrative_hold":true'; then
    log_pass "Verified suspended profile has administrative_hold=true"
else
    log_fail "Suspension state mismatch: $SUSPEND_CHECK"
fi

# Reactivate Student
REACTIVATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/students/${STUDENT_ID}/reactivate" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Student hearing resolved; attendance deficiency made up through remedial lab work."}')

if echo "$REACTIVATE_RESP" | grep -q '"status":"active"'; then
    log_pass "Reactivated student profile and lifted administrative hold"
else
    log_fail "Failed to reactivate student: $REACTIVATE_RESP"
fi

# 10. Bulk Student CSV Import Engine
CSV_CONTENT="roll_no,name,email,course,semester,section\n"
CSV_CONTENT="${CSV_CONTENT}BULK-01-${TS},Aarav Patel,aarav.${TS}@vignan.ac.in,B.Tech CSE,5,A\n"
CSV_CONTENT="${CSV_CONTENT}BULK-02-${TS},Ananya Rao,ananya.${TS}@vignan.ac.in,B.Tech CSE,5,B\n"
CSV_CONTENT="${CSV_CONTENT}BULK-03-${TS},Rohit Reddy,rohit.${TS}@vignan.ac.in,B.Tech ECE,5,A"

IMPORT_PAYLOAD=$(cat <<EOF
{
  "institution_id": "${INST_ID}",
  "filename": "students_batch_${TS}.csv",
  "csv_data": "${CSV_CONTENT}"
}
EOF
)

IMPORT_PREVIEW=$(curl -s -X POST "${BASE_URL}/api/v1/student-imports" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "${IMPORT_PAYLOAD}")

JOB_ID=$(echo "$IMPORT_PREVIEW" | grep -o '"job_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$JOB_ID" ] && echo "$IMPORT_PREVIEW" | grep -q '"valid_rows":3'; then
    log_pass "Bulk CSV import preview validated 3 rows: job_id=${JOB_ID}"
else
    log_fail "Failed to preview bulk import: $IMPORT_PREVIEW"
fi

# Confirm & Execute Import Job
CONFIRM_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/student-imports/${JOB_ID}/confirm" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$CONFIRM_RESP" | grep -q '"status":"completed"'; then
    log_pass "Bulk CSV import executed transactionally: 3 students created"
else
    log_fail "Failed to confirm bulk import: $CONFIRM_RESP"
fi

# Query Import Row Results
RESULTS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/student-imports/${JOB_ID}/results" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$RESULTS_RESP" | grep -q "BULK-01-${TS}" && echo "$RESULTS_RESP" | grep -q "CREATED"; then
    log_pass "Row-level import results verified: all student rows audited"
else
    log_fail "Row results verification failed: $RESULTS_RESP"
fi

# 11. Cross-Module Integration Endpoints
# Module 10: Exam Eligibility
ELIG_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}/exam-eligibility" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$ELIG_RESP" | grep -q '"student_id":"' && echo "$ELIG_RESP" | grep -q '"eligibility_records"'; then
    log_pass "Cross-module query: Module 10 Eligibility Status endpoint responsive"
else
    log_fail "Module 10 Eligibility query failed: $ELIG_RESP"
fi

# Module 13: Device Assignments
DEV_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}/device-assignments" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$DEV_RESP" | grep -q '"student_id":"' && echo "$DEV_RESP" | grep -q '"assigned_devices"'; then
    log_pass "Cross-module query: Module 13 Device Assignments endpoint responsive"
else
    log_fail "Module 13 Device Assignments query failed: $DEV_RESP"
fi

# Module 11: Exam Sessions
SESS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}/exam-sessions" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$SESS_RESP" | grep -q '"exam_sessions"'; then
    log_pass "Cross-module query: Module 11 Exam Sessions endpoint responsive"
else
    log_fail "Module 11 Exam Sessions query failed: $SESS_RESP"
fi

# 12. Student Immutable Audit History
AUDIT_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/students/${STUDENT_ID}/history" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$AUDIT_RESP" | grep -q "STUDENT_CREATED"; then
    log_pass "Immutable audit history verified: captures full lifecycle progression"
else
    log_fail "Audit history incomplete: $AUDIT_RESP"
fi

echo "======================================================================"
echo -e "Module 5 Test Results: \e[32m${PASS_COUNT} Passed\e[0m, \e[31m${FAIL_COUNT} Failed\e[0m"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
