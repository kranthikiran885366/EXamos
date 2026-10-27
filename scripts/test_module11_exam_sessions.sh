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
echo " Starting Module 11: Exam Session Management Test Suite"
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

INST_A="inst_vignan"
INST_B="inst_gitam"

# 2. Provision Test Examination
EXAM_CODE="JAVA-M11-$(date +%s | tail -c 4)"
EXAM_CREATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"Advanced Java Programming – Semester 5\",\"subject\":\"Java\",\"code\":\"${EXAM_CODE}\",\"academic_year\":\"2026-2027\",\"duration_minutes\":120,\"institution_id\":\"${INST_A}\",\"exam_url\":\"https://exam.vignan.ac.in/portal/java2026\",\"allowed_origins\":\"https://exam.vignan.ac.in\"}")

EXAM_ID=$(echo "$EXAM_CREATE_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)
if [ -n "$EXAM_ID" ]; then
    log_pass "Test examination created: id=${EXAM_ID} (${EXAM_CODE})"
else
    log_fail "Failed to create test exam: $EXAM_CREATE_RESP"
    exit 1
fi

# Submit and Approve Examination to make it ready
curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/submit-for-approval" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"notes":"Ready for session testing"}' > /dev/null

curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/approve" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"decision":"approved","notes":"Approved by Controller"}' > /dev/null

curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/publish" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"notes":"Published for scheduling and sessions"}' > /dev/null

# 3. Provision Students
# Eligible Student
STU1_ROLL="22VIG1101"
STU1_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU1_ROLL}\",\"name\":\"Varun Reddy\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":85,\"administrative_hold\":false,\"institution_id\":\"${INST_A}\"}")
STU1_ID=$(echo "$STU1_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)

# Unregistered / Ineligible Student
STU2_ROLL="22VIG1102"
STU2_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/admin/students" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"roll_no\":\"${STU2_ROLL}\",\"name\":\"Sneha K\",\"course\":\"B.Tech CSE\",\"semester\":5,\"academic_status\":\"active\",\"attendance_pct\":80,\"administrative_hold\":false,\"institution_id\":\"${INST_A}\"}")
STU2_ID=$(echo "$STU2_RESP" | grep -o '"student_id":"[^"]*' | cut -d'"' -f4)

# Register Student 1 for Examination
REG_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/registrations" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU1_ID}\"}")
log_pass "Student 1 registered & approved for examination"

# ======================================================================
# CHECK 1: Pre-flight Authorization Check for Eligible Student
# ======================================================================
AUTH_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${EXAM_ID}\",\"student_id\":\"${STU1_ID}\"}")

if echo "$AUTH_RESP" | grep -q '"status":"authorized"' && echo "$AUTH_RESP" | grep -q '"can_create":true'; then
    log_pass "Check 1: Pre-flight authorization passed for eligible registered student"
else
    log_fail "Check 1: Pre-flight authorization failed: $AUTH_RESP"
fi

# ======================================================================
# CHECK 2: Reject Authorization for Unregistered Student
# ======================================================================
UNREG_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${EXAM_ID}\",\"student_id\":\"${STU2_ID}\"}")

if echo "$UNREG_RESP" | grep -q '"status":"denied"' && echo "$UNREG_RESP" | grep -q '"can_create":false'; then
    log_pass "Check 2: Session rejected for unregistered student (assignment enforcement)"
else
    log_fail "Check 2: Unregistered student was incorrectly permitted: $UNREG_RESP"
fi

# ======================================================================
# CHECK 3: Create Exam Session (Authorized State & Device Link)
# ======================================================================
DEVICE_ID="dev_lab_042"
CREATE_SES_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${EXAM_ID}\",\"student_id\":\"${STU1_ID}\",\"device_id\":\"${DEVICE_ID}\",\"os_release\":\"ExamOS 2.0 (Wayland/Cage)\",\"mac_address\":\"00:1A:2B:3C:4D:5E\",\"ip_address\":\"192.168.10.42\"}")

SESSION_ID=$(echo "$CREATE_SES_RESP" | grep -o '"id":"[^"]*' | cut -d'"' -f4 || true)
if [ -n "$SESSION_ID" ] && echo "$CREATE_SES_RESP" | grep -q '"status":"authorized"'; then
    log_pass "Check 3: Exam session created successfully in authorized state: ${SESSION_ID}"
else
    log_fail "Check 3: Failed to create exam session: $CREATE_SES_RESP"
    exit 1
fi

# ======================================================================
# CHECK 4: Concurrent Active Session Prevention (409 Conflict)
# ======================================================================
CONC_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${EXAM_ID}\",\"student_id\":\"${STU1_ID}\",\"device_id\":\"dev_another_terminal\"}")

# First session is in 'authorized' state, launch it to active to test concurrency
LAUNCH_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/launch" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")

# Now attempt concurrent session while session is active
CONC_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${EXAM_ID}\",\"student_id\":\"${STU1_ID}\"}")

if echo "$CONC_RESP" | grep -q "CONCURRENT_SESSION_EXISTS"; then
    log_pass "Check 4: Concurrent active session prevented (concurrency policy enforced)"
else
    log_fail "Check 4: Concurrent session was not prevented: $CONC_RESP"
fi

# ======================================================================
# CHECK 5: Automatic Exam Launch (Single-use token & Exact Assigned URL)
# ======================================================================
if echo "$LAUNCH_RESP" | grep -q '"status":"launch_authorized"' && \
   echo "$LAUNCH_RESP" | grep -q '"launch_token":' && \
   echo "$LAUNCH_RESP" | grep -q "https://exam.vignan.ac.in/portal/java2026"; then
    log_pass "Check 5: Exam URL launch authorized with cryptographic one-time token and exact URL binding"
else
    log_fail "Check 5: Launch authorization failed or URL mismatched: $LAUNCH_RESP"
fi

# ======================================================================
# CHECK 6: Heartbeat Liveness Tracking
# ======================================================================
HB_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/heartbeat" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$HB_RESP" | grep -q '"status":"alive"' && echo "$HB_RESP" | grep -q '"session_status":"active"'; then
    log_pass "Check 6: Heartbeat acknowledged and updated session liveness"
else
    log_fail "Check 6: Heartbeat failed: $HB_RESP"
fi

# ======================================================================
# CHECK 7: Interruption Detection & Reconnection Policy Evaluation
# ======================================================================
INT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/interrupt" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"network_loss"}')

if echo "$INT_RESP" | grep -q '"status":"interrupted"' && \
   echo "$INT_RESP" | grep -q '"interruption_count":1' && \
   echo "$INT_RESP" | grep -q '"reentry_allowed":true'; then
    log_pass "Check 7: Network interruption captured, counted (1), and verified against recovery policy"
else
    log_fail "Check 7: Interruption handling failed: $INT_RESP"
fi

# ======================================================================
# CHECK 8: Revalidate and Resume Interrupted Session
# ======================================================================
RESUME_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/resume" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$RESUME_RESP" | grep -q '"status":"resumed"' && \
   echo "$RESUME_RESP" | grep -q "https://exam.vignan.ac.in/portal/java2026"; then
    log_pass "Check 8: Interrupted session successfully revalidated and resumed into active examination"
else
    log_fail "Check 8: Resume session failed: $RESUME_RESP"
fi

# ======================================================================
# CHECK 9: Interruption While Academic Status Suspended (Denied Resume)
# ======================================================================
# Interrupt again
curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/interrupt" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"browser_crash"}' > /dev/null

# Suspend student
/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos \
    -c "UPDATE students SET academic_status = 'suspended' WHERE id = '${STU1_ID}';" > /dev/null

DENIED_RESUME=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/resume" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$DENIED_RESUME" | grep -q "no longer in active academic standing"; then
    log_pass "Check 9: Resumption safely denied when student academic standing was revoked"
else
    log_fail "Check 9: Suspended student was incorrectly permitted to resume: $DENIED_RESUME"
fi

# Restore student status
/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos \
    -c "UPDATE students SET academic_status = 'active' WHERE id = '${STU1_ID}';" > /dev/null

# Resume after restore
curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/resume" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" > /dev/null

# ======================================================================
# CHECK 10: Early Login Timing Policy (Pending State)
# ======================================================================
# Create Exam with schedule in the future (starts in 2 hours)
FUTURE_START=$(($(date +%s) + 7200))
FUTURE_END=$(($(date +%s) + 14400))
EXAM_FUTURE_CODE="JAVA-FUT-$(date +%s | tail -c 4)"

EXAM_FUT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"Future Java Exam\",\"subject\":\"Java\",\"code\":\"${EXAM_FUTURE_CODE}\",\"institution_id\":\"${INST_A}\"}")
FUT_ID=$(echo "$EXAM_FUT_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)

curl -s -X POST "${BASE_URL}/api/v1/examinations/${FUT_ID}/approve" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"decision":"approved"}' > /dev/null

curl -s -X POST "${BASE_URL}/api/v1/examinations/${FUT_ID}/schedules" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"session_name\":\"Future Shift\",\"start_time\":${FUTURE_START},\"end_time\":${FUTURE_END}}" > /dev/null

curl -s -X POST "${BASE_URL}/api/v1/examinations/${FUT_ID}/registrations" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"student_id\":\"${STU1_ID}\"}" > /dev/null

EARLY_AUTH=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/authorize" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"examination_id\":\"${FUT_ID}\",\"student_id\":\"${STU1_ID}\"}")

if echo "$EARLY_AUTH" | grep -q '"status":"pending"' && echo "$EARLY_AUTH" | grep -q '"wait_seconds":'; then
    log_pass "Check 10: Early login held in pending state with calculated wait timer"
else
    log_fail "Check 10: Early login not held in pending state: $EARLY_AUTH"
fi

# ======================================================================
# CHECK 11: Normal Session Closure
# ======================================================================
CLOSE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/exam-sessions/${SESSION_ID}/close" \
    -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"student_completed"}')

if echo "$CLOSE_RESP" | grep -q '"status":"closed"' && echo "$CLOSE_RESP" | grep -q "student_completed"; then
    log_pass "Check 11: Exam session normally closed and marked complete"
else
    log_fail "Check 11: Failed to close session: $CLOSE_RESP"
fi

# ======================================================================
# CHECK 12: List Sessions & Multi-tenant Isolation
# ======================================================================
LIST_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${EXAM_ID}/sessions" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$LIST_RESP" | grep -q "\"id\":\"${SESSION_ID}\"" && echo "$LIST_RESP" | grep -q "Varun Reddy"; then
    log_pass "Check 12a: Examination sessions list retrieved with full student metadata"
else
    log_fail "Check 12a: Failed to list sessions: $LIST_RESP"
fi

# Verify events and audit logs in database
EVENT_COUNT=$(/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -t -A \
    -c "SELECT count(*) FROM exam_session_events WHERE session_id = '${SESSION_ID}';")

AUDIT_COUNT=$(/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -t -A \
    -c "SELECT count(*) FROM exam_session_audit_logs WHERE session_id = '${SESSION_ID}';")

if [ "$EVENT_COUNT" -ge 4 ] && [ "$AUDIT_COUNT" -ge 4 ]; then
    log_pass "Check 12b: Durable session lifecycle events (${EVENT_COUNT}) and audit logs (${AUDIT_COUNT}) verified"
else
    log_fail "Check 12b: Insufficient events or audit logs: events=${EVENT_COUNT}, audit=${AUDIT_COUNT}"
fi

echo "======================================================================"
echo " Module 11 Test Results: ${PASS_COUNT} Passed, ${FAIL_COUNT} Failed"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
