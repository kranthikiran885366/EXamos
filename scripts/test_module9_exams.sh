#!/usr/bin/env bash
# ==============================================================================
# test_module9_exams.sh — Test Suite for ExamOS Module 9: Examination Management
# Validates 9-stage lifecycle, separation of duties, schedules, OS policy,
# student assignments, real-time monitoring, and tenant isolation.
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
echo " Starting Module 9: Examination Management Test Suite"
echo "======================================================================"

# 1. Admin Login (Creator)
LOGIN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"StrongAdminPassword#2026!"}')

TOKEN_ADMIN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -n "$TOKEN_ADMIN" ]; then
    log_pass "Admin login successful (Creator)"
else
    log_fail "Admin login failed: $LOGIN_RESP"
    exit 1
fi

# 2. Root Login (Approver / Different Admin)
ROOT_LOGIN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"Exam0S!Root#2026"}')

echo "ROOT_LOGIN_RESP: $ROOT_LOGIN_RESP"
TOKEN_ROOT=$(echo "$ROOT_LOGIN_RESP" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -n "$TOKEN_ROOT" ]; then
    log_pass "Root login successful (Approver)"
else
    log_fail "Root login failed: $ROOT_LOGIN_RESP"
    exit 1
fi

# 3. Create Examination (Stage 1: Draft)
CREATE_JSON=$(cat <<EOF
{
  "name": "Java Programming – Semester 5 – 100 Marks",
  "subject": "Java Programming",
  "code": "JAVA-M9-$(date +%s | tail -c 5)",
  "academic_year": "2026-2027",
  "exam_type": "final",
  "duration_minutes": 120,
  "total_marks": 100,
  "passing_marks": 40,
  "instructions": "Standard ExamOS lockdown rules apply. Use of unauthorized devices prohibited.",
  "exam_url": "https://exam.vignan.edu/java501",
  "institution_id": "inst_vignan"
}
EOF
)

CREATE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "$CREATE_JSON")

EXAM_ID=$(echo "$CREATE_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)
EXAM_STATUS=$(echo "$CREATE_RESP" | grep -o '"lifecycle_status":"[^"]*' | cut -d'"' -f4)

if [ -n "$EXAM_ID" ] && [ "$EXAM_STATUS" = "draft" ]; then
    log_pass "Stage 1 (Draft): Exam created with id=${EXAM_ID}"
else
    log_fail "Stage 1 (Draft) creation failed: $CREATE_RESP"
    exit 1
fi

# 4. List Examinations
LIST_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/examinations" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$LIST_RESP" | grep -q "$EXAM_ID"; then
    log_pass "GET /api/v1/examinations includes newly created exam"
else
    log_fail "GET /api/v1/examinations missing exam: $LIST_RESP"
fi

# 5. Add Schedule Session
NOW=$(date +%s)
START_TIME=$((NOW + 7200 + (RANDOM % 10000) * 10))
END_TIME=$((START_TIME + 7200))
ROOM_ID="room_lab_$(date +%s | tail -c 4)"

SCHED_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/schedules" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"session_name\":\"Morning Shift - Lab A\",\"start_time\":${START_TIME},\"end_time\":${END_TIME},\"room_id\":\"${ROOM_ID}\"}")

if echo "$SCHED_RESP" | grep -q '"created"'; then
    log_pass "Schedule session added (Lab A, duration 2h)"
else
    log_fail "Failed to add schedule session: $SCHED_RESP"
fi

# 6. Configure ExamOS Appliance Policy
POLICY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/policy" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"required_os_release":"ExamOS-2026.1","permitted_application":"examos-kiosk-browser","require_tpm":true,"require_secure_boot":true,"kiosk_lockdown":true,"block_usb":true}')

if echo "$POLICY_RESP" | grep -q '"configured"'; then
    log_pass "ExamOS appliance policy configured (TPM 2.0, SecureBoot, Kiosk lockdown)"
else
    log_fail "Failed to configure policy: $POLICY_RESP"
fi

# 7. Assign Students
STUDENT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/students" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"student_id":"stu_1001","roll_no":"22B91A0501","name":"Aarav Sharma","room_id":"room_lab_a","seat_no":"A-12"}')

if echo "$STUDENT_RESP" | grep -q '"assigned"'; then
    log_pass "Student assignment created (Aarav Sharma - 22B91A0501)"
else
    log_fail "Failed to assign student: $STUDENT_RESP"
fi

# 8. Transition Stage 1 -> 2: Configured
CONF_RESP=$(curl -s -X PATCH "${BASE_URL}/api/v1/examinations/${EXAM_ID}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"status":"configured"}')

if echo "$CONF_RESP" | grep -q '"updated"'; then
    log_pass "Stage 2 (Configured): Exam rules, duration, participants defined"
else
    log_fail "Failed to transition to configured: $CONF_RESP"
fi

# 9. Transition Stage 2 -> 3: Submit for Approval (Pending Approval)
SUBMIT_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/submit-for-approval" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$SUBMIT_RESP" | grep -q '"pending_approval"'; then
    log_pass "Stage 3 (Pending Approval): Exam submitted for authorized review"
else
    log_fail "Failed to submit for approval: $SUBMIT_RESP"
fi

# 10. Separation of Duties Check: Creator (admin) CANNOT approve their own exam
SELF_APPROVE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/approve" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$SELF_APPROVE_RESP" | grep -q "Separation of duties"; then
    log_pass "Separation of Duties Enforced: Creator prevented from approving own exam"
else
    log_fail "Separation of Duties FAILED - Creator was allowed to approve: $SELF_APPROVE_RESP"
fi

# 11. Stage 4: Authorized Reviewer (root) Approves
ROOT_APPROVE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/approve" \
    -H "Authorization: Bearer ${TOKEN_ROOT}")

if echo "$ROOT_APPROVE_RESP" | grep -q '"approved"'; then
    log_pass "Stage 4 (Approved): Authorized approver (root) approved examination"
else
    log_fail "Approval by root failed: $ROOT_APPROVE_RESP"
fi

# 12. Stage 5: Publish / Schedule
PUB_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/publish" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$PUB_RESP" | grep -q '"scheduled"'; then
    log_pass "Stage 5 (Scheduled / Published): Exam date and access communicated"
else
    log_fail "Publish/Schedule failed: $PUB_RESP"
fi

# 13. Stage 6: Mark Ready (Pre-exam checks completed)
READY_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/ready" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$READY_RESP" | grep -q '"ready"'; then
    log_pass "Stage 6 (Ready): Device trust and pre-exam readiness verified"
else
    log_fail "Mark ready failed: $READY_RESP"
fi

# 14. Stage 7: Start Exam (In Progress / Live)
START_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/start" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$START_RESP" | grep -q '"in_progress"'; then
    log_pass "Stage 7 (In Progress): Exam delivery active"
else
    log_fail "Start exam failed: $START_RESP"
fi

# 15. Check Real-Time Attempt Status Monitoring
STATUS_RESP=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${EXAM_ID}/status" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$STATUS_RESP" | grep -q '"attempts"'; then
    log_pass "Real-time monitoring status queried successfully: $STATUS_RESP"
else
    log_fail "Failed to query status monitoring: $STATUS_RESP"
fi

# 16. Stage 8: Close Examination
CLOSE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/close" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$CLOSE_RESP" | grep -q '"closed"'; then
    log_pass "Stage 8 (Closed): Submissions collected and attempts frozen"
else
    log_fail "Close exam failed: $CLOSE_RESP"
fi

# 17. Stage 9: Finalize Examination (Permanent Lock)
FINALIZE_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${EXAM_ID}/finalize" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}")

if echo "$FINALIZE_RESP" | grep -q '"finalized"'; then
    log_pass "Stage 9 (Finalized): Results reconciled and exam locked permanently"
else
    log_fail "Finalize exam failed: $FINALIZE_RESP"
fi

# 18. Test Cancellation Flow with 8+ char requirement
CANCEL_EXAM_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"To Cancel Exam\",\"subject\":\"Testing\",\"code\":\"CAN-$(date +%s | tail -c 5)\",\"duration_minutes\":60}")

CANCEL_ID=$(echo "$CANCEL_EXAM_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)

# Short reason rejection test (< 8 chars)
SHORT_CAN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${CANCEL_ID}/cancel" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"rain"}')

if echo "$SHORT_CAN_RESP" | grep -q "minimum 8 characters"; then
    log_pass "Cancellation rejected when reason < 8 characters"
else
    log_fail "Short cancellation reason was not rejected: $SHORT_CAN_RESP"
fi

# Valid cancellation test (>= 8 chars)
VALID_CAN_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations/${CANCEL_ID}/cancel" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d '{"reason":"Severe power grid failure and campus evacuation"}')

if echo "$VALID_CAN_RESP" | grep -q '"cancelled"'; then
    log_pass "Exam successfully cancelled with recorded reason >= 8 chars"
else
    log_fail "Valid cancellation failed: $VALID_CAN_RESP"
fi

# 19. Multi-Tenant Isolation Test
# Provision two scoped tenant admins: Inst A (vignan) vs Inst B (gitam)
TENANT_A_RESP=$(curl -s -X POST "${BASE_URL}/api/v1/examinations" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN_ADMIN}" \
    -d "{\"name\":\"Vignan Midterm Exam\",\"subject\":\"Data Structures\",\"code\":\"VIG-DS-$(date +%s | tail -c 4)\",\"duration_minutes\":90,\"institution_id\":\"inst_vignan\"}")
TENANT_A_ID=$(echo "$TENANT_A_RESP" | grep -o '"exam_id":"[^"]*' | cut -d'"' -f4)

# Create a tenant admin session scoped to inst_gitam in postgres
bash -c "/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -c \"
INSERT INTO examos_admin_users (user_id, username, password_hash, full_name, email, role, institution_id, active, mfa_enabled)
VALUES ('usr_gitam_admin', 'gitam_admin', '310000:d52abc412bf0f6f47a17e8fbaa240292:931722f49f380ffc3f4401e072fdbf88c997a1e6ea1b0dff146bc56e35f933b7', 'Gitam Admin', 'admin@gitam.edu', 2, 'inst_gitam', true, false)
ON CONFLICT (username) DO UPDATE SET institution_id = 'inst_gitam', role = 2, active = true, mfa_enabled = false;
\"" > /dev/null 2>&1

GITAM_LOGIN=$(curl -s -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gitam_admin","password":"StrongAdminPassword#2026!"}')
TOKEN_GITAM=$(echo "$GITAM_LOGIN" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Test cross-tenant reading
CROSS_READ=$(curl -s -X GET "${BASE_URL}/api/v1/examinations/${TENANT_A_ID}" \
    -H "Authorization: Bearer ${TOKEN_GITAM}")

if echo "$CROSS_READ" | grep -q "Access to other institution's exam is prohibited"; then
    log_pass "Multi-Tenant Isolation Enforced: Gitam admin cannot access Vignan exam"
else
    log_fail "Multi-Tenant Isolation FAILED: Gitam read Vignan exam: $CROSS_READ"
fi

# Clean up temporary gitam user
bash -c "/usr/lib/postgresql/18/bin/psql -h /tmp -p 5433 -U examos_bootstrap -d examos -c \"DELETE FROM examos_admin_users WHERE username = 'gitam_admin'; DELETE FROM users WHERE username = 'gitam_admin';\"" > /dev/null 2>&1

echo "======================================================================"
echo " Module 9 Test Results: ${PASS_COUNT} Passed, ${FAIL_COUNT} Failed"
echo "======================================================================"

if [ "$FAIL_COUNT" -eq 0 ]; then
    exit 0
else
    exit 1
fi
