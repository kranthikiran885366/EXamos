#!/usr/bin/env bash
# =============================================================================
# ExamOS / SPPIO — Exam URL delivery regression test
#
# SPPIO's only delivery responsibility is handing a candidate the individually
# assigned external assessment URL. That URL is attacker-relevant input once it
# is stored in the database, so every path that returns it must validate it:
#   * candidate TPM-attested check-in (auth_controller.c)
#   * legacy candidate login (auth_controller.c)
#   * exam-session authorization (exam_session_controller.c)
#
# The test also guards adjacent defects fixed in the same audit: a username
# based platform-owner fallback and a placeholder session id in the
# already-closed response.
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUTH="$WORKSPACE/server/controllers/auth_controller.c"
SESSION="$WORKSPACE/server/controllers/exam_session_controller.c"
PLATFORM="$WORKSPACE/server/admin/enterprise_platform.c"
MAIN="$WORKSPACE/server/main.c"
fail=0

fail_msg() {
    printf '[URL-DELIVERY] FAIL: %s\n' "$1" >&2
    fail=1
}

require_file() {
    if [[ ! -s "$1" ]]; then
        printf '[URL-DELIVERY] FAIL: source file missing or empty: %s\n' "$1" >&2
        exit 1
    fi
}

require_file "$AUTH"
require_file "$SESSION"

# ---------------------------------------------------------------------------
# 1. Both controllers must use the shared approved-URL validator.
# ---------------------------------------------------------------------------
if ! grep -Fq '#include "../include/enterprise_platform.h"' "$AUTH"; then
    fail_msg "auth_controller.c must include the enterprise platform URL validator"
fi
if ! grep -Fq 'platform_validate_exam_url(' "$AUTH"; then
    fail_msg "auth_controller.c never calls platform_validate_exam_url"
fi
if ! grep -Fq 'platform_validate_exam_url(' "$SESSION"; then
    fail_msg "exam_session_controller.c never calls platform_validate_exam_url"
fi

# ---------------------------------------------------------------------------
# 2. Candidate check-in: validation must happen before the URL is delivered.
# ---------------------------------------------------------------------------
CHECKIN_BLOCK="$(awk '/CANDIDATE_CHECKIN_TPM_ATTESTED/ {print}' "$AUTH")"
CHECKIN_VALIDATION_LINE="$(grep -n 'platform_validate_exam_url(exam_url' "$AUTH" | head -1 | cut -d: -f1 || true)"
CHECKIN_DELIVERY_LINE="$(grep -n 'candidate_success_response(client_fd, token' "$AUTH" | head -1 | cut -d: -f1 || true)"
if [[ -z "$CHECKIN_VALIDATION_LINE" ]]; then
    fail_msg "candidate check-in path does not validate exam_url"
elif [[ -z "$CHECKIN_DELIVERY_LINE" ]]; then
    fail_msg "could not locate the candidate check-in success response"
elif (( CHECKIN_VALIDATION_LINE > CHECKIN_DELIVERY_LINE )); then
    fail_msg "candidate check-in validates exam_url after it is delivered"
fi
if ! grep -Fq 'CANDIDATE_EXAM_URL_REJECTED' "$AUTH"; then
    fail_msg "rejected check-in exam URLs must be audited"
fi

# ---------------------------------------------------------------------------
# 3. Legacy candidate login: same rule.
# ---------------------------------------------------------------------------
LOGIN_VALIDATION_LINE="$(grep -n 'platform_validate_exam_url(exam_url' "$AUTH" | tail -1 | cut -d: -f1 || true)"
# The legacy login response is emitted after the shared delivery function or the
# login handler's JSON response; use the second delivery site as the marker.
LOGIN_DELIVERY_LINE="$(grep -n 'candidate_success_response(client_fd, token' "$AUTH" | tail -1 | cut -d: -f1 || true)"
if [[ -z "$LOGIN_VALIDATION_LINE" ]]; then
    fail_msg "legacy login path does not validate exam_url"
elif [[ -z "$LOGIN_DELIVERY_LINE" ]]; then
    fail_msg "could not locate the legacy login delivery path"
elif (( LOGIN_VALIDATION_LINE > LOGIN_DELIVERY_LINE )); then
    fail_msg "legacy login validates exam_url after it is delivered"
fi

# ---------------------------------------------------------------------------
# 4. Exam-session authorization must validate before returning the URL.
# ---------------------------------------------------------------------------
SESSION_VALIDATION_LINE="$(grep -n 'platform_validate_exam_url(exam_url' "$SESSION" | head -1 | cut -d: -f1 || true)"
SESSION_DELIVERY_LINE="$(grep -nF '\"exam_url\":\"%s\"' "$SESSION" | head -1 | cut -d: -f1 || true)"
if [[ -z "$SESSION_VALIDATION_LINE" ]]; then
    fail_msg "exam_session_controller.c does not validate exam_url"
elif [[ -z "$SESSION_DELIVERY_LINE" ]]; then
    fail_msg "could not locate the exam-session URL response"
elif (( SESSION_VALIDATION_LINE > SESSION_DELIVERY_LINE )); then
    fail_msg "exam session returns exam_url before validating it"
fi
if ! grep -Fq 'A valid, approved external assessment URL is not configured' "$SESSION"; then
    fail_msg "exam session must fail closed with an explicit URL error"
fi

# ---------------------------------------------------------------------------
# 5. No username-based platform-owner escalation.
# ---------------------------------------------------------------------------
if grep -Eq 'strcmp\(sess\.username, "(admin|root)"\)' "$SESSION"; then
    fail_msg "platform owner must be derived from ROLE_PLATFORM_OWNER, not a username"
fi

# ---------------------------------------------------------------------------
# 6. Closed sessions must return the real identifier.
# ---------------------------------------------------------------------------
if grep -Fq 'already_closed\",\"session_id\":\"...\"' "$SESSION"; then
    fail_msg "already-closed response must not contain a placeholder session id"
fi
if ! grep -Fq 'already_closed\",\"session_id\":\"%s\"' "$SESSION"; then
    fail_msg "already-closed response must return the real session id"
fi

# ---------------------------------------------------------------------------
# 7. The write boundary must validate too, and URL updates must be tenant
#    scoped. A delivery-time check alone would still let one institution
#    persist a malicious target for another institution's exam.
# ---------------------------------------------------------------------------
require_file "$PLATFORM"
require_file "$MAIN"

UPDATE_BLOCK="$(awk '/int platform_update_exam_url\(/ {found=1} found {print} found && /^}/ {exit}' "$PLATFORM")"
if [[ -z "$UPDATE_BLOCK" ]]; then
    fail_msg "could not locate platform_update_exam_url"
else
    if ! printf '%s\n' "$UPDATE_BLOCK" | grep -Fq 'platform_validate_exam_url(new_url'; then
        fail_msg "platform_update_exam_url must validate the new URL before persisting it"
    fi
    if ! printf '%s\n' "$UPDATE_BLOCK" | grep -Fq 'platform_validate_allowed_origins(allowed_origins'; then
        fail_msg "platform_update_exam_url must validate allowed origins"
    fi
fi

if ! grep -Fq 'strcmp(sess.institution_id, exam.institution_id) != 0' "$MAIN"; then
    fail_msg "exam URL update endpoint must be tenant scoped"
fi
if ! grep -Fq 'Exam scope denied' "$MAIN"; then
    fail_msg "exam URL update endpoint must reject cross-tenant updates explicitly"
fi

if [[ "$fail" -ne 0 ]]; then
    printf '[URL-DELIVERY] FAIL: exam URL delivery regression checks failed.\n' >&2
    exit 1
fi
printf '[URL-DELIVERY] PASS: all exam URL delivery paths validate before returning the URL.\n'
