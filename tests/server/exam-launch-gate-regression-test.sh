#!/usr/bin/env bash
# =============================================================================
# ExamOS / SPPIO — Exam launch authorization gate regression test
#
# The /api/v1/exam-launch/authorize endpoint hands the kiosk an individually
# assigned external exam URL and a one-time launch token. This test guards the
# properties that keep that hand-off safe:
#   1. the caller must be an authenticated, institution-scoped operator;
#   2. the examination must belong to the caller's institution (except for the
#      platform owner);
#   3. the delivered URL must pass the approved-exam-URL validator;
#   4. a failure to persist the session or launch token must fail closed;
#   5. no fabricated fallback institution may be substituted;
#   6. a launch token must never fall back to a non-CSPRNG.
#
# When EXAMOS_TEST_BASE_URL points at a live server, the test also proves that
# an unauthenticated request is rejected with 401 and never returns a token.
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$WORKSPACE/server/controllers/device_trust_controller.c"
fail=0

check_contains() {
    local pattern="$1" description="$2"
    if ! grep -Fq -- "$pattern" "$SRC"; then
        printf '[LAUNCH-GATE] FAIL: %s (missing: %s)\n' "$description" "$pattern" >&2
        fail=1
    fi
}

check_absent() {
    local pattern="$1" description="$2"
    if grep -Fq -- "$pattern" "$SRC"; then
        printf '[LAUNCH-GATE] FAIL: %s (found forbidden: %s)\n' "$description" "$pattern" >&2
        fail=1
    fi
}

if [[ ! -s "$SRC" ]]; then
    printf '[LAUNCH-GATE] FAIL: source file missing: %s\n' "$SRC" >&2
    exit 1
fi

# Extract the launch-authorization block so the checks cannot be satisfied by
# unrelated code elsewhere in the file.
BLOCK="$(awk '/POST \/api\/v1\/exam-launch\/authorize/ {found=1} found {print}' "$SRC")"
if [[ -z "$BLOCK" ]]; then
    printf '[LAUNCH-GATE] FAIL: could not locate the launch authorization handler\n' >&2
    exit 1
fi

block_contains() {
    local pattern="$1" description="$2"
    if ! printf '%s\n' "$BLOCK" | grep -Fq -- "$pattern"; then
        printf '[LAUNCH-GATE] FAIL: %s (missing: %s)\n' "$description" "$pattern" >&2
        fail=1
    fi
}

block_absent() {
    local pattern="$1" description="$2"
    if printf '%s\n' "$BLOCK" | grep -Fq -- "$pattern"; then
        printf '[LAUNCH-GATE] FAIL: %s (found forbidden: %s)\n' "$description" "$pattern" >&2
        fail=1
    fi
}

# 1. Authentication is mandatory before any trust evaluation.
block_contains 'if (auth_rc != 0)' 'launch gate must require an authenticated session'
block_contains 'Authentication is required to authorize an exam launch' \
    'launch gate must return an explicit authentication error'

# 2. Institution scope.
block_contains 'sess.role != ROLE_PLATFORM_OWNER' 'launch gate must apply tenant scoping'
block_contains 'strcmp(ex_inst, sess.institution_id) != 0' \
    'launch gate must reject cross-tenant examinations'

# 3. Approved URL validation before delivery.
block_contains 'platform_validate_exam_url(ex_url' \
    'launch gate must validate the exam URL before delivering it'

# 4. Persistence failures must fail closed.
block_contains 'int session_saved' 'launch gate must check the session insert result'
block_contains 'int launch_saved' 'launch gate must check the launch-token insert result'
block_contains 'Could not persist the exam session; launch was not authorized' \
    'launch gate must refuse to authorize when the session cannot be stored'
block_contains 'Could not persist the launch authorization; launch was not authorized' \
    'launch gate must refuse to authorize when the token cannot be stored'

# 5. No fabricated tenant fallback.
check_absent 'inst_vignan' 'launch path must not fall back to a hard-coded institution'

# 6. Fail closed if the CSPRNG is unavailable.
block_contains 'Secure launch token generation failed; launch was not authorized' \
    'launch gate must fail closed when RAND_bytes fails'
block_absent 'rand() % 256' 'launch token must never fall back to rand()'

if [[ "$fail" -ne 0 ]]; then
    printf '[LAUNCH-GATE] FAIL: exam launch gate regression checks failed.\n' >&2
    exit 1
fi
printf '[LAUNCH-GATE] PASS: static launch-gate checks passed.\n'

# -----------------------------------------------------------------------------
# Optional live check: unauthenticated launch must be rejected.
# -----------------------------------------------------------------------------
if [[ -n "${EXAMOS_TEST_BASE_URL:-}" ]]; then
    printf '[LAUNCH-GATE] Running live unauthenticated check against %s\n' "$EXAMOS_TEST_BASE_URL"
    response_file="$(mktemp)"
    trap 'rm -f "$response_file"' EXIT
    http_code="$(curl -sS -o "$response_file" -w '%{http_code}' \
        -X POST "$EXAMOS_TEST_BASE_URL/api/v1/exam-launch/authorize" \
        -H 'Content-Type: application/json' \
        -d '{"device_id":"dev_regression","student_id":"stu_regression","examination_id":"exam_regression"}' \
        || true)"
    body="$(cat "$response_file")"
    if [[ "$http_code" != "401" ]]; then
        printf '[LAUNCH-GATE] FAIL: unauthenticated launch expected HTTP 401, got %s (%s)\n' \
            "$http_code" "$body" >&2
        exit 1
    fi
    if printf '%s' "$body" | grep -q 'launch_token'; then
        printf '[LAUNCH-GATE] FAIL: unauthenticated launch response leaked a launch token\n' >&2
        exit 1
    fi
    printf '[LAUNCH-GATE] PASS: unauthenticated launch rejected with 401 and no token.\n'
else
    printf '[LAUNCH-GATE] NOT TESTED: live unauthenticated check (set EXAMOS_TEST_BASE_URL to run it).\n'
fi
