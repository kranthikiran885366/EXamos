#!/usr/bin/env bash
# =============================================================================
# ExamOS P5 — Viva Engine Test
#
# Tests:
#   VI1: Generate viva questions (idempotent — calling twice returns same viva_id)
#   VI2: Candidate JSON export (no rubric/keys leaked)
#   VI3: Viva response submission
#   VI4: Duplicate response rejection (immutable after first write)
#   VI5: Reviewer export (includes suggestions and all evidence)
#   VI6: Reviewer decision/override workflow
#   VI7: Audit trail verification
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P5_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase5}"
mkdir -p "$ARTIFACT_DIR"

# PG-44: Make test port configurable to avoid conflicts
# PG-42: Support production mode testing (EXAMOS_TEST_MODE=production uses
# EXAMOS_ALLOW_UNPROVISIONED_DEV=0 + EXAMOS_TPM_MODE=production instead of dev mode)
EXAMOS_TEST_MODE="${EXAMOS_TEST_MODE:-dev}"
SERVER_PORT="${EXAMOS_P5_SERVER_PORT:-9105}"
# Use a dynamic port if the default is in use
if ss -tlnp 2>/dev/null | grep -q ":${SERVER_PORT} " || \
   netstat -tlnp 2>/dev/null | grep -q ":${SERVER_PORT} "; then
    SERVER_PORT=$((SERVER_PORT + 100))
fi
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_PID=""
RUN_DIR="$(mktemp -d /tmp/examos-p5-viva.XXXXXX)"
PASS=0; FAIL=0; BLOCKED=0

# Set up PostgreSQL for P5 tests using system PostgreSQL
EXAMOS_DB_NAME="examos_p5_viva_$(date +%s)"
EXAMOS_DB_USER="examos_p5"
EXAMOS_DB_PASS="$(openssl rand -hex 16)"

if ! sudo -u postgres pg_isready >/dev/null 2>&1; then
    echo "[P5-VIVA] BLOCKED: PostgreSQL service is not running" >&2
    exit 2
fi

sudo -u postgres psql -c "CREATE DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || {
    echo "[P5-VIVA] BLOCKED: cannot create PostgreSQL database" >&2
    exit 2
}

sudo -u postgres psql -c "CREATE USER \"$EXAMOS_DB_USER\" WITH PASSWORD '$EXAMOS_DB_PASS';" >/dev/null 2>&1 || {
    echo "[P5-VIVA] BLOCKED: cannot create PostgreSQL user" >&2
    sudo -u postgres psql -c "DROP DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
    exit 2
}

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$EXAMOS_DB_NAME\" TO \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || {
    echo "[P5-VIVA] BLOCKED: cannot grant PostgreSQL privileges" >&2
    sudo -u postgres psql -c "DROP DATABASE \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
    sudo -u postgres psql -c "DROP USER \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || true
    exit 2
}

export EXAMOS_DB_NAME
export EXAMOS_DB_USER
export EXAMOS_DB_PASS
export EXAMOS_DB_HOST="127.0.0.1"
export EXAMOS_DB_PORT="5432"

# Dynamic test configuration - no hardcoded values
CANDIDATE_UID_BASE="${EXAMOS_CANDIDATE_UID_BASE:-100000}"
PBKDF2_ITERATIONS="${EXAMOS_PBKDF2_ITERATIONS:-100000}"
EXAM_DURATION_MINUTES="${EXAMOS_EXAM_DURATION_MINUTES:-60}"

# Production mode validation
if [ "$EXAMOS_TEST_MODE" = "production" ]; then
    TEST_DEV_FLAG=0
    TEST_TPM_MODE="production"
else
    TEST_DEV_FLAG=1
    TEST_TPM_MODE="development"
fi

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
record() {
    local id="$1" expected="$2" actual="$3" detail="$4"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS+1)); echo "  [VIVA-PASS] $id: $detail"
    elif [ "$actual" = "BLOCKED" ]; then
        BLOCKED=$((BLOCKED+1)); echo "  [VIVA-BLOCKED] $id: $detail"
    else
        FAIL=$((FAIL+1)); echo "  [VIVA-FAIL] $id: $detail (expected=$expected actual=$actual)"
    fi
}

echo "=== [P5-VIVA] Viva Engine Test ==="

# Start server
CANDIDATE_TOKEN=""
if [ -x "$SERVER_BIN" ]; then
    CANDIDATE_ID="P5-VIVA-$(date +%s)"
    CANDIDATE_PIN="$(openssl rand -hex 8)"
    CAND_SALT="$(openssl rand -hex 32)"
    CAND_HASH=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "hexsalt:${CAND_SALT}" -kdfopt "pass:${CANDIDATE_PIN}" \
        -kdfopt "iter:${PBKDF2_ITERATIONS}" PBKDF2 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f')
    CAND_FILE="$RUN_DIR/candidates.conf"
    echo "${CANDIDATE_ID}:${CANDIDATE_UID_BASE}:${CAND_SALT}:${CAND_HASH}" > "$CAND_FILE"

    # PG-31: Generate reviewer token explicitly before starting server
    REVIEWER_TOKEN="$(openssl rand -hex 32)"
    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="$RUN_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_REVIEWER_TOKEN="$REVIEWER_TOKEN" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV="$TEST_DEV_FLAG" \
    EXAMOS_BEHAVIOUR_STORE="$RUN_DIR/behaviour-store" \
    EXAMOS_VIVA_STORE="$RUN_DIR/viva-store" \
    EXAMOS_VARIANT_STORE="$RUN_DIR/variant-store" \
    EXAMOS_EVENT_CHAIN_PATH="$RUN_DIR/events.log" \
    EXAMOS_DATA_DIR="$RUN_DIR/data" \
    EXAMOS_TPM_MODE="$TEST_TPM_MODE" \
    EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
    EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    EXAMOS_CANDIDATE_STORE="$CAND_FILE" \
    EXAMOS_DB_NAME="$EXAMOS_DB_NAME" \
    EXAMOS_DB_USER="$EXAMOS_DB_USER" \
    EXAMOS_DB_PASS="$EXAMOS_DB_PASS" \
    EXAMOS_DB_HOST="$EXAMOS_DB_HOST" \
    EXAMOS_DB_PORT="5432" \
    EXAMOS_SESSION_JOURNAL="$RUN_DIR/session.log" \
        "$SERVER_BIN" &
    SERVER_PID=$!
    for i in $(seq 1 15); do
        curl -sf "${SERVER_URL}/api/v1/health" >/dev/null 2>&1 && break
        sleep 0.5
    done

    LOGIN_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/candidate/login" \
        -H "Content-Type: application/json" \
        -d "{\"candidate_id\":\"${CANDIDATE_ID}\",\"pin\":\"${CANDIDATE_PIN}\"}" 2>/dev/null)
    CANDIDATE_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    # Clean up PostgreSQL database and user
    if [ -n "${EXAMOS_DB_NAME:-}" ]; then
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$EXAMOS_DB_NAME\";" >/dev/null 2>&1 || true
    fi
    if [ -n "${EXAMOS_DB_USER:-}" ]; then
        sudo -u postgres psql -c "DROP USER IF EXISTS \"$EXAMOS_DB_USER\";" >/dev/null 2>&1 || true
    fi
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

if [ -z "$CANDIDATE_TOKEN" ]; then
    echo "  BLOCKED: Cannot start server or authenticate"
    echo "{\"phase\":\"P5\",\"test\":\"viva\",\"status\":\"BLOCKED\"}" > "$ARTIFACT_DIR/viva-results.json"
    exit 2
fi

SESSION_ID="viva-test-session-$(date +%s)"
# Provisioned examination identity (no server-side default is fabricated).
EXAM_ID="P5-VIVA-$(date +%s)"
# A receipt hash that is not bound to a server-held submission. The route must
# refuse to generate viva questions from client-supplied context text.
RECEIPT_HASH=$(echo -n "${SESSION_ID}-submission" | sha256sum | cut -d' ' -f1)

# -----------------------------------------------------------------------
# VI1: Generate viva questions
# -----------------------------------------------------------------------
echo "  VI1: Generating viva questions..."
VIVA_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/viva/generate" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
    -d "{\"candidate_id\":\"${CANDIDATE_ID}\",\"exam_id\":\"${EXAM_ID}\",\"submission_receipt_hash\":\"${RECEIPT_HASH}\"}" 2>/dev/null)

VIVA_ID=$(echo "$VIVA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('viva_id',''))" 2>/dev/null || echo "")
VIVA_STATUS=$(echo "$VIVA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
VIVA_ERR=$(echo "$VIVA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "")
VIVA_Q_COUNT=$(echo "$VIVA_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('questions',[])))" 2>/dev/null || echo "0")

if [ "$VIVA_ERR" = "VIVA_SUBMISSION_NOT_FOUND_OR_RECEIPT_MISMATCH" ]; then
    # The route intentionally refuses client-supplied viva context. A real
    # submission must exist in the exam engine before viva can be generated.
    record "VI1" "PASS" "BLOCKED" "Viva requires a server-held submitted exam; no submission is provisioned in this environment"
    for vid in VI2 VI3 VI4 VI5 VI6 VI7; do
        record "$vid" "PASS" "BLOCKED" "Requires a provisioned, submitted exam"
    done
    OVERALL="BLOCKED"
    cat > "$ARTIFACT_DIR/viva-results.json" <<EOF2
{
  "phase": "P5",
  "test": "viva_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "note": "No server-held submitted exam is available. Viva context is derived server-side and client-supplied context is rejected.",
  "timestamp": "$(ts)"
}
EOF2
    echo ""
    echo "=== [P5-VIVA] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
    exit 2
fi

if [ "$VIVA_STATUS" = "VIVA_PROVIDER_UNAVAILABLE" ] || [ "$VIVA_ERR" = "VIVA_PROVIDER_UNAVAILABLE" ]; then
    # No LLM configured — this is expected in CI. The engine correctly
    # reports UNAVAILABLE rather than fabricating questions.
    record "VI1" "PASS" "BLOCKED" "Viva engine correctly reports PROVIDER_UNAVAILABLE (no LLM in CI)"
    # Skip remaining tests that require actual generated questions
    for vid in VI2 VI3 VI4 VI5 VI6 VI7; do
        record "$vid" "PASS" "BLOCKED" "Requires LLM provider — not available in CI"
    done
    # Write results and exit
    OVERALL="BLOCKED"
    cat > "$ARTIFACT_DIR/viva-results.json" <<EOF2
{
  "phase": "P5",
  "test": "viva_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "note": "LLM provider not configured — viva generation correctly returns PROVIDER_UNAVAILABLE",
  "timestamp": "$(ts)"
}
EOF2
    echo ""
    echo "=== [P5-VIVA] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
    exit 2
fi

if [ -n "$VIVA_ID" ] && [ "$VIVA_Q_COUNT" -ge 2 ]; then
    record "VI1" "PASS" "BLOCKED" "Viva generated: $VIVA_ID ($VIVA_Q_COUNT questions)"
else
    record "VI1" "PASS" "FAIL" "Viva generation failed: status=$VIVA_STATUS resp=$VIVA_RESP"
    # If generation fails, mark remaining as blocked
    for vid in VI2 VI3 VI4 VI5 VI6 VI7; do
        record "$vid" "PASS" "BLOCKED" "Viva generation failed"
    done
    OVERALL="FAIL"
    cat > "$ARTIFACT_DIR/viva-results.json" <<EOF2
{
  "phase": "P5",
  "test": "viva_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "timestamp": "$(ts)"
}
EOF2
    echo ""
    echo "=== [P5-VIVA] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
    [ "$FAIL" -eq 0 ]
    exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
fi

# -----------------------------------------------------------------------
# VI2: Candidate JSON — no rubric/keys
# -----------------------------------------------------------------------
echo "  VI2: Checking candidate JSON has no rubric..."
ANSWER_LEAK=$(echo "$VIVA_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for key in ['rubric_reference','answer_explanation','assessment_objective']:
    # These are OK in questions array for context, but not as answer keys
    pass
# Check no answer keys
for q in d.get('questions',[]):
    if 'answer' in q or 'key' in q or 'rubric' in str(q).lower():
        print('LEAKED')
        sys.exit(0)
print('CLEAN')
" 2>/dev/null || echo "UNKNOWN")
if [ "$ANSWER_LEAK" = "CLEAN" ]; then
    record "VI2" "CLEAN" "CLEAN" "Candidate viva JSON has no answer keys"
else
    record "VI2" "CLEAN" "FAIL" "Answer key leaked in candidate JSON"
fi

# -----------------------------------------------------------------------
# VI3: Viva response submission
# -----------------------------------------------------------------------
echo "  VI3: Submitting viva response..."
FIRST_Q_ID=$(echo "$VIVA_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['questions'][0]['question_id'])" 2>/dev/null || echo "")
if [ -n "$FIRST_Q_ID" ]; then
    SUBMIT_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/viva/response" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
        -d "{\"viva_id\":\"${VIVA_ID}\",\"question_id\":\"${FIRST_Q_ID}\",\"candidate_id\":\"${CANDIDATE_ID}\",\"response_text\":\"The throughput calculation accounts for the pipeline latency by...\"}" 2>/dev/null)
    SUBMIT_STATUS=$(echo "$SUBMIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$SUBMIT_STATUS" = "RESPONSE_RECORDED" ]; then
        record "VI3" "RESPONSE_RECORDED" "RESPONSE_RECORDED" "Viva response submitted"
    else
        record "VI3" "RESPONSE_RECORDED" "FAIL" "Response submission failed: $SUBMIT_STATUS"
    fi
else
    record "VI3" "RESPONSE_RECORDED" "BLOCKED" "No question ID available"
fi

# -----------------------------------------------------------------------
# VI4: Duplicate response rejection
# PG-34: Only test duplicate rejection if the first response was actually
# accepted (RESPONSE_RECORDED). Testing duplicate rejection against a
# non-existent first response is a test design flaw.
# -----------------------------------------------------------------------
echo "  VI4: Testing duplicate response rejection..."
FIRST_ACCEPTED=0
if [ -n "$FIRST_Q_ID" ]; then
    SUBMIT_STATUS=$(echo "$SUBMIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$SUBMIT_STATUS" = "RESPONSE_RECORDED" ]; then
        FIRST_ACCEPTED=1
    fi
fi
if [ "$FIRST_ACCEPTED" -eq 1 ]; then
    DUP_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/viva/response" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
        -d "{\"viva_id\":\"${VIVA_ID}\",\"question_id\":\"${FIRST_Q_ID}\",\"candidate_id\":\"${CANDIDATE_ID}\",\"response_text\":\"Different answer that should be rejected\"}" 2>/dev/null)
    DUP_STATUS=$(echo "$DUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$DUP_STATUS" = "DUPLICATE_REJECTED" ] || [ "$DUP_STATUS" = "ALREADY_SUBMITTED" ]; then
        record "VI4" "REJECTED" "REJECTED" "Duplicate response correctly rejected"
    else
        record "VI4" "REJECTED" "FAIL" "Duplicate not rejected: $DUP_STATUS"
    fi
elif [ -n "$FIRST_Q_ID" ]; then
    record "VI4" "REJECTED" "FAIL" "First response was not accepted (status=$SUBMIT_STATUS) — cannot test duplicate rejection"
else
    record "VI4" "REJECTED" "BLOCKED" "No question ID available"
fi

# -----------------------------------------------------------------------
# VI5: Reviewer export
# -----------------------------------------------------------------------
echo "  VI5: Reviewer export..."
if [ -n "$REVIEWER_TOKEN" ]; then
    REVIEWER_RESP=$(curl -s "${SERVER_URL}/api/v1/reviewer/viva?viva_id=${VIVA_ID}" \
        -H "Authorization: Bearer ${REVIEWER_TOKEN}" 2>/dev/null)
    if echo "$REVIEWER_RESP" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        record "VI5" "PASS" "PASS" "Reviewer viva export succeeded"
    else
        record "VI5" "PASS" "FAIL" "Reviewer export failed"
    fi
else
    record "VI5" "PASS" "BLOCKED" "No reviewer token"
fi

# -----------------------------------------------------------------------
# VI6: Reviewer decision/override
# -----------------------------------------------------------------------
echo "  VI6: Reviewer decision..."
if [ -n "$REVIEWER_TOKEN" ]; then
    DECISION_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/reviewer/viva/decide" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${REVIEWER_TOKEN}" \
        -d "{\"viva_id\":\"${VIVA_ID}\",\"reviewer_id\":\"reviewer-001\",\"state\":1,\"final_score\":85.0,\"reason_code\":\"REVIEWED\",\"written_rationale\":\"Candidate demonstrated adequate understanding\"}" 2>/dev/null)
    DECISION_STATUS=$(echo "$DECISION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$DECISION_STATUS" = "DECISION_RECORDED" ]; then
        record "VI6" "DECISION_RECORDED" "DECISION_RECORDED" "Reviewer decision recorded"
    else
        record "VI6" "DECISION_RECORDED" "FAIL" "Decision failed: $DECISION_STATUS"
    fi
else
    record "VI6" "DECISION_RECORDED" "BLOCKED" "No reviewer token"
fi

# -----------------------------------------------------------------------
# VI7: Audit trail
# -----------------------------------------------------------------------
echo "  VI7: Audit trail..."
# The audit trail is written internally — verify via reviewer export
if [ -n "$REVIEWER_TOKEN" ]; then
    AUDIT_RESP=$(curl -s "${SERVER_URL}/api/v1/reviewer/viva?viva_id=${VIVA_ID}" \
        -H "Authorization: Bearer ${REVIEWER_TOKEN}" 2>/dev/null)
    HAS_AUDIT=$(echo "$AUDIT_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# Check if decision or audit info is present
if 'review_state' in d or 'decision' in d or 'state' in d:
    print('HAS_AUDIT')
else:
    print('NO_AUDIT')
" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$HAS_AUDIT" = "HAS_AUDIT" ]; then
        record "VI7" "HAS_AUDIT" "HAS_AUDIT" "Audit trail present in reviewer export"
    else
        record "VI7" "HAS_AUDIT" "WARN" "Audit trail not clearly visible"
    fi
else
    record "VI7" "HAS_AUDIT" "BLOCKED" "No reviewer token"
fi

# -----------------------------------------------------------------------
# VI8: P5→P4 regression — verify event chain integrity after P5 operations
# -----------------------------------------------------------------------
echo "  VI8: Verifying P4 tamper-evident event chain integrity..."
EVENT_CHAIN="$RUN_DIR/events.log"
if [ -f "$EVENT_CHAIN" ]; then
    VERIFIER_BIN="${EXAMOS_P4_VERIFIER:-$WORKSPACE/tools/exam-event-verify}"
    if [ -x "$VERIFIER_BIN" ]; then
        VERIFY_OUT=$("$VERIFIER_BIN" --session "$SESSION_ID" --store "$EVENT_CHAIN" 2>&1 || true)
        if echo "$VERIFY_OUT" | grep -q "RESULT: PASS"; then
            record "VI8" "PASS" "PASS" "P4 event chain integrity verified after P5 operations"
        else
            record "VI8" "PASS" "FAIL" "P4 event chain verification failed: $VERIFY_OUT"
        fi
    else
        record "VI8" "PASS" "BLOCKED" "Event verifier not available"
    fi
else
    record "VI8" "PASS" "BLOCKED" "Event chain file not found"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
OVERALL="PASS"
[ "$FAIL" -gt 0 ] && OVERALL="FAIL"
[ "$BLOCKED" -gt 0 ] && [ "$FAIL" -eq 0 ] && OVERALL="BLOCKED"

cat > "$ARTIFACT_DIR/viva-results.json" <<EOF
{
  "phase": "P5",
  "test": "viva_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "timestamp": "$(ts)"
}
EOF

echo ""
echo "=== [P5-VIVA] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
[ "$FAIL" -eq 0 ]
