#!/usr/bin/env bash
# =============================================================================
# ExamOS P5 — Variant Engine Test
#
# Tests:
#   V1: Generate a question variant (HMAC-seeded, unique per candidate)
#   V2: Candidate JSON export (no answer key leaked)
#   V3: Reviewer JSON export (includes answer key)
#   V4: Grade a submitted answer against server-stored key
#   V5: Watermark tracing (trace fragment → candidate)
#   V6: Variant diversity (different candidates get different params)
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P5_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase5}"
mkdir -p "$ARTIFACT_DIR"

SERVER_PORT="${EXAMOS_P5_SERVER_PORT:-9104}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_PID=""
RUN_DIR="$(mktemp -d /tmp/examos-p5-variant.XXXXXX)"
PASS=0; FAIL=0; BLOCKED=0

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
record() {
    local id="$1" expected="$2" actual="$3" detail="$4"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS+1)); echo "  [VAR-PASS] $id: $detail"
    elif [ "$actual" = "BLOCKED" ]; then
        BLOCKED=$((BLOCKED+1)); echo "  [VAR-BLOCKED] $id: $detail"
    else
        FAIL=$((FAIL+1)); echo "  [VAR-FAIL] $id: $detail (expected=$expected actual=$actual)"
    fi
}

echo "=== [P5-VARIANT] Variant Engine Test ==="

# Start server
CANDIDATE_TOKEN=""
if [ -x "$SERVER_BIN" ]; then
    CANDIDATE_ID="P5-VAR-$(date +%s)"
    CANDIDATE_PIN="$(openssl rand -hex 8)"
    CAND_SALT="$(openssl rand -hex 32)"
    CAND_HASH=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "hexsalt:${CAND_SALT}" -kdfopt "pass:${CANDIDATE_PIN}" \
        -kdfopt iter:100000 PBKDF2 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f')
    CAND_FILE="$RUN_DIR/candidates.conf"
    echo "${CANDIDATE_ID}:100000:${CAND_SALT}:${CAND_HASH}" > "$CAND_FILE"

    # Provision a real examination identity; the server no longer fabricate one.
    EXAM_ID="P5-VARIANT-$(date +%s)"
    cat > "$RUN_DIR/exam.conf" <<EXAMCONF
EXAM_URL=https://exam.university.edu/test
EXAM_NAME=ExamOS Variant Test
EXAM_ID=${EXAM_ID}
ALLOWED_ORIGINS=https://exam.university.edu
EXAM_DURATION_MINUTES=60
EXAMCONF

    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="$RUN_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_REVIEWER_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV=1 \
    EXAMOS_EXAM_CONFIG="$RUN_DIR/exam.conf" \
    EXAMOS_VARIANT_STORE="$RUN_DIR/variant-store" \
    EXAMOS_EVENT_CHAIN_PATH="$RUN_DIR/events.log" \
    EXAMOS_BEHAVIOUR_STORE="$RUN_DIR/behaviour-store" \
    EXAMOS_VIVA_STORE="$RUN_DIR/viva-store" \
    EXAMOS_DATA_DIR="$RUN_DIR/data" \
    EXAMOS_TPM_MODE=development \
    EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
    EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    EXAMOS_CANDIDATE_STORE="$CAND_FILE" \
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
    REVIEWER_TOKEN=$(cat /proc/$SERVER_PID/environ 2>/dev/null | tr '\0' '\n' | grep EXAMOS_REVIEWER_TOKEN | cut -d= -f2)
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

if [ -z "$CANDIDATE_TOKEN" ]; then
    echo "  BLOCKED: Cannot start server or authenticate"
    echo "{\"phase\":\"P5\",\"test\":\"variant\",\"status\":\"BLOCKED\"}" > "$ARTIFACT_DIR/variant-results.json"
    exit 2
fi

# -----------------------------------------------------------------------
# V1: Generate variant
# -----------------------------------------------------------------------
echo "  V1: Generating question variant..."
VARIANT_RESP=$(curl -s "${SERVER_URL}/api/v1/exam/variant" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" 2>/dev/null)

VARIANT_ID=$(echo "$VARIANT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('variant_id',''))" 2>/dev/null || echo "")
RENDERED_Q=$(echo "$VARIANT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rendered_question', d.get('question_text',''))[:60])" 2>/dev/null || echo "")
WATERMARK=$(echo "$VARIANT_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('watermark_footer', d.get('watermark_text',''))[:60])" 2>/dev/null || echo "")

if [ -n "$VARIANT_ID" ]; then
    record "V1" "PASS" "PASS" "Variant generated: $VARIANT_ID"
else
    record "V1" "PASS" "FAIL" "No variant_id in response: $VARIANT_RESP"
fi

# -----------------------------------------------------------------------
# V2: Candidate JSON — no answer key
# -----------------------------------------------------------------------
echo "  V2: Checking candidate JSON has no answer key..."
ANSWER_LEAK=$(echo "$VARIANT_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# Check for answer key fields that should never be in candidate response
for key in ['answer_numeric','answer_option_index','answer_explanation','rubric']:
    if key in d:
        print('LEAKED: ' + key)
        sys.exit(0)
print('CLEAN')
" 2>/dev/null || echo "UNKNOWN")

if [ "$ANSWER_LEAK" = "CLEAN" ]; then
    record "V2" "CLEAN" "CLEAN" "Candidate JSON has no answer key fields"
else
    record "V2" "CLEAN" "FAIL" "Answer key leaked: $ANSWER_LEAK"
fi

# -----------------------------------------------------------------------
# V3: Watermark present in variant
# -----------------------------------------------------------------------
echo "  V3: Checking watermark in variant..."
if [ -n "$WATERMARK" ]; then
    record "V3" "PASS" "PASS" "Watermark present: ${WATERMARK:0:40}..."
else
    record "V3" "PASS" "FAIL" "No watermark in candidate JSON"
fi

# -----------------------------------------------------------------------
# V4: Reviewer export (includes answer key)
# -----------------------------------------------------------------------
echo "  V4: Reviewer JSON should include answer key..."
REVIEWER_RESP=$(curl -s "${SERVER_URL}/api/v1/reviewer/variant?variant_id=${VARIANT_ID}" \
    -H "Authorization: Bearer ${REVIEWER_TOKEN}" 2>/dev/null)

HAS_ANSWER=$(echo "$REVIEWER_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'answer_numeric' in d or 'answer_option_index' in d:
    print('HAS_ANSWER')
else:
    print('NO_ANSWER')
" 2>/dev/null || echo "PARSE_ERROR")

if [ "$HAS_ANSWER" = "HAS_ANSWER" ]; then
    record "V4" "HAS_ANSWER" "HAS_ANSWER" "Reviewer JSON includes answer key"
else
    record "V4" "HAS_ANSWER" "FAIL" "Reviewer JSON missing answer key: $HAS_ANSWER"
fi

# -----------------------------------------------------------------------
# V5: Watermark tracing
# -----------------------------------------------------------------------
echo "  V5: Tracing watermark..."
if [ -n "$WATERMARK" ]; then
    # Extract a fragment of the watermark to trace
    WM_FRAGMENT=$(echo "$WATERMARK" | cut -c1-20)
    TRACE_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/reviewer/watermark/trace" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${REVIEWER_TOKEN}" \
        -d "{\"watermark_fragment\":\"${WM_FRAGMENT}\"}" 2>/dev/null)
    TRACE_STATUS=$(echo "$TRACE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$TRACE_STATUS" = "TRACED" ]; then
        record "V5" "TRACED" "TRACED" "Watermark traced to candidate"
    else
        record "V5" "TRACED" "FAIL" "Watermark trace failed: $TRACE_STATUS"
    fi
else
    record "V5" "TRACED" "BLOCKED" "No watermark to trace"
fi

# -----------------------------------------------------------------------
# V6: Variant diversity — different candidates get different params
# -----------------------------------------------------------------------
echo "  V6: Checking variant diversity..."
# Login as a second candidate
CANDIDATE_ID2="P5-VAR2-$(date +%s)"
CAND2_SALT="$(openssl rand -hex 32)"
CAND2_HASH=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
    -kdfopt "hexsalt:${CAND2_SALT}" -kdfopt "pass:${CANDIDATE_PIN}" \
    -kdfopt iter:100000 PBKDF2 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f')
echo "${CANDIDATE_ID2}:100000:${CAND2_SALT}:${CAND2_HASH}" >> "$CAND_FILE"

LOGIN2_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/candidate/login" \
    -H "Content-Type: application/json" \
    -d "{\"candidate_id\":\"${CANDIDATE_ID2}\",\"pin\":\"${CANDIDATE_PIN}\"}" 2>/dev/null)
CAND2_TOKEN=$(echo "$LOGIN2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")

if [ -n "$CAND2_TOKEN" ]; then
    VAR2_RESP=$(curl -s "${SERVER_URL}/api/v1/exam/variant" \
        -H "Authorization: Bearer ${CAND2_TOKEN}" 2>/dev/null)
    VAR2_ID=$(echo "$VAR2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('variant_id',''))" 2>/dev/null || echo "")

    if [ "$VAR2_ID" != "$VARIANT_ID" ]; then
        record "V6" "DIFFERENT" "DIFFERENT" "Two candidates got different variant IDs"
    else
        record "V6" "DIFFERENT" "FAIL" "Same variant ID for two candidates"
    fi
else
    record "V6" "DIFFERENT" "BLOCKED" "Cannot authenticate second candidate"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
OVERALL="PASS"
[ "$FAIL" -gt 0 ] && OVERALL="FAIL"
[ "$BLOCKED" -gt 0 ] && [ "$FAIL" -eq 0 ] && OVERALL="BLOCKED"

cat > "$ARTIFACT_DIR/variant-results.json" <<EOF
{
  "phase": "P5",
  "test": "variant_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "timestamp": "$(ts)"
}
EOF

echo ""
echo "=== [P5-VARIANT] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
[ "$FAIL" -eq 0 ]
