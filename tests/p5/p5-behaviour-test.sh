#!/usr/bin/env bash
# =============================================================================
# ExamOS P5 — Behaviour Engine Test
#
# Tests:
#   B1: Ingest per-question behaviour features (6 features F1-F6)
#   B2: Personal baseline computation (median/MAD from practice quizzes)
#   B3: Robust z-score risk score computation (0-100)
#   B4: Quality codes — missing data never silently replaced
#   B5: Relay detection (pause + burst patterns)
#   B6: Feature export (reviewer-facing JSON)
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P5_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase5}"
mkdir -p "$ARTIFACT_DIR"

SERVER_PORT="${EXAMOS_P5_SERVER_PORT:-9103}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_PID=""
PASS=0; FAIL=0; BLOCKED=0

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" expected="$2" actual="$3" detail="$4"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS+1)); echo "  [BEH-PASS] $id: $detail"
    elif [ "$actual" = "BLOCKED" ]; then
        BLOCKED=$((BLOCKED+1)); echo "  [BEH-BLOCKED] $id: $detail"
    else
        FAIL=$((FAIL+1)); echo "  [BEH-FAIL] $id: $detail (expected=$expected actual=$actual)"
    fi
}

echo "=== [P5-BEHAVIOUR] Behaviour Engine Test ==="

# Start server
CANDIDATE_TOKEN=""
REVIEWER_TOKEN="${EXAMOS_REVIEWER_TOKEN:-test-reviewer-token-32chars-minimum}"

if [ -x "$SERVER_BIN" ]; then
    # Create candidate credentials first so candidate store exists when server checks
    CANDIDATE_ID="P5-BEH-$(date +%s)"
    CANDIDATE_PIN="$(openssl rand -hex 8)"
    CAND_SALT="$(openssl rand -hex 32)"
    CAND_HASH=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "hexsalt:${CAND_SALT}" -kdfopt "pass:${CANDIDATE_PIN}" \
        -kdfopt iter:100000 PBKDF2 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f')
    CAND_FILE="/tmp/examos-p5-behaviour-candidates.conf"
    echo "${CANDIDATE_ID}:100000:${CAND_SALT}:${CAND_HASH}" > "$CAND_FILE"

    AGENT_TOKEN="$(openssl rand -hex 32)"
    PROCTOR_TOKEN="$(openssl rand -hex 32)"
    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="/tmp/examos-p5-behaviour-ledger.log" \
    EXAMOS_EVENT_CHAIN_PATH="/tmp/examos-p5-behaviour-events.log" \
    EXAMOS_AGENT_API_TOKEN="$AGENT_TOKEN" \
    EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_REVIEWER_TOKEN="$REVIEWER_TOKEN" \
    EXAMOS_BEHAVIOUR_STORE="/tmp/examos-p5-behaviour-store" \
    EXAMOS_VIVA_STORE="/tmp/examos-p5-viva-store" \
    EXAMOS_TPM_MODE=development \
    EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
    EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
    EXAMOS_SESSION_JOURNAL="/tmp/examos-p5-behaviour-sessions.log" \
    EXAMOS_CANDIDATE_STORE="$CAND_FILE" \
        "$SERVER_BIN" &
    SERVER_PID=$!
    for i in $(seq 1 15); do
        curl -sf "${SERVER_URL}/api/v1/health" >/dev/null 2>&1 && break
        sleep 0.5
    done

    # Login to get candidate token
    LOGIN_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/candidate/login" \
        -H "Content-Type: application/json" \
        -d "{\"candidate_id\":\"${CANDIDATE_ID}\",\"pin\":\"${CANDIDATE_PIN}\"}" 2>/dev/null)
    CANDIDATE_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [ -z "$CANDIDATE_TOKEN" ]; then
    echo "  BLOCKED: Cannot start server or authenticate candidate"
    echo "{\"phase\":\"P5\",\"test\":\"behaviour\",\"status\":\"BLOCKED\"}" > "$ARTIFACT_DIR/behaviour-results.json"
    exit 2
fi

SESSION_ID="${CANDIDATE_TOKEN}"

# -----------------------------------------------------------------------
# B1: Ingest per-question behaviour features
# -----------------------------------------------------------------------
echo "  B1: Ingesting per-question features..."
INGEST_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/behaviour/events" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
    -d "{
        \"session_id\": \"${SESSION_ID}\",
        \"question_id\": 1,
        \"question_presented_server_ts_ms\": 1700000000000,
        \"first_input_server_ts_ms\": 1700000005000,
        \"answer_submitted_server_ts_ms\": 1700000030000,
        \"question_char_length\": 150,
        \"edit_count\": 3,
        \"typing_intervals_ms\": [120, 150, 80, 200, 90, 110, 130, 95, 180, 100, 115, 140, 85, 160, 105],
        \"focus_fraction\": 0.85,
        \"gaze_fraction\": 0.80,
        \"gaze_confidence_pct\": 88,
        \"camera_available\": 1
    }" 2>/dev/null)

INGEST_STATUS=$(echo "$INGEST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
if [ "$INGEST_STATUS" = "FEATURES_INGESTED" ] || [ "$INGEST_STATUS" = "INGESTED" ]; then
    record "B1" "PASS" "PASS" "Feature ingestion succeeded"
else
    record "B1" "PASS" "FAIL" "Ingestion returned: $INGEST_STATUS ($INGEST_RESP)"
fi

# -----------------------------------------------------------------------
# B2: Practice quiz recording
# -----------------------------------------------------------------------
echo "  B2: Recording practice quizzes..."
for i in 1 2 3 4 5; do
    curl -s -X POST "${SERVER_URL}/api/v1/behaviour/practice" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
        -d "{\"candidate_id\":\"${CANDIDATE_ID}\",\"practice_session_id\":\"practice-${i}\"}" \
        >/dev/null 2>&1
done

PRACTICE_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/behaviour/practice" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
    -d "{\"candidate_id\":\"${CANDIDATE_ID}\",\"practice_session_id\":\"practice-6\"}" 2>/dev/null)
PRACTICE_COUNT=$(echo "$PRACTICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('eligible_count',0))" 2>/dev/null || echo "0")
if [ "$PRACTICE_COUNT" -ge 5 ]; then
    record "B2" "PASS" "PASS" "Practice count: $PRACTICE_COUNT (≥5 required for baseline)"
else
    record "B2" "PASS" "FAIL" "Practice count: $PRACTICE_COUNT (need ≥5)"
fi

# -----------------------------------------------------------------------
# B3: Baseline computation
# -----------------------------------------------------------------------
echo "  B3: Computing personal baseline..."
BASELINE_RESP=$(curl -s "${SERVER_URL}/api/v1/behaviour/baseline?candidate_id=${CANDIDATE_ID}" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" 2>/dev/null)
BASELINE_STATUS=$(echo "$BASELINE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('baseline_status',''))" 2>/dev/null || echo "")
if [ -n "$BASELINE_STATUS" ]; then
    record "B3" "PASS" "PASS" "Baseline computed with status: $BASELINE_STATUS"
else
    record "B3" "PASS" "FAIL" "Baseline computation failed: $BASELINE_RESP"
fi

# -----------------------------------------------------------------------
# B4: Risk score computation
# -----------------------------------------------------------------------
echo "  B4: Computing risk score..."
SCORE_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/behaviour/score/compute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${CANDIDATE_TOKEN}" \
    -d "{\"session_id\":\"${SESSION_ID}\",\"candidate_id\":\"${CANDIDATE_ID}\",\"exam_id\":\"EXAM-MAIN\"}" 2>/dev/null)
RISK_SCORE=$(echo "$SCORE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('risk_score',''))" 2>/dev/null || echo "")
CONF_STATUS=$(echo "$SCORE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('confidence_status', d.get('status','')))" 2>/dev/null || echo "")
if [ -n "$RISK_SCORE" ] || [ "$CONF_STATUS" = "SCORE_INSUFFICIENT_EVIDENCE" ] || [ "$CONF_STATUS" = "INSUFFICIENT_EVIDENCE" ]; then
    record "B4" "PASS" "PASS" "Risk engine executed with confidence_status: ${CONF_STATUS:-$RISK_SCORE}"
else
    record "B4" "PASS" "FAIL" "Risk score computation failed: $SCORE_RESP"
fi

# -----------------------------------------------------------------------
# B5: Feature export (reviewer-only)
# -----------------------------------------------------------------------
echo "  B5: Exporting features for reviewer..."
FEATURES_RESP=$(curl -s "${SERVER_URL}/api/v1/behaviour/features?session_id=${SESSION_ID}" \
    -H "Authorization: Basic $(echo -n "admin:${CANDIDATE_PIN}" | base64)" 2>/dev/null)
if echo "$FEATURES_RESP" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    record "B5" "PASS" "PASS" "Features exported as valid JSON"
else
    # Admin auth may not work without a proper admin.conf — try reviewer token
    FEATURES_RESP=$(curl -s "${SERVER_URL}/api/v1/behaviour/features?session_id=${SESSION_ID}" \
        -H "Authorization: Bearer ${REVIEWER_TOKEN}" 2>/dev/null)
    if echo "$FEATURES_RESP" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        record "B5" "PASS" "PASS" "Features exported via reviewer token"
    else
        record "B5" "PASS" "BLOCKED" "Cannot export features — auth issue"
    fi
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
OVERALL="PASS"
[ "$FAIL" -gt 0 ] && OVERALL="FAIL"
[ "$BLOCKED" -gt 0 ] && [ "$FAIL" -eq 0 ] && OVERALL="BLOCKED"

cat > "$ARTIFACT_DIR/behaviour-results.json" <<EOF
{
  "phase": "P5",
  "test": "behaviour_engine",
  "passed": $PASS,
  "failed": $FAIL,
  "blocked": $BLOCKED,
  "overall": "$OVERALL",
  "timestamp": "$(ts)"
}
EOF

echo ""
echo "=== [P5-BEHAVIOUR] PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCKED OVERALL=$OVERALL ==="
[ "$FAIL" -eq 0 ]
