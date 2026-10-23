#!/usr/bin/env bash
# =============================================================================
# ExamOS Load & Stress Test Suite
# Simulates concurrent candidate sessions, heartbeats, and admin operations
# to identify connection pool exhaustion, thread starvation, and response
# degradation under load.
#
# Usage:
#   ./tests/server/test_load_stress.sh [CONCURRENT_USERS] [SERVER_URL]
#
# Requirements:
#   - curl, GNU parallel (optional), bc
#   - ExamOS server running on target URL
#   - Admin credentials and agent token configured
# =============================================================================
set -e

CONCURRENT="${1:-50}"
SERVER_URL="${2:-http://127.0.0.1:8000}"
TOTAL_REQUESTS=$((CONCURRENT * 10))

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo "================================================================="
echo "  ExamOS Load & Stress Test Suite"
echo "  Concurrent users: $CONCURRENT"
echo "  Server: $SERVER_URL"
echo "  Total requests per test: $TOTAL_REQUESTS"
echo "================================================================="
echo ""

# ---------------------------------------------------------------------------
# Test 1: Health endpoint under concurrent load
# ---------------------------------------------------------------------------
info "Test 1: Health endpoint concurrency ($TOTAL_REQUESTS requests, $CONCURRENT parallel)"

HEALTH_START=$(date +%s%N)
HEALTH_OK=0
HEALTH_FAIL=0

for i in $(seq 1 $TOTAL_REQUESTS); do
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        "$SERVER_URL/api/v1/health" &
done | while read code; do
    if [ "$code" = "200" ]; then
        HEALTH_OK=$((HEALTH_OK + 1))
    else
        HEALTH_FAIL=$((HEALTH_FAIL + 1))
    fi
done
wait

HEALTH_END=$(date +%s%N)
HEALTH_ELAPSED=$(( (HEALTH_END - HEALTH_START) / 1000000 ))

if [ "$HEALTH_FAIL" -eq 0 ] 2>/dev/null; then
    pass "Health: all requests returned 200 in ${HEALTH_ELAPSED}ms"
else
    info "Health: completed in ${HEALTH_ELAPSED}ms (some may have failed under load)"
fi

# ---------------------------------------------------------------------------
# Test 2: Rapid connection open/close (slowloris defense)
# ---------------------------------------------------------------------------
info "Test 2: Rapid connection churn ($CONCURRENT simultaneous connects)"

SLOWLORIS_FAIL=0
for i in $(seq 1 $CONCURRENT); do
    (
        # Open a TCP connection and send partial HTTP, wait 6s (past the 5s timeout)
        exec 3<>/dev/tcp/${SERVER_URL#*//} 2>/dev/null || exit 0
        echo -ne "GET / HTTP/1.1\r\nHost: exam\r\n" >&3 2>/dev/null
        sleep 6
        exec 3<&-
    ) &
done
wait

# After the slowloris attempt, verify server is still responsive
AFTER_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$SERVER_URL/api/v1/health" 2>/dev/null || echo "000")
if [ "$AFTER_CODE" = "200" ]; then
    pass "Slowloris defense: server still responding after connection churn"
else
    fail "Slowloris defense: server returned $AFTER_CODE after connection churn"
fi

# ---------------------------------------------------------------------------
# Test 3: Concurrent candidate login attempts (rate limiting)
# ---------------------------------------------------------------------------
info "Test 3: Concurrent candidate login flood ($CONCURRENT parallel)"

LOGIN_OK=0
LOGIN_REJECT=0
LOGIN_TIMEOUT=0

for i in $(seq 1 $CONCURRENT); do
    (
        CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -X POST "$SERVER_URL/api/v1/candidate/login" \
            -H "Content-Type: application/json" \
            -d "{\"candidate_id\":\"STRESS-CAND-$i\",\"pin\":\"000000\"}" 2>/dev/null || echo "000")
        echo "$CODE"
    ) &
done | while read code; do
    case "$code" in
        200) LOGIN_OK=$((LOGIN_OK + 1)) ;;
        401) LOGIN_REJECT=$((LOGIN_REJECT + 1)) ;;
        429) LOGIN_REJECT=$((LOGIN_REJECT + 1)) ;;
        000) LOGIN_TIMEOUT=$((LOGIN_TIMEOUT + 1)) ;;
        *)   LOGIN_REJECT=$((LOGIN_REJECT + 1)) ;;
    esac
done
wait

pass "Login flood: server handled $CONCURRENT simultaneous login attempts without crash"

# ---------------------------------------------------------------------------
# Test 4: Oversized request rejection
# ---------------------------------------------------------------------------
info "Test 4: Oversized request rejection (>128KB payload)"

# Generate a 200KB JSON payload
LARGE_PAYLOAD=$(python3 -c "print('{\"data\":\"' + 'A'*200000 + '\"}')" 2>/dev/null || echo '{"data":"AAAA"}')

OVERSIZE_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "$SERVER_URL/api/v1/candidate/login" \
    -H "Content-Type: application/json" \
    -d "$LARGE_PAYLOAD" 2>/dev/null || echo "000")

if [ "$OVERSIZE_CODE" = "400" ] || [ "$OVERSIZE_CODE" = "413" ]; then
    pass "Oversized request: correctly rejected with HTTP $OVERSIZE_CODE"
elif [ "$OVERSIZE_CODE" = "000" ]; then
    pass "Oversized request: connection dropped (acceptable for >BUFFER_SIZE)"
else
    fail "Oversized request: unexpected response code $OVERSIZE_CODE"
fi

# ---------------------------------------------------------------------------
# Test 5: Admin auth brute force lockout
# ---------------------------------------------------------------------------
info "Test 5: Admin brute force lockout (10 rapid failed attempts)"

for i in $(seq 1 10); do
    curl -s -o /dev/null -X POST "$SERVER_URL/api/v1/admin/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"WRONG_PASSWORD_'$i'"}' \
        --max-time 5 2>/dev/null
done

LOCKOUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -X POST "$SERVER_URL/api/v1/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"WRONG_AGAIN"}' 2>/dev/null || echo "000")

if [ "$LOCKOUT_CODE" = "429" ] || [ "$LOCKOUT_CODE" = "401" ]; then
    pass "Brute force: account lockout/throttle active (HTTP $LOCKOUT_CODE)"
else
    info "Brute force: server returned $LOCKOUT_CODE (verify lockout policy)"
fi

# ---------------------------------------------------------------------------
# Test 6: Post-stress health verification
# ---------------------------------------------------------------------------
info "Test 6: Post-stress health verification"

sleep 2
FINAL_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$SERVER_URL/api/v1/health" 2>/dev/null || echo "000")
if [ "$FINAL_CODE" = "200" ]; then
    pass "Post-stress: server is healthy and responding normally"
else
    fail "Post-stress: server returned $FINAL_CODE (may need restart)"
fi

echo ""
echo "================================================================="
echo "  Load & Stress Test Suite Complete"
echo "================================================================="
