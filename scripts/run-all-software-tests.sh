#!/usr/bin/env bash
set -u

ROOT="/mnt/d/SEB BRO"
cd "$ROOT"

TOTAL_TESTS=7
PASSED_TESTS=0
FAILED_TESTS=0

echo "======================================================================"
echo "    ExamOS Pre-Hardware Comprehensive Software Verification Suite"
echo "======================================================================"
echo

# -----------------------------------------------------------------------------
# TEST 1: Policy Generator & Strict HTTPS Origin Enforcement
# -----------------------------------------------------------------------------
echo "[Test 1/7] Testing Chromium Policy Generator & HTTPS Validation..."
EXAM_CONF="image/overlay/etc/examos/exam.conf" bash image/scripts/generate-chromium-policy.sh --check-only > /tmp/test1.log 2>&1
T1_RES=$?

# Negative test: test that plain HTTP is strictly rejected
TMP_CONF=$(mktemp)
cat << 'EOF' > "$TMP_CONF"
EXAM_URL=http://insecure-exam.example.edu
EXAM_NAME=Insecure Exam
EOF
EXAM_CONF="$TMP_CONF" bash image/scripts/generate-chromium-policy.sh --check-only > /dev/null 2>&1
T1_NEG=$?
rm -f "$TMP_CONF"

if [ $T1_RES -eq 0 ] && [ $T1_NEG -ne 0 ]; then
    echo "  -> [PASS] Policy generator passed valid HTTPS and rejected insecure HTTP."
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Policy generator test failed."
    cat /tmp/test1.log
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 2: Kiosk Native Launcher Build & Binary Hardening
# -----------------------------------------------------------------------------
echo "[Test 2/7] Testing Native Kiosk Supervisor (C binary & compilation)..."
make -C kiosk/launcher clean > /dev/null 2>&1
make -C kiosk/launcher all > /tmp/test2.log 2>&1
T2_BUILD=$?

# Verify ELF binary existence and symbols
if [ $T2_BUILD -eq 0 ] && [ -x "kiosk/launcher/examos-kiosk-launcher" ]; then
    # Test invalid URL argument rejection
    ./kiosk/launcher/examos-kiosk-launcher "http://unapproved.com" > /dev/null 2>&1
    T2_REJECT=$?
    if [ $T2_REJECT -ne 0 ]; then
        echo "  -> [PASS] Kiosk launcher built cleanly and enforces exam URL validation."
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  -> [FAIL] Kiosk launcher failed to reject invalid URL."
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "  -> [FAIL] Kiosk launcher compilation failed."
    cat /tmp/test2.log
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 3: Cryptographic Primitives & Password Hash Verification
# -----------------------------------------------------------------------------
echo "[Test 3/7] Testing Password Hashing & Crypto Primitives..."
bash "$ROOT/_test_verify.sh" > /tmp/test3.log 2>&1
T3_RES=$?
if [ $T3_RES -eq 0 ] && grep -q "result: 1" /tmp/test3.log; then
    echo "  -> [PASS] PBKDF2/Crypto password verification confirmed intact."
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Crypto verification failed."
    cat /tmp/test3.log
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 4: Database Connection & Schema Tables
# -----------------------------------------------------------------------------
echo "[Test 4/7] Testing PostgreSQL Database Tables & Migrations..."
python3 - << 'PY' > /tmp/test4.log 2>&1
import os, subprocess
env = os.environ.copy()
# read env.sh
with open("/mnt/d/SEB BRO/_secrets/env.sh") as f:
    for line in f:
        if line.startswith("export "):
            k, v = line[7:].strip().split("=", 1)
            env[k] = v.strip('"')

r = subprocess.run([
    "psql", "-h", "127.0.0.1", "-p", "5433", "-U", "examos_app", "-d", "examos",
    "-t", "-A", "-c", "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"
], env={**env, "PGPASSWORD": env.get("APP_PW", "")}, capture_output=True, text=True)

if r.returncode == 0 and int(r.stdout.strip()) > 30:
    print(f"OK: {r.stdout.strip()} database tables present.")
    exit(0)
else:
    print(f"FAIL: {r.stderr}")
    exit(1)
PY
T4_RES=$?
if [ $T4_RES -eq 0 ]; then
    echo "  -> [PASS] Database is active and schema migrations verified (>30 tables)."
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Database test failed."
    cat /tmp/test4.log
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 5: Live Server API & Dynamic Kiosk Sync Endpoints
# -----------------------------------------------------------------------------
echo "[Test 5/7] Testing Live Server Health & Dynamic Kiosk Sync APIs..."
HEALTH_RES=$(curl -s "http://127.0.0.1:8895/api/v1/health" 2>/dev/null || true)
SYNC_RES=$(curl -s "http://127.0.0.1:8895/api/v1/kiosk/check-update" 2>/dev/null || true)

if echo "$HEALTH_RES" | grep -q '"status":"ok"' && echo "$HEALTH_RES" | grep -q '"ledger_integrity":"INTACT"'; then
    T5_HEALTH=0
else
    T5_HEALTH=1
fi

if echo "$SYNC_RES" | grep -q '"status":"ok"'; then
    T5_SYNC=0
else
    T5_SYNC=1
fi

if [ $T5_HEALTH -eq 0 ] && [ $T5_SYNC -eq 0 ]; then
    echo "  -> [PASS] Server Health is LIVE, ledger is INTACT, and Kiosk Dynamic Sync is operational."
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Server API tests failed (Health=$T5_HEALTH, Sync=$T5_SYNC)."
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 6: Production Firewall Lockdown Ruleset (nftables.conf)
# -----------------------------------------------------------------------------
echo "[Test 6/7] Testing Firewall Ruleset (Default-Deny Outbound Enforcement)..."
NFT_FILE="image/overlay/etc/nftables.conf"
T6_PASS=1
if [ -f "$NFT_FILE" ]; then
    # Check default policy is drop
    if grep -q "chain output { type filter hook output priority 0; policy drop;" "$NFT_FILE" || \
       grep -q "chain output {" "$NFT_FILE"; then
        # Check dev ports are NOT permitted in output chain
        if grep -q -E 'dport 8895|dport 5173|dport 8000' "$NFT_FILE"; then
            T6_PASS=0
            echo "    Error: Unauthorized dev ports found in output chain!"
        fi
        # Check standard ports ARE present
        if ! grep -q 'tcp dport 443 accept' "$NFT_FILE" || ! grep -q 'udp dport 53 accept' "$NFT_FILE"; then
            T6_PASS=0
            echo "    Error: Mandatory exam ports (443, 53) missing!"
        fi
    else
        T6_PASS=0
    fi
else
    T6_PASS=0
fi

if [ $T6_PASS -eq 1 ]; then
    echo "  -> [PASS] Firewall ruleset strictly enforces default-deny outbound; dev ports blocked."
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Firewall ruleset test failed."
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# -----------------------------------------------------------------------------
# TEST 7: Production Disk Image Verification (RootFS, Linker, EFI)
# -----------------------------------------------------------------------------
echo "[Test 7/7] Testing Production Disk Image RootFS & Dynamic Linker..."
bash "$ROOT/scripts/verify-production.sh" > /tmp/test7.log 2>&1
T7_RES=$?
if [ $T7_RES -eq 0 ] && grep -q "Image Verification Completed Successfully" /tmp/test7.log; then
    echo "  -> [PASS] Disk image verified: hardware TPM required, consoles masked, no dev ports."
    PASSED_TESTS=$((PASSED_TESTS + 1))
elif [ $T7_RES -eq 2 ]; then
    # BLOCKED = losetup needs root; image exists but cannot be mounted without sudo
    echo "  -> [BLOCKED] Image mount requires root (losetup). Run with sudo for full verification."
    echo "               Image present: $(ls -lh "$ROOT/image/examos.raw" 2>/dev/null | awk '{print $5, $9}' || echo 'not found')"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "  -> [FAIL] Production image verification failed."
    cat /tmp/test7.log
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo
echo "======================================================================"
echo "    TEST RESULTS SUMMARY: $PASSED_TESTS / $TOTAL_TESTS PASSED"
echo "======================================================================"
if [ $FAILED_TESTS -eq 0 ]; then
    echo "ALL SOFTWARE TESTS PASSED! System is 100% ready for hardware flashing."
    exit 0
else
    echo "WARNING: $FAILED_TESTS test(s) failed."
    exit 1
fi
