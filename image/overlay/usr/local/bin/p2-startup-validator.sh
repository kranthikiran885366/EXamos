#!/bin/bash
# ExamOS P2 Startup Validator
# Checks mandatory lockdown controls before the kiosk starts.
# Exits 0 (pass) or 1 (fail — triggers examos-lockdown-failed.target).
set -euo pipefail

# This overlay placeholder must be replaced by the complete validator staged
# by scripts/build-full-image.sh. Never treat an incomplete shortcut build as
# suitable for a kiosk session.
echo "[P2-VALIDATOR] FAIL: complete runtime validator was not staged." >&2
echo "[P2-VALIDATOR] Build with scripts/build-full-image.sh." >&2
exit 2

PASS=0
FAIL=0

check() {
    local name="$1" result="$2"
    if [ "$result" = "ok" ]; then
        echo "[preflight] PASS: $name"
        PASS=$((PASS+1))
    else
        echo "[preflight] FAIL: $name — $result" >&2
        FAIL=$((FAIL+1))
    fi
}

# 1. Kernel lockdown mode
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "none")
if echo "$LOCKDOWN" | grep -q '\[confidentiality\]\|\[integrity\]'; then
    check "kernel-lockdown" "ok"
else
    check "kernel-lockdown" "lockdown not active: $LOCKDOWN"
fi

# 2. No swap active
SWAP=$(swapon --show 2>/dev/null | wc -l)
[ "$SWAP" -eq 0 ] && check "no-swap" "ok" || check "no-swap" "swap is active ($SWAP entries)"

# 3. nftables ruleset loaded
NFT_RULES=$(nft list ruleset 2>/dev/null | wc -l)
[ "$NFT_RULES" -gt 0 ] && check "nftables-active" "ok" || check "nftables-active" "no nft rules loaded"

# 4. AppArmor enforcing
AA_STATUS=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "N")
[ "$AA_STATUS" = "Y" ] && check "apparmor-enabled" "ok" || check "apparmor-enabled" "AppArmor not enabled"

# 5. exam user exists
id exam >/dev/null 2>&1 && check "exam-user-exists" "ok" || check "exam-user-exists" "exam user missing"

# 6. Candidate store readable
[ -f /etc/examos/candidates.conf ] && check "candidates-conf" "ok" || check "candidates-conf" "candidates.conf missing"

# 7. Admin conf present
[ -f /etc/examos/admin.conf ] && check "admin-conf" "ok" || check "admin-conf" "admin.conf missing"

echo "[preflight] Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    echo "[preflight] LOCKDOWN VALIDATION FAILED — kiosk will not start" >&2
    exit 1
fi

echo "[preflight] All mandatory controls verified."
exit 0
