#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

LOG_FILE="$ARTIFACT_DIR/kiosk.log"
exec > >(tee "$LOG_FILE") 2>&1

echo "=== [P1-KIOSK] Static Verification of Kiosk Configuration ==="

# Check service user
if grep -q "User=exam" "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"; then
    echo "[KIOSK-CHECK] PASS: Kiosk service executes as unprivileged user 'exam'"
else
    echo "[KIOSK-CHECK] FAIL: Kiosk service user is not 'exam'"
    exit 1
fi

# Check target
if grep -q "WantedBy=graphical.target" "$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"; then
    echo "[KIOSK-CHECK] PASS: Kiosk service hooked to graphical.target"
else
    echo "[KIOSK-CHECK] FAIL: Kiosk service not hooked to graphical.target"
    exit 1
fi

# Check no desktop environments in mkosi
for de in "gnome" "kde" "xfce" "lightdm" "gdm3"; do
    if grep -i " $de " "$WORKSPACE/image/mkosi.conf" 2>/dev/null; then
        echo "[KIOSK-CHECK] FAIL: Unapproved desktop environment found in mkosi.conf: $de"
        exit 1
    fi
done
echo "[KIOSK-CHECK] PASS: No conventional desktop environments installed (pure Cage kiosk)"

# Check exam.conf
if [ -f "$WORKSPACE/image/overlay/etc/examos/exam.conf" ]; then
    echo "[KIOSK-CHECK] PASS: /etc/examos/exam.conf configuration source exists"
else
    echo "[KIOSK-CHECK] FAIL: exam.conf missing"
    exit 1
fi

# Check AppArmor profile
if [ -f "$WORKSPACE/image/overlay/etc/apparmor.d/usr.bin.chromium" ]; then
    echo "[KIOSK-CHECK] PASS: Chromium AppArmor security profile exists"
else
    echo "[KIOSK-CHECK] FAIL: Chromium AppArmor profile missing"
    exit 1
fi

# Check Chromium Enterprise Managed Policy
if [ -f "$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json" ]; then
    echo "[KIOSK-CHECK] PASS: Chromium enterprise managed policies configured"
else
    echo "[KIOSK-CHECK] FAIL: Chromium managed policies missing"
    exit 1
fi

echo "[P1-KIOSK] PASS: All kiosk static verification checks passed"
exit 0
