#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P1_ARTIFACT_DIR:-$WORKSPACE/artifacts/p1}"
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

# PG-07: Verify kiosk binary is actually built and is a valid ELF executable
KIOSK_BIN="$WORKSPACE/kiosk/launcher/examos-kiosk-launcher"
if [ ! -f "$KIOSK_BIN" ]; then
    echo "[KIOSK-CHECK] FAIL: kiosk launcher binary not built: $KIOSK_BIN"
    exit 1
fi
if ! file "$KIOSK_BIN" 2>/dev/null | grep -q 'ELF 64-bit.*x86-64'; then
    echo "[KIOSK-CHECK] FAIL: kiosk launcher is not a valid ELF x86-64 binary"
    exit 1
fi
echo "[KIOSK-CHECK] PASS: Kiosk launcher binary is a valid ELF x86-64 executable"

# PG-07: Verify kiosk service ExecStart references the correct binary path
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"
if ! grep -q 'ExecStart=.*examos-kiosk-launcher\|ExecStart=.*cage' "$KIOSK_SVC" 2>/dev/null; then
    echo "[KIOSK-CHECK] FAIL: kiosk service ExecStart does not reference launcher or cage"
    exit 1
fi
echo "[KIOSK-CHECK] PASS: Kiosk service ExecStart references correct binary"

# PG-07: Verify kiosk service has required hardening directives
for directive in "NoNewPrivileges=true" "ProtectSystem=strict" "PrivateTmp=true"; do
    if ! grep -q "^${directive}" "$KIOSK_SVC" 2>/dev/null; then
        echo "[KIOSK-CHECK] FAIL: kiosk.service missing hardening directive: $directive"
        exit 1
    fi
done
echo "[KIOSK-CHECK] PASS: Kiosk service has required systemd hardening directives"

echo "[P1-KIOSK] PASS: All kiosk static verification checks passed"
exit 0
