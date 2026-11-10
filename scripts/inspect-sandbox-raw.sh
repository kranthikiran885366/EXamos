#!/usr/bin/env bash
set -euo pipefail

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== chrome-sandbox in raw image ==="
ls -la "$MNT/usr/lib/chromium/chrome-sandbox" 2>&1 || true

echo "=== chromium binaries ==="
ls -la "$MNT/usr/lib/chromium/chromium" 2>&1 || true
ls -la "$MNT/usr/bin/chromium" 2>&1 || true

echo "=== AppArmor profiles ==="
ls -la "$MNT/etc/apparmor.d/" 2>&1 || true

echo "=== sysctl settings ==="
grep -rn "userns" "$MNT/etc/" 2>&1 || true

echo "=== examos-kiosk AppArmor profile content ==="
cat "$MNT/etc/apparmor.d/examos-kiosk" 2>&1 || true

umount "$MNT"
losetup -d "$LOOP"
