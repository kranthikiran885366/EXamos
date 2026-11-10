#!/usr/bin/env bash
set -euo pipefail
RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== ls -la chrome-sandbox ==="
ls -la "$MNT/usr/lib/chromium/chrome-sandbox" || true

echo "=== kernel sysctls in /etc/sysctl.d/ ==="
grep -rn "unprivileged_userns_clone" "$MNT/etc/sysctl"* 2>/dev/null || true
grep -rn "apparmor" "$MNT/etc/sysctl"* 2>/dev/null || true

echo "=== AppArmor userns rules ==="
grep -rn "userns" "$MNT/etc/apparmor.d/" 2>/dev/null || true

umount "$MNT"
losetup -d "$LOOP"
