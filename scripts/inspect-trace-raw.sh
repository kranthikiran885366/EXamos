#!/usr/bin/env bash
set -euo pipefail
RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"
echo "=== tail -n 30 of /etc/apparmor.d/examos-kiosk ==="
tail -n 30 "$MNT/etc/apparmor.d/examos-kiosk"
echo "=== ls -la /usr/lib/chromium/ ==="
ls -la "$MNT/usr/lib/chromium/" | grep -E 'crashpad|chromium' || true
umount "$MNT"
losetup -d "$LOOP"
