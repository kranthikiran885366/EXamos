#!/usr/bin/env bash
set -euo pipefail
RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== chrome_crashpad_handler --help ==="
chroot "$MNT" /usr/lib/chromium/chrome_crashpad_handler --help 2>&1 || true

echo "=== strings /usr/lib/chromium/chromium | grep -C 2 -i BREAKPAD_DUMP_LOCATION ==="
strings "$MNT/usr/lib/chromium/chromium" | grep -C 2 "BREAKPAD_DUMP_LOCATION" || true

umount "$MNT"
losetup -d "$LOOP"
