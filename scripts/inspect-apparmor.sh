#!/usr/bin/env bash
set -euo pipefail

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== /etc/apparmor.d/chromium ==="
cat "$MNT/etc/apparmor.d/chromium" || true

echo "=== /usr/bin/chromium wrapper script ==="
cat "$MNT/usr/bin/chromium" || true

echo "=== sysctl kernel.unprivileged_userns_clone ==="
find "$MNT/etc" -type f -exec grep -H "unprivileged_userns" {} + || true

umount "$MNT"
losetup -d "$LOOP"
