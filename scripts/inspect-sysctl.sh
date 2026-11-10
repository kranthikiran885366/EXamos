#!/usr/bin/env bash
set -euo pipefail

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== /etc/sysctl.d/ files ==="
ls -la "$MNT/etc/sysctl.d/" || true
for f in "$MNT"/etc/sysctl.d/*; do
    echo "--- $f ---"
    cat "$f"
done

echo "=== /etc/sysctl.conf ==="
cat "$MNT/etc/sysctl.conf" || true

umount "$MNT"
losetup -d "$LOOP"
