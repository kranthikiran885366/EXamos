#!/usr/bin/env bash
set -euo pipefail

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(/sbin/losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== /etc/apparmor.d/unprivileged_userns ==="
cat "$MNT/etc/apparmor.d/unprivileged_userns" || true

umount "$MNT"
/sbin/losetup -d "$LOOP"
