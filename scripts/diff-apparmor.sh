#!/usr/bin/env bash
set -euo pipefail

V14="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-test-v14.raw"
TRACE="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"

LOOP1=$(losetup -fP --show "$V14")
LOOP2=$(losetup -fP --show "$TRACE")

MNT1="/mnt/cmp_v14"
MNT2="/mnt/cmp_trace"
mkdir -p "$MNT1" "$MNT2"

mount -o ro "${LOOP1}p2" "$MNT1"
mount -o ro "${LOOP2}p2" "$MNT2"

echo "=== Diffing /etc/apparmor.d/examos-kiosk ==="
diff -u "$MNT1/etc/apparmor.d/examos-kiosk" "$MNT2/etc/apparmor.d/examos-kiosk" || true

umount "$MNT1"
umount "$MNT2"
losetup -d "$LOOP1"
losetup -d "$LOOP2"
