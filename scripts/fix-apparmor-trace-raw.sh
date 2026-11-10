#!/usr/bin/env bash
set -euo pipefail

RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_fix"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

PROFILE="$MNT/etc/apparmor.d/examos-kiosk"

# Remove any misplaced line at the end
sed -i '/chrome_crashpad_handler.real ix,/d' "$PROFILE"

# Insert in the correct files section right after chrome_crashpad_handler ix,
sed -i '/\/usr\/lib\/chromium\/chrome_crashpad_handler ix,/a \    /usr/lib/chromium/chrome_crashpad_handler.real ix,' "$PROFILE"

# Verify profile with apparmor_parser
apparmor_parser -q -p "$PROFILE"
echo "PROFILE VALIDATED IN GUEST ROOTFS"

sync
umount "$MNT"
losetup -d "$LOOP"
echo "RAW IMAGE UPDATED SUCCESSFULLY"
