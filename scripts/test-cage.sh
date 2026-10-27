#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"
echo "=== Check /usr/lib/chromium/chromium ==="
ls -la "$MNT/usr/lib/chromium/chromium" 2>&1 || true
ldd "$MNT/usr/lib/chromium/chromium" 2>&1 | grep "not found" || echo "All dynamic libs resolved!"

echo "=== Test running launcher directly in chroot ==="
chroot "$MNT" /usr/local/bin/examos-kiosk-launcher 2>&1 || true

umount "$MNT"
losetup -d "$LOOP"
