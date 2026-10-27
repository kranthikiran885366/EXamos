#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

# 1. Download matching libharfbuzz0b
curl -s -L -o /tmp/harfbuzz0b.deb "http://deb.debian.org/debian/pool/main/h/harfbuzz/libharfbuzz0b_12.3.2-2+b2_amd64.deb"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

# Extract matching libharfbuzz0b into rootfs
dpkg-deb -x /tmp/harfbuzz0b.deb "$MNT/"
chroot "$MNT" ldconfig 2>/dev/null || true

mount -t proc /proc "$MNT/proc"
mount -t sysfs /sys "$MNT/sys"
mount --bind /dev "$MNT/dev"

echo "=== Testing Chromium startup now ==="
timeout 5 chroot "$MNT" /usr/lib/chromium/chromium \
  --user-data-dir=/tmp/test_profile \
  --kiosk \
  --no-first-run \
  --no-default-browser-check \
  --no-sandbox \
  --test-type \
  --disable-dev-shm-usage \
  --disable-gpu \
  --ozone-platform=wayland \
  --app=file:///usr/share/examos/onboarding.html 2>&1 || true

umount "$MNT/proc" || true
umount "$MNT/sys" || true
umount "$MNT/dev" || true
sync
umount "$MNT"
losetup -d "$LOOP"
echo "=== Done! ==="
