#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== Mount dev, proc, sys for chroot ==="
mount -t proc /proc "$MNT/proc"
mount -t sysfs /sys "$MNT/sys"
mount --bind /dev "$MNT/dev"
cp /etc/resolv.conf "$MNT/etc/resolv.conf"

echo "=== Check apt sources in image ==="
cat "$MNT/etc/apt/sources.list" 2>/dev/null || true
ls -la "$MNT/etc/apt/sources.list.d" 2>/dev/null || true

echo "=== Testing apt update and install missing libs ==="
chroot "$MNT" apt-get update -qq
chroot "$MNT" apt-get install -y --no-install-recommends libjpeg62-turbo libopenh264-8 libharfbuzz-subset0 || true

echo "=== Verifying Chromium dynamic libraries ==="
chroot "$MNT" ldd /usr/lib/chromium/chromium | grep "not found" || echo "ALL LIBS RESOLVED!"

umount "$MNT/proc" || true
umount "$MNT/sys" || true
umount "$MNT/dev" || true
umount "$MNT"
losetup -d "$LOOP"
