#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"
echo "=== Check nftables service ==="
find "$MNT/etc/systemd/system" -name "*nft*"
cat "$MNT/etc/nftables.conf" 2>/dev/null || echo "No /etc/nftables.conf"
umount "$MNT"
losetup -d "$LOOP"
