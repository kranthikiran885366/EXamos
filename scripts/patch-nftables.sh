#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

# Add port 8895 to nftables if not present
if ! grep -q "dport 8895" "$MNT/etc/nftables.conf"; then
    sed -i '/tcp dport 443 accept/a \        tcp dport 8895 accept\n        tcp dport 5173 accept' "$MNT/etc/nftables.conf"
    echo "Added port 8895 and 5173 to nftables.conf"
fi

sync
umount "$MNT"
losetup -d "$LOOP"
