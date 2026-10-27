#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

tail -n 30 "$MNT/usr/bin/chromium"

umount "$MNT"
losetup -d "$LOOP"
