#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_inspect"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"
ls -la "$MNT/usr/share/examos"
umount "$MNT"
losetup -d "$LOOP"
