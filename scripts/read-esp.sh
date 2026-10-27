#!/usr/bin/env bash
set -e
IMG="/mnt/d/SEB BRO/output/examos-flat.vmdk"
MNT="/mnt/examos_esp"

losetup -D
LOOP=$(losetup -fP --show "$IMG")
mkdir -p "$MNT"
mount "${LOOP}p1" "$MNT"
echo "=== UKI cmdline section ==="
objcopy -O binary --only-section=.cmdline "$MNT/EFI/Linux/examos-6.12.113+deb13-amd64.efi" /tmp/cmdline.txt
cat /tmp/cmdline.txt
echo ""
umount "$MNT"
losetup -d "$LOOP"
