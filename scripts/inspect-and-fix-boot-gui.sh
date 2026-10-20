#!/bin/bash
set -euo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
VMDK="/mnt/d/SEB BRO/image/examos.vmdk"
MNT="/mnt/examos"

sudo umount -R "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1

sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -n 1 | cut -d: -f1)
echo "Attached loop: $LOOP"

sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"

echo "=== System Units in Image ==="
ls -la "$MNT/etc/systemd/system/"

echo "=== Checking examos services ==="
cat "$MNT/etc/systemd/system/examos-server.service" || true
echo "---"
cat "$MNT/etc/systemd/system/examos-agent.service" || true
echo "---"
cat "$MNT/etc/systemd/system/examos-kiosk.service" || true
