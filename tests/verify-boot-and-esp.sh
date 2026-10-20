#!/bin/bash
set -euo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
VMDK="/mnt/d/SEB BRO/image/examos.vmdk"
MNT="/mnt/examos"

echo "=== [1/3] Inspecting ESP partition in raw disk image ==="
sudo losetup -D 2>/dev/null || true
sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -n 1 | cut -d: -f1)

sudo mkdir -p "$MNT/esp"
sudo mount "${LOOP}p1" "$MNT/esp"
echo "ESP partition contents:"
find "$MNT/esp" -type f
sudo umount "$MNT/esp"
sudo losetup -d "$LOOP"

echo ""
echo "=== [2/3] Live Booting VMDK with QEMU + UEFI OVMF ==="
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_TMPL="/usr/share/OVMF/OVMF_VARS_4M.fd"
TMP_VARS=$(mktemp /tmp/ovmf_vmdk.XXXXXX.fd)
cp "$OVMF_VARS_TMPL" "$TMP_VARS"

timeout 20s qemu-system-x86_64 \
    -m 1024M \
    -smp 2 \
    -cpu qemu64 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$VMDK",format=vmdk,if=virtio \
    -display none \
    -serial stdio 2>&1 || true

rm -f "$TMP_VARS"

echo ""
echo "=== [3/3] Live Server Check ==="
curl -s http://127.0.0.1:8000/api/v1/desktop/telemetry || echo "Server endpoint test"
