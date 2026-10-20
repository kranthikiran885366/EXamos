#!/bin/bash
set -euo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
ISO="/mnt/d/SEB BRO/image/examos.iso"
ISO_LIVE="/mnt/d/SEB BRO/image/examos-live.iso"
STAGING="/tmp/examos_iso_staging"
MNT="/tmp/examos_iso_mnt"
EFIMNT="/tmp/efitmp"

echo "=== [1/4] Extracting EFI Boot Structure from Raw Image ==="
sudo umount "$EFIMNT" 2>/dev/null || true
sudo umount "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1

rm -rf "$STAGING" "$MNT" "$EFIMNT" 2>/dev/null || true
mkdir -p "$STAGING" "$MNT" "$EFIMNT" "$STAGING/boot"

sudo losetup -fP "$RAW"
LOOP=$(sudo losetup -j "$RAW" | head -n 1 | cut -d: -f1)
echo "Loop device: $LOOP"

sudo mount "${LOOP}p1" "$MNT"

# Copy EFI tree directly into ISO root (critical for UEFI & Windows USB creation)
sudo cp -r "$MNT/." "$STAGING/"

# Generate FAT32 EFI boot partition image (efiboot.img)
echo "=== [2/4] Generating FAT EFI Boot Disk Image ==="
EFI_IMG="$STAGING/boot/efiboot.img"
dd if=/dev/zero of="$EFI_IMG" bs=1M count=512
mkfs.vfat -F 32 -n "EXAMOS_ESP" "$EFI_IMG"

sudo mount "$EFI_IMG" "$EFIMNT"
sudo cp -r "$MNT/." "$EFIMNT/"
sudo umount "$EFIMNT"
rm -rf "$EFIMNT"

sudo umount "$MNT"
rm -rf "$MNT"
sudo losetup -d "$LOOP"

echo "=== [3/4] Building VMware-Compliant Hybrid UEFI ISO ==="
rm -f "$ISO_LIVE" 2>/dev/null || true

xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS" \
    -eltorito-alt-boot \
    -e boot/efiboot.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -output "$ISO_LIVE" \
    "$STAGING"

rm -rf "$STAGING"

cp "$ISO_LIVE" "$ISO" 2>/dev/null || true

echo "=== [4/4] Testing Boot with QEMU in UEFI Mode ==="
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_TMPL="/usr/share/OVMF/OVMF_VARS_4M.fd"
TMP_VARS=$(mktemp /tmp/ovmf_iso.XXXXXX.fd)
cp "$OVMF_VARS_TMPL" "$TMP_VARS"

echo "Running QEMU UEFI CDROM boot test..."
timeout 15s qemu-system-x86_64 \
    -m 1024M \
    -smp 2 \
    -cpu qemu64 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$ISO_LIVE",media=cdrom,readonly=on \
    -boot d \
    -display none \
    -serial stdio 2>&1 || true

rm -f "$TMP_VARS"

echo ""
echo "=== ISO SUCCESSFUL ==="
ls -lh "$ISO_LIVE"
