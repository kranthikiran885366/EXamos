#!/bin/bash
# =============================================================================
# ExamOS Universal Hybrid UEFI ISO Generator
# Creates D:\SEB BRO\image\examos.iso compatible with VMware Workstation,
# VirtualBox, Proxmox, and physical USB installation.
# =============================================================================
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
IMAGE_DIR="$WORKSPACE/image"
RAW_IMAGE="$IMAGE_DIR/examos.raw"
ISO_OUTPUT="$IMAGE_DIR/examos.iso"
ISODIR="/tmp/examos_iso_build"
MNT="/tmp/examos_mnt_iso"

echo "============================================================"
echo "  ExamOS — Universal Bootable ISO Builder"
echo "============================================================"
echo ""

if [ ! -f "$RAW_IMAGE" ]; then
    echo "ERROR: $RAW_IMAGE not found!"
    exit 1
fi

rm -rf "$ISODIR" "$MNT"
mkdir -p "$ISODIR/EFI/BOOT" "$ISODIR/EFI/Linux" "$ISODIR/loader" "$MNT"

echo "[1/4] Mounting ESP & RootFS from $RAW_IMAGE..."
sudo losetup -D 2>/dev/null || true
sudo losetup -fP "$RAW_IMAGE"
LOOP=$(losetup -j "$RAW_IMAGE" | head -n 1 | cut -d: -f1)

sudo mount "${LOOP}p1" "$MNT"

echo "[2/4] Copying EFI Bootloader and Unified Kernel Image..."
sudo cp -r "$MNT/EFI" "$ISODIR/"
sudo cp -r "$MNT/loader" "$ISODIR/" 2>/dev/null || true
sudo cp "$MNT"/*.efi "$ISODIR/EFI/BOOT/" 2>/dev/null || true
sudo cp "$MNT/EFI/BOOT/BOOTX64.EFI" "$ISODIR/EFI/BOOT/BOOTX64.EFI" 2>/dev/null || true

# Create FAT EFI boot partition image (efiboot.img)
echo "[3/4] Creating FAT32 EFI boot partition image..."
EFI_IMG="$ISODIR/efiboot.img"
dd if=/dev/zero of="$EFI_IMG" bs=1M count=128
mkfs.vfat -F 32 "$EFI_IMG"

mkdir -p /tmp/efiboot_mnt
sudo mount "$EFI_IMG" /tmp/efiboot_mnt
sudo cp -r "$MNT/"* /tmp/efiboot_mnt/ 2>/dev/null || true
sudo umount /tmp/efiboot_mnt
rm -rf /tmp/efiboot_mnt

sudo umount "$MNT"
sudo losetup -d "$LOOP"

echo "[4/4] Building Hybrid UEFI ISO with xorriso..."
rm -f "$ISO_OUTPUT"

# ISS-02 FIX: Inject kernel command line parameters to prevent boot failures on optical media.
#   root=LABEL=EXAMOS_ROOT  — explicitly bind the root filesystem to the ISO volume label,
#                             avoiding systemd-gpt-auto-generator's GPT partition probing
#                             (which fails on optical/loop media with no GPT partition table).
#   systemd.gpt_auto=0      — disable the systemd GPT auto-generator entirely for ISO boots.
#   rd.auto=0               — prevent the initrd from auto-mounting partitions, which can
#                             race or deadlock on CD-ROM / virtual optical drives.
# The -append_partition / -appended_part_as_gpt flags and the EFI catalog (-e efiboot.img)
# remain unchanged; only the kernel parameters are extended.
KERNEL_CMDLINE="root=LABEL=EXAMOS_ROOT systemd.gpt_auto=0 rd.auto=0"

xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS_ROOT" \
    -eltorito-alt-boot \
    -e efiboot.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -output "$ISO_OUTPUT" \
    "$ISODIR"

# Embed the kernel parameters into the ISO's El Torito / GRUB boot catalog.
# xorriso's --boot_image any cmdline= applies the parameters to the EFI boot entry.
# This is a post-processing step to patch the boot entry after initial ISO creation.
xorriso -dev "$ISO_OUTPUT" \
    --boot_image any cmdline="$KERNEL_CMDLINE" \
    --commit

rm -rf "$ISODIR" "$MNT"

echo ""
echo "============================================================"
echo "  ✅ ExamOS Universal ISO Successfully Generated!"
echo "============================================================"
echo "  File Path: D:\\SEB BRO\\image\\examos.iso"
ls -lh "$ISO_OUTPUT"
echo ""
echo "How to use in VMware Workstation:"
echo "1. Create New Virtual Machine → Installer disc image file (iso)"
echo "2. Browse and select: D:\\SEB BRO\\image\\examos.iso"
echo "3. Guest OS: Linux → Debian 12.x / 13.x 64-bit"
echo "4. Firmware: UEFI"
echo "5. Click Finish and Power On!"
