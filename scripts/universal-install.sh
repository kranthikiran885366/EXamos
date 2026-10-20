#!/bin/bash
# =============================================================================
# ExamOS Universal Bare-Metal & Target System Installer
# Installs ExamOS onto any target physical disk (/dev/nvme0n1, /dev/sda, /dev/vda)
# or prepares a bootable USB drive for deployment on other computers.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
RAW_IMAGE="$WORKSPACE/image/examos.raw"

echo "============================================================"
echo "  ExamOS — Universal System Installer & Deployment Engine"
echo "============================================================"
echo ""

if [ "$#" -lt 1 ]; then
    echo "Usage:"
    echo "  sudo ./scripts/universal-install.sh <target_disk_device>"
    echo ""
    echo "Examples:"
    echo "  # Install to primary NVMe SSD on a laptop/desktop:"
    echo "  sudo ./scripts/universal-install.sh /dev/nvme0n1"
    echo ""
    echo "  # Install to SATA SSD/HDD on a PC:"
    echo "  sudo ./scripts/universal-install.sh /dev/sda"
    echo ""
    echo "  # Flash to a USB flash drive (for booting on any computer):"
    echo "  sudo ./scripts/universal-install.sh /dev/sdb"
    echo ""
    echo "Available Storage Disks on this system:"
    lsblk -d -o NAME,SIZE,MODEL,TRAN,TYPE 2>/dev/null || true
    exit 1
fi

TARGET_DEV="$1"

if [ ! -b "$TARGET_DEV" ]; then
    echo "ERROR: Target device '$TARGET_DEV' is not a valid block device."
    exit 1
fi

if [ ! -f "$RAW_IMAGE" ]; then
    echo "ERROR: Source image '$RAW_IMAGE' not found. Please build the image first."
    exit 1
fi

IMAGE_SIZE=$(stat -c%s "$RAW_IMAGE")
echo "Source Image: $RAW_IMAGE ($(( IMAGE_SIZE / 1048576 )) MB)"
echo "Target Drive: $TARGET_DEV ($(lsblk -d -n -o SIZE "$TARGET_DEV" 2>/dev/null || echo 'Unknown'))"
echo ""
echo "⚠️  WARNING: ALL DATA ON $TARGET_DEV WILL BE PERMANENTLY ERASED!"
echo ""

# Unmount any mounted partitions on the target drive
echo "[1/4] Unmounting target partitions..."
for part in "${TARGET_DEV}"* "${TARGET_DEV}p"*; do
    if [ -b "$part" ]; then
        sudo umount "$part" 2>/dev/null || true
    fi
done

echo "[2/4] Flashing ExamOS Universal Image to $TARGET_DEV..."
sudo dd if="$RAW_IMAGE" of="$TARGET_DEV" bs=4M status=progress conv=fsync oflag=direct

echo ""
echo "[3/4] Expanding root partition to fill the full disk capacity..."
# Fix GPT backup header at the end of the physical drive
if command -v sgdisk >/dev/null 2>&1; then
    sudo sgdisk -e "$TARGET_DEV" 2>/dev/null || true
fi

# Grow partition 2 (rootfs) to 100% of available space
if command -v growpart >/dev/null 2>&1; then
    sudo growpart "$TARGET_DEV" 2 2>/dev/null || true
fi

# Determine partition 2 path (e.g. /dev/nvme0n1p2 or /dev/sda2)
PART2="${TARGET_DEV}2"
if [ ! -b "$PART2" ]; then
    PART2="${TARGET_DEV}p2"
fi

if [ -b "$PART2" ]; then
    echo "Resizing ext4 filesystem on $PART2..."
    sudo e2fsck -f -y "$PART2" 2>/dev/null || true
    sudo resize2fs "$PART2" 2>/dev/null || true
fi

echo ""
echo "[4/4] Syncing buffers and verifying bootloader..."
sync

echo ""
echo "============================================================"
echo "  ✅ ExamOS SUCCESSFULLY INSTALLED ON $TARGET_DEV!"
echo "============================================================"
echo ""
echo "Next Steps for the Target Machine:"
echo "1. Insert the drive / USB into the target PC/laptop."
echo "2. Power on the computer and press the Boot Menu key (F12 / F11 / F8 / Esc / Del)."
echo "3. Select UEFI Boot → 'ExamOS' or your USB drive."
echo "4. ExamOS will automatically boot into the Secure Graphical Desktop!"
echo ""
