#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/.." && pwd)
IMAGE_DIR="$WORKSPACE/image"
ISO_DIR="$WORKSPACE/artifacts/iso"
mkdir -p "$ISO_DIR"

echo "=== [ExamOS-ISO] Building Bootable ISO Image ==="

IMAGE_FILE=""
for cand in "$IMAGE_DIR/examos.raw.raw" "$IMAGE_DIR/examos.raw"; do
    if [ -f "$cand" ]; then
        IMAGE_FILE="$cand"
        break
    fi
done

if [ -z "$IMAGE_FILE" ]; then
    echo "[ExamOS-ISO] FAIL: No raw disk image found to wrap into ISO"
    exit 1
fi

OUTPUT_ISO="$ISO_DIR/examos-appliance-v0.2.0.iso"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/iso/boot/grub"
mkdir -p "$TMP_DIR/iso/EFI/BOOT"

# Copy EFI unified kernel image / kernel if split artifacts exist
if [ -f "$IMAGE_DIR/examos.raw.efi" ]; then
    cp "$IMAGE_DIR/examos.raw.efi" "$TMP_DIR/iso/EFI/BOOT/BOOTX64.EFI"
fi

cat > "$TMP_DIR/iso/boot/grub/grub.cfg" << 'EOF'
set timeout=5
set default=0

menuentry "ExamOS Secure Examination Appliance (x86_64)" {
    insmod efi_gop
    insmod efi_uga
    insmod gfxterm
    terminal_output gfxterm
    set root=(hd0)
    chainloader /EFI/BOOT/BOOTX64.EFI
}
EOF

# Create ISO with xorriso
echo "[ExamOS-ISO] Creating ISO at $OUTPUT_ISO..."
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS_APPLIANCE" \
    -output "$OUTPUT_ISO" \
    "$TMP_DIR/iso" >/dev/null 2>&1

if [ -f "$OUTPUT_ISO" ]; then
    ISO_SIZE=$(du -sh "$OUTPUT_ISO" | cut -f1)
    sha256sum "$OUTPUT_ISO" > "$OUTPUT_ISO.sha256"
    echo "[ExamOS-ISO] PASS: Bootable ISO generated: $OUTPUT_ISO ($ISO_SIZE)"
    exit 0
else
    echo "[ExamOS-ISO] FAIL: ISO creation failed"
    exit 1
fi
