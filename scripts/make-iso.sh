#!/usr/bin/env bash
# ExamOS ISO Builder — wraps output/examos.efi into a UEFI-bootable ISO
# Usage: bash scripts/make-iso.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT/output"
ISO_DIR="$ROOT/artifacts/iso"
ISO_OUT="$ISO_DIR/examos-appliance-v0.2.0-new.iso"

EFI_SRC=""
for c in "$OUTPUT_DIR/examos.efi" "$ROOT/image/examos.raw.efi" "$ROOT/image/examos.efi"; do
    [ -f "$c" ] && { EFI_SRC="$c"; break; }
done
[ -z "$EFI_SRC" ] && { echo "ERROR: No EFI artifact found. Run build-full-image.sh first." >&2; exit 1; }

mkdir -p "$ISO_DIR"
STAGING=$(mktemp -d /tmp/examos-iso.XXXXXX)
# trap set after TMP_ISO is created below

mkdir -p "$STAGING/EFI/BOOT" "$STAGING/boot/grub"
cp "$EFI_SRC" "$STAGING/EFI/BOOT/BOOTX64.EFI"

cat > "$STAGING/boot/grub/grub.cfg" <<'GRUB'
set timeout=5
set default=0
menuentry "ExamOS Secure Examination Appliance" {
    insmod efi_gop
    chainloader /EFI/BOOT/BOOTX64.EFI
}
GRUB

# xorriso cannot write directly to NTFS/Windows mounts — build in /tmp then copy
TMP_ISO=$(mktemp /tmp/examos-XXXXXX.iso)
trap 'rm -rf -- "$STAGING" "$TMP_ISO"' EXIT

echo "[ExamOS-ISO] Building ISO from $EFI_SRC ..."
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS_APPLIANCE" \
    -output "$TMP_ISO" \
    "$STAGING" 2>&1

cp "$TMP_ISO" "$ISO_OUT"

if [ -s "$ISO_OUT" ]; then
    sha256sum "$ISO_OUT" | tee "$ISO_OUT.sha256"
    du -sh "$ISO_OUT"
    echo ""
    echo "=================================================="
    echo "  ISO built: $ISO_OUT"
    echo "  Boot in QEMU: qemu-system-x86_64 -cdrom '$ISO_OUT' ..."
    echo "=================================================="
else
    echo "ERROR: ISO creation failed." >&2
    exit 1
fi
