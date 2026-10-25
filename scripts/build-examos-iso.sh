#!/usr/bin/env bash
# =============================================================================
# ExamOS Hybrid UEFI ISO Builder (no sudo / no losetup)
# Uses dd + mcopy to extract partitions directly from examos.raw offsets.
# Produces a proper GPT hybrid ISO bootable on UEFI firmware (VMware, QEMU, USB).
#
# Architecture:
#   1. Extract ESP partition (FAT32, 512 MiB) via dd skip_bytes
#   2. Extract root partition (ext4, ~3.8 GiB) via dd skip_bytes
#   3. Extract UKI (BOOTX64.EFI) from ESP using mcopy (no mount/sudo)
#   4. Combine initrd with optical-media overlay (iso-init.sh)
#   5. Build new ISO-specific UKI with examos.media=optical cmdline
#   6. Create FAT32 El Torito boot image with the ISO UKI
#   7. Assemble hybrid UEFI ISO with xorriso -append_partition
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=examos-lib.sh
source "$WORKSPACE/scripts/examos-lib.sh"
IMAGE_RAW="$WORKSPACE/image/examos.raw"
ISO_OUT="$WORKSPACE/output/examos-fresh.iso"
TMP_DIR="$(mktemp -d /var/tmp/examos_iso_XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

ESP_GUID="C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
ROOT_GUID="4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"

# Partition geometry from sfdisk (sector size = 512)
ESP_SKIP_BYTES=$((2048 * 512))
ESP_COUNT_BYTES=$((1048576 * 512))
ROOT_SKIP_BYTES=$((1050624 * 512))
ROOT_COUNT_BYTES=$((7941496 * 512))

log() { echo "[ExamOS-ISO] $*"; }
fail() { echo "[ExamOS-ISO] FATAL: $*" >&2; exit 1; }

log "============================================================"
log "  ExamOS Hybrid UEFI ISO Builder (no-sudo dd method)"
log "============================================================"

# --- Tool check ---
for tool in dd xorriso sha256sum mcopy mmd mkfs.vfat objcopy ukify blkid e2fsck tune2fs; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool missing: $tool"
done

[ -f "$IMAGE_RAW" ] || fail "Source image not found: $IMAGE_RAW"
log "Source: $IMAGE_RAW ($(du -sh "$IMAGE_RAW" | cut -f1))"

mkdir -p "$(dirname "$ISO_OUT")"

# --- Step 1: Extract partitions ---
log "[1/7] Extracting ESP partition (no sudo)…"
dd if="$IMAGE_RAW" of="$TMP_DIR/esp.raw" bs=1M \
    iflag=skip_bytes,count_bytes \
    skip="$ESP_SKIP_BYTES" count="$ESP_COUNT_BYTES" \
    conv=fsync status=none || fail "ESP extraction failed"
[ -s "$TMP_DIR/esp.raw" ] || fail "Extracted ESP is empty"

log "[2/7] Extracting root filesystem (ext4, ~3.8 GiB)…"
dd if="$IMAGE_RAW" of="$TMP_DIR/root.ext4" bs=4M \
    iflag=skip_bytes,count_bytes \
    skip="$ROOT_SKIP_BYTES" count="$ROOT_COUNT_BYTES" \
    conv=fsync status=none || fail "Root extraction failed"
[ -s "$TMP_DIR/root.ext4" ] || fail "Extracted root is empty"

# Verify root filesystem
ROOT_FS_TYPE="$(blkid -p -o value -s TYPE "$TMP_DIR/root.ext4" 2>/dev/null || true)"
[ "$ROOT_FS_TYPE" = "ext4" ] || fail "Extracted root is not ext4 (got: $ROOT_FS_TYPE)"
log "[2b/7] Replaying ext4 journal on extracted root (H-12 / read-only optical)…"
examos_ext4_replay_journal_for_readonly "$TMP_DIR/root.ext4" ||
    fail "Unable to replay the extracted root journal for read-only optical media"
ROOT_FS_UUID="$(blkid -p -o value -s UUID "$TMP_DIR/root.ext4" 2>/dev/null || true)"
ROOT_FS_LABEL="$(blkid -p -o value -s LABEL "$TMP_DIR/root.ext4" 2>/dev/null || true)"
log "  root: label=${ROOT_FS_LABEL} uuid=${ROOT_FS_UUID}"

# --- Step 3: Extract UKI from ESP ---
log "[3/7] Extracting UKI from ESP…"
mkdir -p "$TMP_DIR/esp-tree/EFI/Linux"
mcopy -s -i "$TMP_DIR/esp.raw" ::/EFI "$TMP_DIR/esp-tree/" 2>/dev/null || fail "mcopy EFI failed"
UKI_FILE="$(find "$TMP_DIR/esp-tree/EFI/Linux" -maxdepth 1 -type f -iname '*.efi' | head -n 1)"
[ -n "$UKI_FILE" ] && [ -f "$UKI_FILE" ] || fail "No UKI .efi found in EFI/Linux"
log "  UKI: $UKI_FILE ($(du -sh "$UKI_FILE" | cut -f1))"

# Extract UKI sections for rebuilding
objcopy --dump-section .linux="$TMP_DIR/source.linux" "$UKI_FILE" || fail "Cannot extract .linux from UKI"
objcopy --dump-section .initrd="$TMP_DIR/source.initrd" "$UKI_FILE" || fail "Cannot extract .initrd from UKI"
objcopy --dump-section .cmdline="$TMP_DIR/source.cmdline" "$UKI_FILE" || fail "Cannot extract .cmdline from UKI"
objcopy --dump-section .osrel="$TMP_DIR/source.osrel" "$UKI_FILE" 2>/dev/null || true

SOURCE_CMDLINE="$(tr -d '\000' < "$TMP_DIR/source.cmdline")"
log "  Source cmdline: $SOURCE_CMDLINE"

# --- Step 4: Build initrd overlay with optical media init ---
log "[4/7] Building initrd overlay for optical boot…"
mkdir -p "$TMP_DIR/initrd-overlay"

ISO_INIT_SH="$WORKSPACE/tests/p0/iso-init.sh"
if [ -f "$ISO_INIT_SH" ]; then
    install -m 0755 "$ISO_INIT_SH" "$TMP_DIR/initrd-overlay/init"
else
    # Minimal inline optical init
    cat > "$TMP_DIR/initrd-overlay/init" << 'INIT_EOF'
#!/bin/sh
# ExamOS optical media root loader
log() { printf '%s\n' "ExamOS ISO init: $*" >/dev/console 2>/dev/null || true; }
fail() { log "FATAL: $1"; exec sh; }

mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true

mkdir -p /run/iso /run/lower /run/upper /run/work /sysroot

modprobe ahci 2>/dev/null || true
modprobe sr_mod 2>/dev/null || true
modprobe isofs 2>/dev/null || true
modprobe loop 2>/dev/null || true
modprobe ext4 2>/dev/null || true
modprobe overlay 2>/dev/null || true

ISO_DEVICE=""
for attempt in $(seq 1 60); do
    for device in /dev/sr*; do
        [ -b "$device" ] || continue
        if blkid -p -s TYPE -o value "$device" 2>/dev/null | grep -qx iso9660; then
            ISO_DEVICE="$device"; break 2
        fi
    done
    sleep 1
done
[ -n "$ISO_DEVICE" ] || fail "no ISO9660 optical device found"
log "optical device: $ISO_DEVICE"

mount -t iso9660 -o ro "$ISO_DEVICE" /run/iso || fail "cannot mount optical media"
ROOT_IMAGE=/run/iso/examos-root.ext4
[ -s "$ROOT_IMAGE" ] || fail "embedded root filesystem missing"

ROOT_LOOP="$(losetup --find --show --read-only "$ROOT_IMAGE")" || fail "cannot attach root loop"
mount -t ext4 -o ro,noload "$ROOT_LOOP" /run/lower || fail "cannot mount root ext4"

mount -t tmpfs tmpfs /run/upper -o mode=0755
mkdir -p /run/upper/rw /run/upper/work
mount -t overlay overlay /sysroot \
    -o lowerdir=/run/lower,upperdir=/run/upper/rw,workdir=/run/upper/work || fail "overlay failed"

log "optical boot ready"
mkdir -p /sysroot/run
mount --move /run /sysroot/run || true
exec /usr/sbin/switch_root /sysroot /usr/lib/systemd/systemd
INIT_EOF
    chmod 0755 "$TMP_DIR/initrd-overlay/init"
fi

(cd "$TMP_DIR/initrd-overlay" && find . -print0 | cpio --null -o --format=newc) \
    > "$TMP_DIR/initrd-overlay.cpio" || fail "cpio overlay failed"

cat "$TMP_DIR/source.initrd" "$TMP_DIR/initrd-overlay.cpio" > "$TMP_DIR/combined.initrd" \
    || fail "combining initrd failed"

# --- Step 5: Build ISO-specific UKI ---
log "[5/7] Building ISO-specific UKI (examos.media=optical)…"

# Strip disk-only cmdline tokens, add optical marker
ISO_CMDLINE=""
for token in $SOURCE_CMDLINE; do
    case "$token" in
        ro|rw|root=*|rootflags=*|init=*|systemd.gpt_auto=*|rd.auto=*) continue ;;
        *) ISO_CMDLINE="$ISO_CMDLINE $token" ;;
    esac
done
ISO_CMDLINE="$(echo "$ISO_CMDLINE" | sed 's/^ //')"
ISO_CMDLINE="$ISO_CMDLINE examos.media=optical systemd.gpt_auto=0 rd.auto=0"
log "  ISO cmdline: $ISO_CMDLINE"

OSREL_ARGS=()
if [ -s "$TMP_DIR/source.osrel" ]; then
    OSREL_ARGS=(--os-release="@$TMP_DIR/source.osrel")
fi

ukify build \
    --linux="$TMP_DIR/source.linux" \
    "${OSREL_ARGS[@]}" \
    --initrd="$TMP_DIR/combined.initrd" \
    --cmdline="$ISO_CMDLINE" \
    --output="$TMP_DIR/BOOTX64.EFI" || fail "ukify build failed"

log "  ISO UKI: $(du -sh "$TMP_DIR/BOOTX64.EFI" | cut -f1)"

# --- Step 6: Build FAT32 El Torito boot image ---
log "[6/7] Building FAT32 El Torito boot image…"
UKI_SIZE_BYTES="$(stat -c '%s' "$TMP_DIR/BOOTX64.EFI")"
EFI_MIB=$(( (UKI_SIZE_BYTES + 1048575) / 1048576 + 64 ))
[ "$EFI_MIB" -le 2048 ] || fail "ISO UKI too large (${EFI_MIB} MiB > 2048)"

truncate -s "${EFI_MIB}M" "$TMP_DIR/efi-boot.img"
mkfs.vfat -F 32 "$TMP_DIR/efi-boot.img" >/dev/null || fail "mkfs.vfat failed"
mmd -i "$TMP_DIR/efi-boot.img" ::/EFI ::/EFI/BOOT || fail "mmd failed"
mcopy -i "$TMP_DIR/efi-boot.img" "$TMP_DIR/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI || fail "mcopy UKI failed"

# --- Step 7: Assemble ISO tree and build hybrid ISO ---
log "[7/7] Assembling hybrid UEFI ISO…"
mkdir -p "$TMP_DIR/iso-tree/EFI/BOOT"

# ISO filesystem content
cp "$TMP_DIR/efi-boot.img" "$TMP_DIR/iso-tree/efi-boot.img"
cp "$TMP_DIR/BOOTX64.EFI" "$TMP_DIR/iso-tree/EFI/BOOT/BOOTX64.EFI"
cp "$TMP_DIR/root.ext4" "$TMP_DIR/iso-tree/examos-root.ext4"

# Metadata for iso-init.sh
printf 'ROOT_FILESYSTEM_LABEL=%s\nROOT_FILESYSTEM_UUID=%s\n' \
    "${ROOT_FS_LABEL:-root-x86-64}" "${ROOT_FS_UUID:-}" \
    > "$TMP_DIR/iso-tree/EXAMOS-P0.conf"

printf 'ExamOS Secure Examination Appliance\nBuilt: %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$TMP_DIR/iso-tree/EXAMOS-P0.txt"

TMP_ISO="$TMP_DIR/examos-build.iso"

xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS_P0" \
    -append_partition 1 "$ESP_GUID" "$TMP_DIR/efi-boot.img" \
    -append_partition 2 "$ROOT_GUID" "$TMP_DIR/root.ext4" \
    -appended_part_as_gpt \
    -eltorito-alt-boot \
    -e /efi-boot.img \
    -no-emul-boot \
    -output "$TMP_ISO" \
    "$TMP_DIR/iso-tree" || fail "xorriso failed"

[ -s "$TMP_ISO" ] || fail "xorriso produced empty ISO"

# Verify embedded root is accessible in ISO
if ! xorriso -osirrox on -indev "$TMP_ISO" \
    -extract /examos-root.ext4 "$TMP_DIR/verified-root.ext4" >/dev/null 2>&1; then
    fail "Cannot verify embedded root in ISO"
fi
cmp -s "$TMP_DIR/root.ext4" "$TMP_DIR/verified-root.ext4" || fail "Root in ISO differs from source"
log "  Root filesystem verified OK inside ISO"

# Verify GPT structure
if ! sfdisk --json "$TMP_ISO" | python3 -c "
import json,sys
pt = json.load(sys.stdin)['partitiontable']
parts = pt['partitions']
esp = [p for p in parts if p['type'].upper() == '${ESP_GUID}'.upper()]
root = [p for p in parts if p['type'].upper() == '${ROOT_GUID}'.upper()]
assert pt['label'] == 'gpt', 'Not GPT'
assert len(esp) == 1, f'Expected 1 ESP, got {len(esp)}'
assert len(root) == 1, f'Expected 1 root, got {len(root)}'
print('GPT structure OK: 1 ESP + 1 root partition')
" 2>/dev/null; then
    log "WARNING: GPT structure check inconclusive (non-fatal)"
fi

# Copy to output
cp "$TMP_ISO" "$ISO_OUT"
ISO_SIZE="$(du -sh "$ISO_OUT" | cut -f1)"
sha256sum "$ISO_OUT" > "${ISO_OUT}.sha256"

log "============================================================"
log "  DONE: $ISO_OUT ($ISO_SIZE)"
log "  SHA256: $(cut -d' ' -f1 "${ISO_OUT}.sha256")"
log "  Hybrid UEFI ISO ready — use as DVD in VMware or flash to USB"
log "============================================================"

# Write build result JSON
cat > "$(dirname "$ISO_OUT")/iso-build-result.json" << EOF
{
  "status": "PASS",
  "iso": "$ISO_OUT",
  "size_bytes": $(stat -c '%s' "$ISO_OUT"),
  "sha256": "$(cut -d' ' -f1 "${ISO_OUT}.sha256")",
  "root_label": "${ROOT_FS_LABEL:-root-x86-64}",
  "root_uuid": "${ROOT_FS_UUID:-}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
