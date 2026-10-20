#!/usr/bin/env bash
# Build a hybrid UEFI ISO from the exact P0 disk partitions.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_load_format "$WORKSPACE" || {
    echo "[P0-ISO] BLOCKED: canonical P0 partition format is missing or invalid." >&2
    exit 2
}

fail() {
    local message="$1"
    echo "[P0-ISO] FATAL: $message" >&2
    cat > "$ISO_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_build",
  "status": "FAIL",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "reason": "$message"
}
EOF
    exit 1
}
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-ISO] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}

SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
if ! SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")"; then
    echo "[P0-ISO] FATAL: unable to determine source worktree state." >&2
    exit 2
fi
if [ -n "$SOURCE_STATUS" ]; then
    echo "[P0-ISO] BLOCKED: refusing to replace P0 ISO evidence from a dirty source tree." >&2
    printf '%s\n' "$SOURCE_STATUS" >&2
    exit 2
fi
SOURCE_STATUS_AT_START="$SOURCE_STATUS"
SOURCE_COMMIT_AT_START="$SOURCE_COMMIT"
DIRTY_PATH_COUNT=0
if [ -n "$SOURCE_STATUS" ]; then
    DIRTY_PATH_COUNT="$(printf '%s\n' "$SOURCE_STATUS" | wc -l | tr -d ' ')"
fi
SOURCE_TREE_STATE="CLEAN"
[ "$DIRTY_PATH_COUNT" -eq 0 ] || SOURCE_TREE_STATE="DIRTY"

mkdir -p "$ARTIFACT_DIR"
ISO_FILE="$ARTIFACT_DIR/examos-p0.iso"
ISO_HASH_FILE="$ARTIFACT_DIR/iso.sha256"
ISO_RESULT="$ARTIFACT_DIR/iso-build-result.json"
TMP_DIR=""
for output in "$ISO_FILE" "$ISO_HASH_FILE" "$ISO_RESULT" "$ARTIFACT_DIR/iso-boot-result.json"; do
    if [ -e "$output" ] || [ -L "$output" ]; then
        echo "[P0-ISO] FATAL: evidence output already exists; refusing to overwrite: $output" >&2
        exit 2
    fi
done
cat > "$ISO_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_build",
  "status": "IN_PROGRESS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

for tool in jq sfdisk xorriso sha256sum mcopy mmd mkfs.vfat objcopy ukify blkid cmp; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required ISO build tool is missing: $tool"
done

IMAGE_PROFILE="p0-canonical"
IMAGE_OVERRIDE="${EXAMOS_P0_IMAGE_SOURCE:-}"
if [ -n "$IMAGE_OVERRIDE" ]; then
    [ "${EXAMOS_P0_ALLOW_DEV_SOURCE:-0}" = "1" ] ||
        fail "An alternate source image requires EXAMOS_P0_ALLOW_DEV_SOURCE=1"
    IMAGE_FILE="$(realpath -e -- "$IMAGE_OVERRIDE")" || fail "Alternate source image cannot be resolved"
    case "$IMAGE_FILE" in
        "$WORKSPACE"/*) ;;
        *) fail "Alternate source image must remain inside the workspace" ;;
    esac
    [ -f "$IMAGE_FILE" ] && [ -s "$IMAGE_FILE" ] && [ ! -L "$IMAGE_FILE" ] ||
        fail "Alternate source image must be a non-empty regular file, not a symlink"
    IMAGE_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$IMAGE_FILE")"
    IMAGE_PROFILE="development-unqualified"
    SOURCE_HASH="$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)" ||
        fail "Unable to hash alternate development source image"
    echo "[P0-ISO] WARNING: building a development ISO from $IMAGE_RELATIVE; this is not P0 release evidence."
else
    IMAGE_RELATIVE=""
    if [ -s "$ARTIFACT_DIR/image-path.txt" ]; then IFS= read -r IMAGE_RELATIVE < "$ARTIFACT_DIR/image-path.txt"; fi
    EXPECTED_IMAGE_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.raw")" ||
        fail "Unable to resolve this P0 run's image path"
    [ "$IMAGE_RELATIVE" = "$EXPECTED_IMAGE_RELATIVE" ] || fail "P0 disk artifact path is absent or does not belong to this run"

    IMAGE_FILE="$WORKSPACE/$IMAGE_RELATIVE"
    [ -f "$IMAGE_FILE" ] && [ -s "$IMAGE_FILE" ] && [ ! -L "$IMAGE_FILE" ] ||
        fail "Canonical P0 disk image is missing or invalid"
    [ -s "$ARTIFACT_DIR/image.sha256" ] || fail "P0 disk checksum is missing"
    sha256sum --check "$ARTIFACT_DIR/image.sha256" ||
        fail "P0 disk checksum verification failed"
    SOURCE_HASH="$(cut -d' ' -f1 "$ARTIFACT_DIR/image.sha256")"
fi
# ISO assembly temporarily needs the extracted partitions, a rebuilt UKI, and
# the complete output at once.  Use a Linux-native filesystem by default:
# DrvFS is both much slower for this workload and incompatible with some
# objcopy metadata operations.  Refuse to start without 3 GiB free.
STAGING_BASE="${EXAMOS_P0_STAGING_DIR:-/var/tmp}"
[ -d "$STAGING_BASE" ] && [ -w "$STAGING_BASE" ] ||
    fail "ISO staging directory is unavailable or not writable: $STAGING_BASE"
STAGING_FREE_KIB="$(df -Pk "$STAGING_BASE" | awk 'NR == 2 { print $4 }')"
case "$STAGING_FREE_KIB" in
    ''|*[!0-9]*) fail "Unable to determine free space for ISO staging" ;;
esac
[ "$STAGING_FREE_KIB" -ge 3145728 ] ||
    fail "ISO staging requires at least 3 GiB free in $STAGING_BASE"
TMP_DIR="$(mktemp -d "$STAGING_BASE/examos-p0-iso.XXXXXX")"
NATIVE_TMP_DIR="$(mktemp -d "$STAGING_BASE/examos-p0-uki.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$NATIVE_TMP_DIR"' EXIT
ESP_FILE="$TMP_DIR/p0-esp.img"
ROOT_FILE="$TMP_DIR/p0-root.img"
TMP_ISO="$TMP_DIR/examos-p0.iso"
ISO_TREE="$TMP_DIR/iso-tree"
INITRD_OVERLAY="$TMP_DIR/initrd-overlay"
COMBINED_INITRD="$TMP_DIR/combined.initrd"
mkdir -p "$ISO_TREE"

PARTITION_LAYOUT="$(sfdisk --json "$IMAGE_FILE" | jq -er \
    --arg esp_guid "$EXAMOS_P0_ESP_TYPE_GUID" \
    --arg root_guid "$EXAMOS_P0_ROOT_TYPE_GUID" '
    .partitiontable as $table
    | ($table.partitions | map(select((.type | ascii_downcase) == ($esp_guid | ascii_downcase)))) as $esp
    | ($table.partitions | map(select((.type | ascii_downcase) == ($root_guid | ascii_downcase)))) as $root
    | if $table.label != "gpt" then error("P0 disk is not GPT")
      elif ($table.sectorsize | type) != "number" or $table.sectorsize <= 0 then error("invalid sector size")
      elif ($esp | length) != 1 then error("expected exactly one EFI System Partition")
      elif ($root | length) != 1 then error("expected exactly one Linux root partition")
      elif ([$esp[0].start, $esp[0].size, $root[0].start, $root[0].size] | all(.[]; type == "number" and floor == . and . > 0)) | not then error("invalid partition geometry")
      else [$table.sectorsize, $esp[0].start, $esp[0].size, $root[0].start, $root[0].size] | @tsv
      end
')" || fail "Unable to parse canonical GPT partition geometry"
IFS=$'\t' read -r SECTOR_SIZE ESP_START ESP_SIZE ROOT_START ROOT_SIZE <<< "$PARTITION_LAYOUT"
for value in "$SECTOR_SIZE" "$ESP_START" "$ESP_SIZE" "$ROOT_START" "$ROOT_SIZE"; do
    case "$value" in
        ''|*[!0-9]*) fail "Canonical GPT has invalid numeric partition geometry" ;;
    esac
done
ESP_SKIP_BYTES=$((ESP_START * SECTOR_SIZE))
ESP_COUNT_BYTES=$((ESP_SIZE * SECTOR_SIZE))
ROOT_SKIP_BYTES=$((ROOT_START * SECTOR_SIZE))
ROOT_COUNT_BYTES=$((ROOT_SIZE * SECTOR_SIZE))
dd if="$IMAGE_FILE" of="$ESP_FILE" bs=4M \
    iflag=skip_bytes,count_bytes skip="$ESP_SKIP_BYTES" count="$ESP_COUNT_BYTES" \
    conv=fsync status=none ||
    fail "Unable to extract the canonical EFI System Partition"
dd if="$IMAGE_FILE" of="$ROOT_FILE" bs=4M \
    iflag=skip_bytes,count_bytes skip="$ROOT_SKIP_BYTES" count="$ROOT_COUNT_BYTES" \
    conv=fsync status=none ||
    fail "Unable to extract the canonical Linux root partition"

[ -s "$ESP_FILE" ] && [ -s "$ROOT_FILE" ] ||
    fail "Extracted P0 EFI or root partition is empty"
mkdir -p "$TMP_DIR/esp-tree"
mcopy -s -i "$ESP_FILE" ::/EFI "$TMP_DIR/esp-tree/" ||
    fail "Unable to inspect the EFI System Partition contents"
mapfile -t UKIS < <(find "$TMP_DIR/esp-tree/EFI/Linux" -maxdepth 1 -type f -iname '*.efi' 2>/dev/null)
[ "${#UKIS[@]}" -eq 1 ] ||
    fail "Expected exactly one Unified Kernel Image in the P0 EFI partition, found ${#UKIS[@]}"

# GNU objcopy attempts metadata operations that DrvFS does not implement while
# reading PE/COFF sections.  Inspect a byte-identical WSL-native copy and prove
# the copy before extracting any UKI component.
SOURCE_UKI_NATIVE="$NATIVE_TMP_DIR/source.efi"
cp "${UKIS[0]}" "$SOURCE_UKI_NATIVE" || fail "Unable to stage the canonical UKI for inspection"
cmp -s "${UKIS[0]}" "$SOURCE_UKI_NATIVE" ||
    fail "Staged UKI differs from the canonical EFI partition payload"

ROOT_FS_TYPE="$(blkid -p -o value -s TYPE "$ROOT_FILE" 2>/dev/null || true)"
[ "$ROOT_FS_TYPE" = "ext4" ] ||
    fail "Extracted root partition is not a recognized ext4 filesystem"
ROOT_FS_LABEL="$(blkid -p -o value -s LABEL "$ROOT_FILE" 2>/dev/null || true)"
[ "$ROOT_FS_LABEL" = "root-x86-64" ] ||
    fail "Extracted root partition label is not root-x86-64"
ROOT_FS_UUID="$(blkid -p -o value -s UUID "$ROOT_FILE" 2>/dev/null || true)"
[ -n "$ROOT_FS_UUID" ] || fail "Extracted root partition has no filesystem UUID"

objcopy --dump-section .linux="$TMP_DIR/source.linux" "$SOURCE_UKI_NATIVE" ||
    fail "Unable to extract the canonical UKI kernel"
objcopy --dump-section .initrd="$TMP_DIR/source.initrd" "$SOURCE_UKI_NATIVE" ||
    fail "Unable to extract the canonical UKI initramfs"
objcopy --dump-section .cmdline="$TMP_DIR/source.cmdline" "$SOURCE_UKI_NATIVE" ||
    fail "Unable to extract the canonical UKI command line"
objcopy --dump-section .osrel="$TMP_DIR/source.osrel" "$SOURCE_UKI_NATIVE" ||
    fail "Unable to extract the canonical UKI OS release metadata"
[ -s "$TMP_DIR/source.linux" ] && [ -s "$TMP_DIR/source.initrd" ] ||
    fail "Canonical UKI kernel or initramfs section is empty"
mkdir -p "$INITRD_OVERLAY"
install -m 0755 "$WORKSPACE/tests/p0/iso-init.sh" "$INITRD_OVERLAY/init" ||
    fail "Unable to stage the optical-media initramfs root loader"
(
    cd "$INITRD_OVERLAY"
    find . -print0 | cpio --null -o --format=newc
) > "$TMP_DIR/initrd-overlay.cpio" ||
    fail "Unable to create the optical-media initramfs overlay"
cat "$TMP_DIR/source.initrd" "$TMP_DIR/initrd-overlay.cpio" > "$COMBINED_INITRD" ||
    fail "Unable to combine the canonical initramfs and optical-media root loader"
SOURCE_CMDLINE="$(tr -d '\000' < "$TMP_DIR/source.cmdline")"
if [ "$IMAGE_PROFILE" = "p0-canonical" ]; then
    case " $SOURCE_CMDLINE " in
        *" systemd.unit=multi-user.target "*) ;;
        *) fail "P0 UKI command line does not select multi-user.target" ;;
    esac
else
    case " $SOURCE_CMDLINE " in
        *" systemd.unit=multi-user.target "*|*" systemd.unit=graphical.target "*) ;;
        *) fail "Development UKI must select a recognized systemd target" ;;
    esac
fi
read -r -a SOURCE_CMDLINE_TOKENS <<< "$SOURCE_CMDLINE"
ISO_CMDLINE_TOKENS=()
for token in "${SOURCE_CMDLINE_TOKENS[@]}"; do
    case "$token" in
        ro|rw|root=*|rootflags=*|init=*) continue ;;
        *) ISO_CMDLINE_TOKENS+=("$token") ;;
    esac
done
if [ "$IMAGE_PROFILE" = "p0-canonical" ]; then
    printf '%s\n' "${ISO_CMDLINE_TOKENS[@]}" |
        grep -Fxq "systemd.unit=multi-user.target" ||
        fail "Source UKI does not select systemd.unit=multi-user.target"
fi
ISO_CMDLINE_TOKENS+=(examos.media=optical)
ISO_CMDLINE="${ISO_CMDLINE_TOKENS[*]}"
ISO_UKI="$TMP_DIR/BOOTX64.EFI"
ukify build \
    --linux="$TMP_DIR/source.linux" \
    --os-release="@$TMP_DIR/source.osrel" \
    --initrd="$COMBINED_INITRD" \
    --cmdline="$ISO_CMDLINE" \
    --output="$ISO_UKI" ||
    fail "Unable to build the ISO-specific UKI for the canonical GPT root"
objcopy --dump-section .cmdline="$TMP_DIR/iso.cmdline" "$ISO_UKI" ||
    fail "Unable to verify the ISO-specific UKI command line"
ISO_UKI_CMDLINE="$(tr -d '\000' < "$TMP_DIR/iso.cmdline")"
case " $ISO_UKI_CMDLINE " in
    *" examos.media=optical "*) ;;
    *) fail "ISO-specific UKI does not identify its optical-media boot path" ;;
esac
mkdir -p "$ISO_TREE"
printf 'ExamOS P0 hybrid UEFI media\nSource disk SHA-256: %s\nRoot filesystem UUID: %s\n' \
    "$SOURCE_HASH" "$ROOT_FS_UUID" > "$ISO_TREE/EXAMOS-P0.txt"
printf 'ROOT_FILESYSTEM_LABEL=%s\nROOT_FILESYSTEM_UUID=%s\n' \
    "$ROOT_FS_LABEL" "$ROOT_FS_UUID" > "$ISO_TREE/EXAMOS-P0.conf"
cp "$ROOT_FILE" "$ISO_TREE/examos-root.ext4" ||
    fail "Unable to include the canonical root filesystem for optical boot"

EFI_BOOT_FILE="$TMP_DIR/p0-efi-boot.img"
# Size the FAT32 boot image from the actual UKI payload and reserve filesystem
# metadata/headroom. FAT32 boot media also needs to exceed the FAT16 size range.
UKI_SIZE_BYTES="$(stat -c '%s' "$ISO_UKI")"
case "$UKI_SIZE_BYTES" in ''|*[!0-9]*) fail "Unable to determine ISO UKI size" ;; esac
EFI_BOOT_SIZE_MIB=$(((UKI_SIZE_BYTES + 1048575) / 1048576 + 64))
[ "$EFI_BOOT_SIZE_MIB" -le 2048 ] || fail "ISO UKI exceeds the supported EFI boot image size"
truncate -s "${EFI_BOOT_SIZE_MIB}M" "$EFI_BOOT_FILE"
mkfs.vfat -F 32 "$EFI_BOOT_FILE" >/dev/null ||
    fail "Unable to format the UEFI fallback ESP"
mmd -i "$EFI_BOOT_FILE" ::/EFI ::/EFI/BOOT ||
    fail "Unable to create the ISO UEFI fallback-loader directory"
mcopy -i "$EFI_BOOT_FILE" "$ISO_UKI" ::/EFI/BOOT/BOOTX64.EFI ||
    fail "Unable to install the Unified Kernel Image as the UEFI fallback loader"
mcopy -i "$EFI_BOOT_FILE" ::/EFI/BOOT/BOOTX64.EFI "$TMP_DIR/verified-BOOTX64.EFI" ||
    fail "Unable to read back the UEFI fallback loader"
cmp -s "$ISO_UKI" "$TMP_DIR/verified-BOOTX64.EFI" ||
    fail "UEFI fallback loader differs from the ISO-specific UKI"

# El Torito boots the same FAT image exposed as the GPT ESP. The ext4 root is
# also appended for hybrid disk media and embedded as a file for optical boot.
cp "$EFI_BOOT_FILE" "$ISO_TREE/efi-boot.img" ||
    fail "Unable to stage the UEFI El Torito image"
mkdir -p "$ISO_TREE/EFI/BOOT" ||
    fail "Unable to create the ISO filesystem fallback-loader directory"
cp "$ISO_UKI" "$ISO_TREE/EFI/BOOT/BOOTX64.EFI" ||
    fail "Unable to stage the UEFI fallback loader in the ISO filesystem"

echo "[P0-ISO] Creating hybrid UEFI media with the source GPT root..."
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "EXAMOS_P0" \
    -append_partition 1 "$EXAMOS_P0_ESP_TYPE_GUID" "$EFI_BOOT_FILE" \
    -append_partition 2 "$EXAMOS_P0_ROOT_TYPE_GUID" "$ROOT_FILE" \
    -appended_part_as_gpt \
    -eltorito-alt-boot \
    -e /efi-boot.img \
    -no-emul-boot \
    -output "$TMP_ISO" \
    "$ISO_TREE" || fail "xorriso failed to create the P0 hybrid ISO"

[ -s "$TMP_ISO" ] || fail "xorriso produced an empty ISO"
if ! xorriso -osirrox on -indev "$TMP_ISO" \
    -extract /examos-root.ext4 "$TMP_DIR/verified-root.ext4" >/dev/null 2>&1; then
    fail "Unable to verify the embedded optical-boot root filesystem"
fi
cmp -s "$ROOT_FILE" "$TMP_DIR/verified-root.ext4" ||
    fail "Embedded optical-boot root differs from the canonical root partition"
if ! sfdisk --json "$TMP_ISO" | jq -e \
    --arg esp_guid "$EXAMOS_P0_ESP_TYPE_GUID" \
    --arg root_guid "$EXAMOS_P0_ROOT_TYPE_GUID" \
    --argjson esp_bytes "$(stat -c '%s' "$EFI_BOOT_FILE")" \
    --argjson root_bytes "$(stat -c '%s' "$ROOT_FILE")" '
    .partitiontable as $table
    | ($table.partitions | map(select((.type | ascii_downcase) == ($esp_guid | ascii_downcase)))) as $esp
    | ($table.partitions | map(select((.type | ascii_downcase) == ($root_guid | ascii_downcase)))) as $root
    | $table.label == "gpt"
      and ($esp | length) == 1
      and ($root | length) == 1
      and ($esp[0].size * $table.sectorsize) == $esp_bytes
      and ($root[0].size * $table.sectorsize) == $root_bytes
    ' >/dev/null; then
    fail "Generated ISO GPT does not contain the exact canonical ESP and root partitions"
fi
xorriso -indev "$TMP_ISO" -report_el_torito plain > "$TMP_DIR/eltorito-report.txt" 2>&1 ||
    fail "Unable to inspect the generated El Torito catalog"
grep -q "UEFI" "$TMP_DIR/eltorito-report.txt" &&
    grep -q "/efi-boot.img" "$TMP_DIR/eltorito-report.txt" ||
    fail "Generated ISO does not expose its UEFI fallback ESP through El Torito"
FINAL_SOURCE_HASH="$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)"
[ "$FINAL_SOURCE_HASH" = "$SOURCE_HASH" ] ||
    fail "Canonical P0 disk changed while the ISO was being assembled"
FINAL_SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
FINAL_SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")" ||
    fail "Unable to inspect source state after ISO assembly"
[ "$FINAL_SOURCE_COMMIT" = "$SOURCE_COMMIT_AT_START" ] &&
    [ "$FINAL_SOURCE_STATUS" = "$SOURCE_STATUS_AT_START" ] ||
    fail "Source commit or worktree changed while the ISO was being assembled"
cp -- "$TMP_ISO" "$ISO_FILE" ||
    fail "Unable to publish the ISO into P0 run evidence"
[ -s "$ISO_FILE" ] && cmp -s -- "$TMP_ISO" "$ISO_FILE" ||
    fail "Published ISO does not match the generated image"
ISO_HASH="$(sha256sum "$ISO_FILE" | cut -d' ' -f1)"
printf '%s  %s\n' "$ISO_HASH" "$ISO_FILE" > "$ISO_HASH_FILE"
sha256sum --check "$ISO_HASH_FILE" || fail "Generated ISO checksum did not verify"
ISO_SIZE="$(stat -c '%s' "$ISO_FILE")"
UKI_HASH="$(sha256sum "$ISO_UKI" | cut -d' ' -f1)"
ROOT_HASH="$(sha256sum "$ROOT_FILE" | cut -d' ' -f1)"
ISO_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ISO_FILE")"

cat > "$ISO_RESULT" <<EOF
{
  "phase": "P0",
  "check": "iso_build",
  "status": "PASS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_commit": "$SOURCE_COMMIT",
  "source_tree_state_at_start": "$SOURCE_TREE_STATE",
  "dirty_path_count_at_start": $DIRTY_PATH_COUNT,
  "source_image_profile": "$IMAGE_PROFILE",
  "source_image_path": "$IMAGE_RELATIVE",
  "iso_path": "$ISO_RELATIVE",
  "iso_sha256": "$ISO_HASH",
  "iso_size_bytes": $ISO_SIZE,
  "source_disk_sha256": "$SOURCE_HASH",
  "source_uki_sha256": "$(sha256sum "${UKIS[0]}" | cut -d' ' -f1)",
  "source_initrd_sha256": "$(sha256sum "$TMP_DIR/source.initrd" | cut -d' ' -f1)",
  "optical_root_loader_sha256": "$(sha256sum "$WORKSPACE/tests/p0/iso-init.sh" | cut -d' ' -f1)",
  "uki_sha256": "$UKI_HASH",
  "root_filesystem_sha256": "$ROOT_HASH",
  "root_filesystem_uuid": "$ROOT_FS_UUID",
  "root_filesystem_label": "$ROOT_FS_LABEL",
  "root_filesystem_mount": "embedded ext4 file on ISO9660, attached read-only as a loop device",
  "root_persistence": "volatile overlay upper/work stored in RAM; changes are lost on reboot or power-off",
  "layout": "UEFI El Torito with direct UKI fallback loader, appended GPT ESP and Linux root partition, and embedded ext4 root file for optical boot"
}
EOF

echo "[P0-ISO] ISO: $ISO_FILE ($ISO_SIZE bytes)"
echo "[P0-ISO] SHA-256: $ISO_HASH"
