#!/usr/bin/env bash
# =============================================================================
# SPPIO / ExamOS — A/B Partitioning & Atomic Rollback Setup
#
# Extends dm-verity (image/scripts/dm-verity-setup.sh) with dual A/B immutable
# root + verity hash partitions and boot-counting rollback metadata.
#
# Partition Layout (GPT):
#   1: ESP         (EFI System Partition, FAT32, signed UKI + bootloader)
#   2: ROOT_A      (SquashFS read-only root filesystem — Slot A)
#   3: VERITY_A    (dm-verity Merkle hash tree — Slot A)
#   4: ROOT_B      (SquashFS read-only root filesystem — Slot B)
#   5: VERITY_B    (dm-verity Merkle hash tree — Slot B)
#   6: PERSIST_ENC (LUKS2 + TPM2/PQC-wrapped encrypted state partition)
# =============================================================================
set -euo pipefail

TARGET_DISK="${TARGET_DISK:-}"
SLOT_A_ROOT_HASH="${SLOT_A_ROOT_HASH:-}"
SLOT_B_ROOT_HASH="${SLOT_B_ROOT_HASH:-}"
ACTIVE_SLOT="${ACTIVE_SLOT:-A}"
METADATA_OUT="${METADATA_OUT:-/etc/examos/ab-slots.json}"
MAX_BOOT_TRIES="${MAX_BOOT_TRIES:-3}"

log()  { echo "[ab-partition] $*"; }
fail() { echo "[ab-partition] FAIL: $*" >&2; exit 1; }

case "$ACTIVE_SLOT" in
    A|B) ;;
    *) fail "ACTIVE_SLOT must be A or B (got: $ACTIVE_SLOT)" ;;
esac

if [ -n "$TARGET_DISK" ]; then
    for tool in sgdisk partprobe; do
        command -v "$tool" >/dev/null 2>&1 || fail "Missing required tool: $tool"
    done
    [ -b "$TARGET_DISK" ] || [ -f "$TARGET_DISK" ] || fail "TARGET_DISK does not exist: $TARGET_DISK"

    log "Partitioning $TARGET_DISK with GPT A/B + dm-verity layout..."
    sgdisk --zap-all "$TARGET_DISK"
    sgdisk -n 1:2048:+512M   -t 1:EF00 -c 1:"ESP"         "$TARGET_DISK"
    sgdisk -n 2:0:+4096M     -t 2:8304 -c 2:"ROOT_A"      "$TARGET_DISK"
    sgdisk -n 3:0:+128M      -t 3:8384 -c 3:"VERITY_A"    "$TARGET_DISK"
    sgdisk -n 4:0:+4096M     -t 4:8304 -c 4:"ROOT_B"      "$TARGET_DISK"
    sgdisk -n 5:0:+128M      -t 5:8384 -c 5:"VERITY_B"    "$TARGET_DISK"
    sgdisk -n 6:0:0          -t 6:8309 -c 6:"PERSIST_ENC" "$TARGET_DISK"
    partprobe "$TARGET_DISK" || true
fi

mkdir -p "$(dirname "$METADATA_OUT")"
cat > "$METADATA_OUT" <<EOF
{
  "schema": "sppio-ab-slots-v1",
  "active_slot": "${ACTIVE_SLOT}",
  "max_boot_tries": ${MAX_BOOT_TRIES},
  "slots": {
    "A": {
      "root_label": "ROOT_A",
      "verity_label": "VERITY_A",
      "verity_root_hash": "${SLOT_A_ROOT_HASH}",
      "boot_successful": $([ "$ACTIVE_SLOT" = "A" ] && echo "true" || echo "false"),
      "tries_remaining": ${MAX_BOOT_TRIES}
    },
    "B": {
      "root_label": "ROOT_B",
      "verity_label": "VERITY_B",
      "verity_root_hash": "${SLOT_B_ROOT_HASH}",
      "boot_successful": $([ "$ACTIVE_SLOT" = "B" ] && echo "true" || echo "false"),
      "tries_remaining": ${MAX_BOOT_TRIES}
    }
  }
}
EOF
log "A/B slot metadata written to $METADATA_OUT (active_slot=${ACTIVE_SLOT})"
