#!/usr/bin/env bash
# =============================================================================
# ExamOS — Production USB Flash Script
#
# Safely writes the ExamOS hybrid ISO to a USB drive for booting on
# physical laptops. Includes device detection, safety guards, and
# post-write verification.
#
# Usage:
#   bash scripts/flash-usb.sh [--device /dev/sdX] [--iso path/to/examos.iso]
#
# Safety:
#   - Never writes to /dev/sda (likely the host OS drive)
#   - Requires explicit --device flag (no auto-detection to wrong drive)
#   - Verifies SHA-256 of ISO before and after writing
#   - Uses dd with status=progress for real-time feedback
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
ISO_PATH=""
DEVICE=""
VERIFY_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --device) shift; DEVICE="$1" ;;
        --iso)    shift; ISO_PATH="$1" ;;
        --verify-only) VERIFY_ONLY=1 ;;
        --help|-h)
            echo "Usage: $0 --device /dev/sdX --iso path/to/examos.iso"
            echo "       $0 --verify-only --device /dev/sdX --iso path/to/examos.iso"
            exit 0
            ;;
    esac
    shift || true
done

log()  { echo "[flash] $*"; }
fail() { echo "[flash] FATAL: $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Validate inputs
# -----------------------------------------------------------------------
[ -n "$DEVICE" ] || fail "--device is required (e.g. /dev/sdb)"
[ -n "$ISO_PATH" ] || fail "--iso is required"
[ -f "$ISO_PATH" ] || fail "ISO file not found: $ISO_PATH"

# -----------------------------------------------------------------------
# Safety: never allow /dev/sda or internal disks
# -----------------------------------------------------------------------
case "$DEVICE" in
    /dev/sda|/dev/sda[0-9]*|/dev/nvme0n1|/dev/nvme0n1*|/dev/mmcblk0|/dev/mmcblk0*)
        fail "Refusing to write to $DEVICE — this is likely your primary disk or host OS partition."
        ;;
    /dev/sd[b-z][0-9]*)
        fail "Refusing to write to partition $DEVICE — use the whole disk device (e.g. ${DEVICE%%[0-9]*})"
        ;;
    /dev/sd[b-z])
        # Valid whole-disk external drive target
        ;;
    *)
        log "Target block device specified: $DEVICE"
        ;;
esac

# -----------------------------------------------------------------------
# Verify device exists and is removable
# -----------------------------------------------------------------------
if [ ! -b "$DEVICE" ]; then
    fail "Device $DEVICE does not exist or is not a block device"
fi

# Check if device is removable (USB)
REMOVABLE=$(cat "/sys/class/block/$(basename "$DEVICE")/removable" 2>/dev/null || echo "0")
if [ "$REMOVABLE" != "1" ]; then
    echo "[flash] WARNING: $DEVICE is not marked as removable."
    echo "[flash] Confirm you want to write to this device? (type YES to continue)"
    read -r confirm
    [ "$confirm" = "YES" ] || fail "Aborted by user"
fi

# -----------------------------------------------------------------------
# Verify ISO SHA-256
# -----------------------------------------------------------------------
ISO_SIZE=$(stat -c%s "$ISO_PATH")
ISO_SHA=$(sha256sum "$ISO_PATH" | cut -d' ' -f1)
log "ISO: $ISO_PATH"
log "Size: $ISO_SIZE bytes ($(( ISO_SIZE / 1048576 )) MB)"
log "SHA-256: $ISO_SHA"

# -----------------------------------------------------------------------
# Verify only mode
# -----------------------------------------------------------------------
if [ "$VERIFY_ONLY" -eq 1 ]; then
    log "Verify-only mode — checking device content..."
    DEV_SHA=$(head -c "$ISO_SIZE" "$DEVICE" 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "READ_FAILED")
    if [ "$DEV_SHA" = "$ISO_SHA" ]; then
        log "PASS: Device content matches ISO SHA-256"
        exit 0
    else
        log "FAIL: Device content does not match ISO"
        log "  Expected: $ISO_SHA"
        log "  Got:      $DEV_SHA"
        exit 1
    fi
fi

# -----------------------------------------------------------------------
# Unmount any mounted partitions on the device
# -----------------------------------------------------------------------
log "Unmounting any partitions on $DEVICE..."
for part in "${DEVICE}"[0-9]*; do
    [ -b "$part" ] || continue
    umount "$part" 2>/dev/null || true
done

# -----------------------------------------------------------------------
# Write ISO to device
# -----------------------------------------------------------------------
log "Writing ISO to $DEVICE..."
log "This will DESTROY all data on $DEVICE."
echo "[flash] Press Ctrl-C within 5 seconds to abort..."
sleep 5

if ! dd if="$ISO_PATH" of="$DEVICE" bs=4M status=progress conv=fsync 2>&1; then
    fail "dd write failed"
fi

# -----------------------------------------------------------------------
# Sync and verify
# -----------------------------------------------------------------------
log "Syncing..."
sync

log "Verifying write..."
DEV_SHA=$(head -c "$ISO_SIZE" "$DEVICE" 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "READ_FAILED")

if [ "$DEV_SHA" = "$ISO_SHA" ]; then
    log "PASS: Write verified — device content matches ISO SHA-256"
    log ""
    log "USB drive is ready. Boot instructions:"
    log "  1. Insert USB into target laptop"
    log "  2. Enter UEFI setup (F2/F12/Del depending on manufacturer)"
    log "  3. Disable Legacy CSM / enable UEFI mode"
    log "  4. Set USB as first boot device"
    log "  5. Save and exit — laptop will boot into ExamOS"
    log ""
    log "After boot, run the hardware preflight:"
    log "  bash /usr/local/sbin/hardware-preflight.sh"
else
    fail "Write verification FAILED — device content does not match ISO"
fi
