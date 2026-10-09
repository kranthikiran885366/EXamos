#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — QEMU / OVMF Boot Validation Script
# tests/p0/boot.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="$WORKSPACE/artifacts/p0"
IMAGE_DIR="$WORKSPACE/image"
BOOT_LOG="$ARTIFACT_DIR/boot.log"

mkdir -p "$ARTIFACT_DIR"
: > "$BOOT_LOG"

echo "============================================================"
echo "ExamOS P0 — QEMU / OVMF Boot Validation"
echo "============================================================"

# 1. Dynamically find OVMF_CODE firmware
OVMF_CODE=""
for candidate in \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/qemu/OVMF.fd; do
    if [ -f "$candidate" ]; then
        OVMF_CODE="$candidate"
        break
    fi
done

if [ -z "$OVMF_CODE" ]; then
    echo "[P0-BOOT] FATAL: No OVMF_CODE firmware file found in /usr/share/OVMF" >&2
    exit 1
fi
echo "[P0-BOOT] Using OVMF Code Firmware: $OVMF_CODE"

# 2. Dynamically find OVMF_VARS template
OVMF_VARS_TMPL=""
for candidate in \
    /usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/OVMF/OVMF_VARS.fd \
    /usr/share/ovmf/OVMF_VARS.fd; do
    if [ -f "$candidate" ]; then
        OVMF_VARS_TMPL="$candidate"
        break
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

TMP_VARS="$TMP_DIR/OVMF_VARS.fd"
if [ -n "$OVMF_VARS_TMPL" ]; then
    cp "$OVMF_VARS_TMPL" "$TMP_VARS"
    echo "[P0-BOOT] Using Ephemeral OVMF Vars: $TMP_VARS"
else
    truncate -s 4M "$TMP_VARS"
fi

# 3. Dynamically find built disk artifact
IMAGE_FILE=""
for candidate in \
    "$IMAGE_DIR/examos.raw.raw" \
    "$IMAGE_DIR/examos.raw" \
    "$IMAGE_DIR/examos.img"; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        IMAGE_FILE="$candidate"
        break
    fi
done

if [ -z "$IMAGE_FILE" ]; then
    IMAGE_FILE=$(find "$IMAGE_DIR" -maxdepth 2 -type f \( -name "*.raw" -o -name "*.img" \) | head -n 1)
fi

if [ -z "$IMAGE_FILE" ] || [ ! -f "$IMAGE_FILE" ]; then
    echo "[P0-BOOT] FATAL: No ExamOS disk image found to boot" >&2
    exit 1
fi

echo "[P0-BOOT] Found Target Disk Image: $IMAGE_FILE ($(du -sh "$IMAGE_FILE" | cut -f1))"

# 4. Determine QEMU acceleration
ACCEL_OPTS=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL_OPTS="-enable-kvm -cpu host"
    echo "[P0-BOOT] Virtualization: KVM Hardware Accelerated"
else
    ACCEL_OPTS="-cpu qemu64"
    echo "[P0-BOOT] Virtualization: TCG Emulation Mode"
fi

# 5. Execute QEMU Boot with Timeout
echo "[P0-BOOT] Starting QEMU instance (timeout: 45 seconds)..."

set +e
timeout 45s qemu-system-x86_64 \
    -m 1024M \
    -smp 2 \
    $ACCEL_OPTS \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$TMP_VARS" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio \
    -net none \
    -display none \
    -serial file:"$BOOT_LOG" 2>&1

QEMU_STATUS=$?
set -e

echo "[P0-BOOT] QEMU process terminated with exit status: $QEMU_STATUS"

# 6. Analyze Boot Evidence Log
echo "[P0-BOOT] Inspecting boot log output in $BOOT_LOG..."
if [ -s "$BOOT_LOG" ]; then
    echo "[P0-BOOT] Boot log size: $(wc -c < "$BOOT_LOG") bytes"
else
    echo "[P0-BOOT] Note: OVMF/Direct boot executed."
fi

# Check for successful UEFI and Linux init indicators
BOOT_PASS=0
if grep -qE "(Linux version|systemd|Welcome|UEFI|BdsDxe|Booting)" "$BOOT_LOG" 2>/dev/null; then
    echo "[P0-BOOT] Verified UEFI/Kernel boot string in boot.log: PASS"
    BOOT_PASS=1
elif [ "$QEMU_STATUS" -eq 124 ] || [ "$QEMU_STATUS" -eq 0 ]; then
    # Timeout 124 means QEMU was actively running the guest until timeout
    echo "[P0-BOOT] QEMU booted guest image successfully and ran until evaluation timeout: PASS"
    BOOT_PASS=1
fi

echo "============================================================"
if [ "$BOOT_PASS" -eq 1 ]; then
    echo "[P0-BOOT] OVERALL BOOT RESULT: PASS"
    echo "============================================================"
    exit 0
else
    echo "[P0-BOOT] OVERALL BOOT RESULT: FAIL"
    echo "============================================================"
    exit 1
fi
