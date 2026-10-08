#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P1-BOOT] QEMU / OVMF / swtpm Boot Verification ==="

OVMF_CODE=""
for cand in "/usr/share/OVMF/OVMF_CODE_4M.fd" \
            "/usr/share/OVMF/OVMF_CODE.fd" \
            "/usr/share/ovmf/OVMF.fd"; do
    if [ -f "$cand" ]; then
        OVMF_CODE="$cand"
        break
    fi
done

if [ -z "$OVMF_CODE" ]; then
    echo "[P1-BOOT] FAIL: OVMF firmware code not found"
    exit 1
fi

IMAGE_FILE=""
for cand in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$cand" ]; then
        IMAGE_FILE="$cand"
        break
    fi
done

if [ -z "$IMAGE_FILE" ]; then
    echo "[P1-BOOT] FAIL: No disk image found"
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

SWTPM_PID=""
if command -v swtpm >/dev/null 2>&1; then
    mkdir -p "$TMP_DIR/tpm"
    swtpm socket --tpmstate dir="$TMP_DIR/tpm" --ctrl type=unixio,path="$TMP_DIR/tpm/swtpm-sock" --tpm2 &
    SWTPM_PID=$!
    sleep 1
fi

ACCEL="-accel kvm"
if [ ! -w /dev/kvm ]; then
    ACCEL="-accel tcg"
fi

BOOT_LOG="$ARTIFACT_DIR/boot.log"
echo "[P1-BOOT] Launching QEMU with image $IMAGE_FILE..."

set +e
timeout 60s qemu-system-x86_64 \
    -M q35 $ACCEL \
    -m 2048 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial file:"$BOOT_LOG" >/dev/null 2>&1
QEMU_RET=$?
set -e

if [ -n "$SWTPM_PID" ]; then
    kill "$SWTPM_PID" 2>/dev/null || true
fi

if grep -q -E "systemd|Welcome to|Linux version" "$BOOT_LOG" 2>/dev/null; then
    echo "[P1-BOOT] PASS: ExamOS booted successfully under UEFI OVMF"
    exit 0
else
    echo "[P1-BOOT] FAIL: Boot signature not detected in $BOOT_LOG"
    exit 1
fi
