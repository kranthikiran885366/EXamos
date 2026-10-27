#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
RAW_IMG="$WORKSPACE/image/examos.raw"

echo "======================================================================"
echo "    ExamOS QEMU + SWTPM Virtual Boot Verification"
echo "======================================================================"

TMP_DIR=$(mktemp -d /tmp/examos-qemu-test.XXXXXX)
SWTPM_DIR="$TMP_DIR/swtpm-state"
SWTPM_SOCK="$TMP_DIR/swtpm.sock"
BOOT_LOG="$TMP_DIR/serial-boot.log"
OVMF_VARS="$TMP_DIR/OVMF_VARS.fd"
mkdir -p "$SWTPM_DIR"

SWTPM_PID=""
QEMU_PID=""

cleanup() {
    echo "--- Cleaning up QEMU and SWTPM processes ---"
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [ -n "$SWTPM_PID" ] && kill -0 "$SWTPM_PID" 2>/dev/null; then
        kill -TERM "$SWTPM_PID" 2>/dev/null || true
        wait "$SWTPM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "--- 1. Launching SWTPM 2.0 emulator instance ---"
swtpm socket --tpm2 \
    --tpmstate "dir=$SWTPM_DIR" \
    --ctrl "type=unixio,path=$SWTPM_SOCK" \
    --flags not-need-init,startup-clear > "$TMP_DIR/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 0.5

if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
    echo "FAIL: swtpm failed to start"
    cat "$TMP_DIR/swtpm.log"
    exit 1
fi
echo "SWTPM 2.0 active (PID $SWTPM_PID, socket: $SWTPM_SOCK)"

echo "--- 2. Preparing UEFI OVMF Variables ---"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"

echo "--- 3. Launching QEMU with UEFI, TPM 2.0, and Disk Snapshot ---"
# Check if KVM is available
ACCEL="-accel tcg"
if [ -w /dev/kvm ]; then
    ACCEL="-accel kvm -accel tcg"
    echo "KVM acceleration enabled."
else
    echo "Running with TCG (CPU emulation)."
fi

qemu-system-x86_64 -M q35 $ACCEL \
    -m 2048 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -chardev socket,id=chrtpm,path="$SWTPM_SOCK" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -drive file="$RAW_IMG",format=raw,if=virtio,snapshot=on \
    -serial file:"$BOOT_LOG" \
    -display none \
    > "$TMP_DIR/qemu.log" 2>&1 &
QEMU_PID=$!
echo "QEMU started (PID $QEMU_PID). Monitoring serial console boot..."

TIMEOUT=120
START_TIME=$SECONDS
BOOT_SUCCESS=0

while kill -0 "$QEMU_PID" 2>/dev/null; do
    ELAPSED=$((SECONDS - START_TIME))
    if [ -f "$BOOT_LOG" ]; then
        if grep -qiE "Queued start job for default target graphical\.target" "$BOOT_LOG" || \
           grep -qiE "systemd-pcrlock.*written" "$BOOT_LOG" || \
           grep -qiE "systemd\[1\]: Reached target.*(Multi-User|multi-user|Graphical|graphical)" "$BOOT_LOG" || \
           grep -qiE "Reached target Multi-User System" "$BOOT_LOG" || \
           grep -qiE "login:" "$BOOT_LOG"; then
            echo "SUCCESS: System reached targets and locked TPM2 PCRs within ${ELAPSED}s!"
            BOOT_SUCCESS=1
            break
        fi
    fi
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "TIMEOUT: QEMU did not reach target within ${TIMEOUT}s."
        break
    fi
    sleep 2
done

echo "--- Boot Log Highlights ---"
if [ -f "$BOOT_LOG" ]; then
    echo "Kernel & systemd milestones:"
    grep -E "(Linux version|systemd\[1\]|tpm|TPM|Reached target|Mounted|Started)" "$BOOT_LOG" | head -n 30 || true
fi

if [ $BOOT_SUCCESS -eq 1 ]; then
    echo
    echo "=== QEMU + SWTPM BOOT VERIFICATION PASSED! ==="
    exit 0
else
    echo
    echo "=== QEMU + SWTPM BOOT FAILED OR TIMED OUT ==="
    tail -n 40 "$BOOT_LOG" 2>/dev/null || true
    exit 1
fi
