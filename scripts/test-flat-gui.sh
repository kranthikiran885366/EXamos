#!/usr/bin/env bash
set -e

SWTPM_DIR="$HOME/sppio-test/swtpm-state"
SWTPM_SOCK="$HOME/sppio-test/swtpm.sock"
BOOT_LOG="$HOME/sppio-test/flat-boot.log"
OVMF_VARS="$HOME/sppio-test/OVMF_VARS.fd"
OVERLAY="$HOME/sppio-test/examos-flat-overlay.qcow2"

mkdir -p "$SWTPM_DIR"
rm -f "$SWTPM_SOCK"
killall -9 swtpm qemu-system-x86_64 2>/dev/null || true

echo "=== 1. Starting SWTPM 2.0 ==="
swtpm socket --tpm2 \
  --tpmstate "dir=$SWTPM_DIR" \
  --ctrl "type=unixio,path=$SWTPM_SOCK" \
  --flags not-need-init,startup-clear > "$HOME/sppio-test/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

echo "=== 2. Launching QEMU with Patched Flat VMDK Overlay & virtio-vga ==="
qemu-system-x86_64 \
  -name SPPIO-Disposable-Test \
  -machine q35,accel=kvm \
  -cpu host \
  -m 4096 \
  -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -chardev socket,id=chrtpm,path="$SWTPM_SOCK" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -drive file="$OVERLAY",format=qcow2,if=virtio \
  -device virtio-vga \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -display gtk \
  -serial stdio \
  -boot menu=on 2>&1 | tee "$BOOT_LOG"
