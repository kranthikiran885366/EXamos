#!/usr/bin/env bash
cd "/mnt/d/SEB BRO" || exit 1

# Confirm the disposable overlay and UEFI files exist
test -f "$HOME/sppio-test/examos-overlay.qcow2" || { echo "ERROR: overlay missing"; exit 1; }
test -f "$HOME/sppio-test/OVMF_VARS.fd" || { echo "ERROR: OVMF_VARS missing"; exit 1; }
test -f /usr/share/OVMF/OVMF_CODE_4M.fd || { echo "ERROR: OVMF_CODE missing"; exit 1; }

echo "=== Launching SPPIO in QEMU (UEFI + KVM + virtio-gpu) ==="

# Start SPPIO with virtual graphics and a serial console, teeing to log
qemu-system-x86_64 \
  -name SPPIO-Disposable-Test \
  -machine q35,accel=kvm \
  -cpu host \
  -m 4096 \
  -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$HOME/sppio-test/OVMF_VARS.fd" \
  -drive file="$HOME/sppio-test/examos-overlay.qcow2",format=qcow2,if=virtio \
  -device virtio-gpu-pci \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -display gtk \
  -serial stdio \
  -boot menu=on 2>&1 | tee "$HOME/sppio-test/qemu-boot.log"
