#!/usr/bin/env bash
set -e
cd "/mnt/d/SEB BRO" || exit 1

LOG_FILE="$HOME/sppio-test/kiosk-test.log"
OVERLAY="$HOME/sppio-test/examos-gui-test.qcow2"
SWTPM_DIR="$HOME/sppio-test/swtpm-state"
SWTPM_SOCK="$HOME/sppio-test/swtpm.sock"
QMP_SOCK="$HOME/sppio-test/qmp.sock"
OVMF_VARS="$HOME/sppio-test/OVMF_VARS.fd"

echo "=== 1. Terminating any existing QEMU and SWTPM processes ==="
killall -9 qemu-system-x86_64 swtpm 2>/dev/null || true
sleep 1

echo "=== 2. Creating fresh disposable overlay backed by output/examos-flat.vmdk ==="
rm -f "$OVERLAY"
qemu-img create -f qcow2 \
  -F raw \
  -b "$PWD/output/examos-flat.vmdk" \
  "$OVERLAY" || exit 1

echo "=== 3. Starting SWTPM 2.0 emulator ==="
mkdir -p "$SWTPM_DIR"
rm -f "$SWTPM_SOCK" "$QMP_SOCK"
swtpm socket --tpm2 \
  --tpmstate dir="$SWTPM_DIR" \
  --ctrl type=unixio,path="$SWTPM_SOCK" \
  --flags not-need-init,startup-clear > "$HOME/sppio-test/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
  echo "FAIL: swtpm could not be started"
  cat "$HOME/sppio-test/swtpm.log"
  exit 1
fi
echo "SWTPM 2.0 active (PID $SWTPM_PID, socket: $SWTPM_SOCK)"

echo "=== 4. Launching QEMU SPPIO-Kiosk-Display (-vga virtio + GTK + QMP) ==="
echo "Display: $DISPLAY, Wayland: $WAYLAND_DISPLAY"
qemu-system-x86_64 \
  -name SPPIO-Kiosk-Display \
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
  -vga virtio \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -qmp "unix:$QMP_SOCK,server,nowait" \
  -display gtk,gl=off \
  -serial stdio 2>&1 | tee "$LOG_FILE"
