#!/usr/bin/env bash
set -e
cd "/mnt/d/SEB BRO" || exit 1

echo "=== Verifying Original Image Checksum ==="
sha256sum -c image/examos.raw.sha256 || exit 1

echo "=== Creating sppio-test Directory ==="
mkdir -p "$HOME/sppio-test"

echo "=== Creating Copy-on-Write Overlay ==="
qemu-img create -f qcow2 \
  -F raw \
  -b "$PWD/image/examos.raw" \
  "$HOME/sppio-test/examos-overlay.qcow2" || exit 1

echo "=== Preparing UEFI Variables Store ==="
cp /usr/share/OVMF/OVMF_VARS_4M.fd \
   "$HOME/sppio-test/OVMF_VARS.fd" || exit 1

echo "=== Inspecting Overlay Configuration ==="
qemu-img info "$HOME/sppio-test/examos-overlay.qcow2"

echo "=== Checking Display Support ==="
echo "DISPLAY=$DISPLAY"
echo "WAYLAND_DISPLAY=$WAYLAND_DISPLAY"
