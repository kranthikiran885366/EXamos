#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT/artifacts/p0"
source "$ROOT/scripts/p0-image-path.sh"
OUTPUT_DIR="$(examos_image_output_dir "$ROOT" "$ROOT/image")"
IMAGE_FILE="$OUTPUT_DIR/examos.raw"
mkdir -p "$ARTIFACT_DIR"

if [ ! -s "$IMAGE_FILE" ]; then
    echo "Error: ExamOS disk image not found: $IMAGE_FILE" >&2
    exit 1
fi

OVMF_CODE=""
for candidate in \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
  /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
  /usr/share/qemu/OVMF.fd; do
  if [ -f "$candidate" ]; then
    OVMF_CODE="$candidate"
    break
  fi
done

if [ -z "$OVMF_CODE" ]; then
    echo "Error: OVMF UEFI firmware not found"
    exit 1
fi

KVM_FLAG=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm -cpu host"
else
    KVM_FLAG="-cpu max"
fi

echo "=================================================="
echo "          Launching ExamOS in QEMU (UEFI)         "
echo "=================================================="
echo "Image: $IMAGE_FILE"
echo "OVMF:  $OVMF_CODE"

exec qemu-system-x86_64 \
    $KVM_FLAG \
    -m 4096 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive file="$IMAGE_FILE",format=raw,if=virtio \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -device virtio-gpu-pci \
    -serial stdio \
    -nographic \
    "$@"
