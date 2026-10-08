#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_DIR="$ROOT/artifacts/p0"
source "$ROOT/scripts/p0-image-path.sh"
OUTPUT_DIR="$(examos_image_output_dir "$ROOT" "$ROOT/image")"
IMAGE="$OUTPUT_DIR/examos-production.raw"
mkdir -p "$ARTIFACT_DIR"

if [[ ! -s "$IMAGE" ]]; then
    echo "[FAIL] Expected bootable image artifact not found: $IMAGE" >&2
    exit 1
fi

OVMF_CODE=""
OVMF_VARS=""
for candidate in \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
  /usr/share/qemu/OVMF.fd; do
  if [[ -f "$candidate" ]]; then
    OVMF_CODE="$candidate"
    break
  fi
done

if [[ -z "$OVMF_CODE" ]]; then
    echo "[FAIL] OVMF firmware not found."
    exit 1
fi

for candidate in \
  /usr/share/OVMF/OVMF_VARS_4M.fd \
  /usr/share/edk2/ovmf/OVMF_VARS_4M.fd \
  /usr/share/OVMF/OVMF_VARS.fd \
  /usr/share/edk2-ovmf/x64/OVMF_VARS.fd; do
  if [[ -f "$candidate" ]]; then
    OVMF_VARS="$candidate"
    break
  fi
done

if [[ -z "$OVMF_VARS" ]]; then
    echo "[FAIL] Writable OVMF variable-store template not found."
    exit 1
fi

KVM_OPTS=(-cpu max)
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    KVM_OPTS=(-enable-kvm -cpu host)
fi

VARS_COPY="$(mktemp)"
trap 'rm -f "$VARS_COPY"' EXIT
cp "$OVMF_VARS" "$VARS_COPY"

echo "[P0-BOOT] Executing automated QEMU/OVMF boot test..."
echo "          Image: $IMAGE"
echo "          OVMF:  $OVMF_CODE"

QEMU_STATUS=0
if timeout 60s qemu-system-x86_64 \
    "${KVM_OPTS[@]}" \
    -m 2048 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$VARS_COPY" \
    -drive file="$IMAGE",format=raw,if=virtio \
    -snapshot \
    -display none \
    -serial stdio \
    -monitor none \
    > "$ARTIFACT_DIR/boot.log" 2>&1; then
    QEMU_STATUS=0
else
    QEMU_STATUS=$?
fi

if [[ "$QEMU_STATUS" -ne 0 && "$QEMU_STATUS" -ne 124 ]]; then
    echo "[FAIL] QEMU exited unexpectedly with status $QEMU_STATUS"
    tail -n 80 "$ARTIFACT_DIR/boot.log" 2>/dev/null || true
    exit 1
fi

if ! grep -E -qi "Reached target .*Login Prompts|login:" "$ARTIFACT_DIR/boot.log"; then
    echo "[FAIL] Guest did not reach the serial login target."
    echo "       Evidence recorded in: $ARTIFACT_DIR/boot.log"
    tail -n 80 "$ARTIFACT_DIR/boot.log" 2>/dev/null || true
    exit 1
fi

if ! grep -E -qi "Started .*examos-server.service" "$ARTIFACT_DIR/boot.log"; then
    echo "[FAIL] Guest reached the serial login target but did not start the ExamOS local server."
    echo "       Evidence recorded in: $ARTIFACT_DIR/boot.log"
    tail -n 80 "$ARTIFACT_DIR/boot.log" 2>/dev/null || true
    exit 1
fi

echo "[P0-BOOT] PASS: Guest reached the serial login target and started the ExamOS local server under UEFI OVMF"
echo "          Evidence recorded in: $ARTIFACT_DIR/boot.log"
