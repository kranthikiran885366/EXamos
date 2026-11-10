#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export EXAMOS_VH_IMAGE="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
export EXAMOS_VH_BASE_HASH="aae03a601b7fac6cb4c8c8d772fcfd3e39c3c09b28afa5120bc2d92b8d8a6253"
export EXAMOS_VH_RUN_ID="kiosk-readiness-verified-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$WORKSPACE/tests/virtual-hardware/evidence/$EXAMOS_VH_RUN_ID"
mkdir -m 700 -p "$RUN_DIR" "$RUN_DIR/logs" "$RUN_DIR/reports"
export EXAMOS_VH_RUN_DIR="$RUN_DIR"

echo "=== STEP 1: Preflight ==="
bash "$WORKSPACE/tests/virtual-hardware/scripts/preflight.sh"

echo "=== STEP 2: Create Isolated VM Overlay ==="
bash "$WORKSPACE/tests/virtual-hardware/scripts/create-vm.sh"

echo "=== STEP 3: Boot Isolated VM and Verify Kiosk Readiness + TPM Quote ==="
bash "$WORKSPACE/tests/virtual-hardware/tests/qemu-boot.sh"

echo "=== STEP 4: Verify Evidence & Results ==="
EPOCH="$(cat "$RUN_DIR/active-epoch")"
echo "Active Epoch: $EPOCH"
echo "=== Serial Log Summary ==="
grep -E 'EXAMOS_KIOSK_READY|KioskLauncher|chrome_crashpad_handler|SIGTRAP' "$RUN_DIR/$EPOCH/serial.log" | tail -n 30 || true

if [ -f "$RUN_DIR/qemu-boot/quote-verification.txt" ]; then
    echo "=== TPM Quote Verification Result ==="
    cat "$RUN_DIR/qemu-boot/quote-verification.txt"
fi

echo "=== RUN COMPLETE: SUCCESS ==="
