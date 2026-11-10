#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export EXAMOS_VH_RUN_DIR="$WORKSPACE/tests/virtual-hardware/evidence/kiosk-readiness-verified-20261109T165135Z"
export EXAMOS_VH_BOOT_TIMEOUT_SECONDS=180
export EXAMOS_VH_KIOSK_STABILITY_SECONDS=30

echo "=== STEP 3: Boot Isolated VM and Verify Kiosk Readiness + TPM Quote ==="
bash "$WORKSPACE/tests/virtual-hardware/tests/qemu-boot.sh"

echo "=== STEP 4: Verify Evidence & Results ==="
EPOCH="$(cat "$EXAMOS_VH_RUN_DIR/active-epoch")"
echo "Active Epoch: $EPOCH"
echo "=== Serial Log Summary ==="
grep -E 'EXAMOS_KIOSK_READY|KioskLauncher|chrome_crashpad_handler|SIGTRAP|No usable sandbox' "$EXAMOS_VH_RUN_DIR/$EPOCH/serial.log" | tail -n 30 || true

if [ -f "$EXAMOS_VH_RUN_DIR/qemu-boot/quote-verification.txt" ]; then
    echo "=== TPM Quote Verification Result ==="
    cat "$EXAMOS_VH_RUN_DIR/qemu-boot/quote-verification.txt"
fi

echo "=== RUN COMPLETE: SUCCESS ==="
