#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="/mnt/d/SEB BRO/tests/virtual-hardware/evidence/kiosk-readiness-verified-20261109T145958Z"
EPOCH_DIR="$RUN_DIR/epoch-001"
echo "=== Checking swtpm pid ==="
cat "$EPOCH_DIR/swtpm.pid" || true
echo "=== Checking qemu pid ==="
cat "$EPOCH_DIR/qemu.pid" || true
echo "=== Checking qemu-kvm.log ==="
cat "$EPOCH_DIR/qemu-kvm.log" || true
echo "=== Checking swtpm.log ==="
cat "$EPOCH_DIR/swtpm.log" || true
