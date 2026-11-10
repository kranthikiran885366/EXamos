#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="/mnt/d/SEB BRO/tests/virtual-hardware/evidence/kiosk-readiness-verified-20261109T165135Z"
EPOCH_DIR="$RUN_DIR/epoch-001"
RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

rm -f "$EPOCH_DIR/disk-overlay.qcow2" "$EPOCH_DIR/OVMF_VARS.fd" "$EPOCH_DIR/serial.log"
cp -- "$VARS" "$EPOCH_DIR/OVMF_VARS.fd"
chmod 600 "$EPOCH_DIR/OVMF_VARS.fd"
qemu-img create -f qcow2 -F raw -b "$RAW" "$EPOCH_DIR/disk-overlay.qcow2"
rm -rf "$EPOCH_DIR/tpm"
mkdir -m 700 "$EPOCH_DIR/tpm"
echo "OVERLAY REINITIALIZED"
