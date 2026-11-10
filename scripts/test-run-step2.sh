#!/usr/bin/env bash
set -x
exec > /tmp/step2.log 2>&1
export EXAMOS_VH_RUN_DIR="/mnt/d/SEB BRO/tests/virtual-hardware/evidence/kiosk-readiness-verified-20261109T165135Z"
export EXAMOS_VH_IMAGE="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
rm -rf "$EXAMOS_VH_RUN_DIR/epoch-001"
bash -x "/mnt/d/SEB BRO/tests/virtual-hardware/scripts/create-vm.sh"
echo "STEP2_EXIT=$?"
