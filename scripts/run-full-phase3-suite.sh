#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export EXAMOS_VH_IMAGE="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
export EXAMOS_VH_BASE_HASH="aae03a601b7fac6cb4c8c8d772fcfd3e39c3c09b28afa5120bc2d92b8d8a6253"
export EXAMOS_VH_RUN_ID="phase3-verification-$(date -u +%Y%m%dT%H%M%SZ)"

echo "=== Launching Phase 3 Independent Verification Suite: $EXAMOS_VH_RUN_ID ==="
exec bash "$WORKSPACE/tests/virtual-hardware/run-all.sh"
