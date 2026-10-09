#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Safe Clean Script
# scripts/clean-p0.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"

echo "[CLEAN-P0] Cleaning generated P0 build and artifact caches..."

rm -rf "$WORKSPACE/image/build" "$WORKSPACE/image/cache" "$WORKSPACE/image/output" 2>/dev/null || true
rm -f "$WORKSPACE/image/examos.raw" "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.efi" \
      "$WORKSPACE/image/examos.raw.vmlinuz" "$WORKSPACE/image/examos.raw.initrd" 2>/dev/null || true
rm -f "$WORKSPACE/artifacts/p0/build.log" "$WORKSPACE/artifacts/p0/boot.log" 2>/dev/null || true

echo "[CLEAN-P0] Clean completed safely."
