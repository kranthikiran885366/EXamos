#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Cleaning ExamOS Artifacts ==="
make -C "$ROOT" clean 2>/dev/null || true
rm -rf "$ROOT/artifacts/tmp"/* "$ROOT/artifacts/p0"/* "$ROOT/output"/* "$ROOT/cache"/*
rm -rf "$ROOT/image"/*.raw "$ROOT/image"/*.img "$ROOT/image"/initrd*
touch "$ROOT/artifacts/p0/.gitkeep" "$ROOT/output/.gitkeep" "$ROOT/cache/.gitkeep"
echo "=== Done ==="
