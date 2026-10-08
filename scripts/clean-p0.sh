#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Cleaning ExamOS P0 Build Artifacts ==="

# Clean compiled native binaries
make -C "$ROOT" clean 2>/dev/null || true

# Clean temporary build and output directories
rm -rf "$ROOT/artifacts/p0"/*
rm -rf "$ROOT/output"/*
rm -rf "$ROOT/cache"/*
rm -rf "$ROOT/image"/*.raw "$ROOT/image"/*.img "$ROOT/image"/*.vmlinuz "$ROOT/image"/initrd*
rm -rf "$ROOT/image/overlay/usr/local/bin"/*

touch "$ROOT/artifacts/p0/.gitkeep"
touch "$ROOT/output/.gitkeep"
touch "$ROOT/cache/.gitkeep"

echo "=== Clean Complete ==="
