#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf "$ROOT/artifacts" "$ROOT/output" "$ROOT/build" "$ROOT/cache"
mkdir -p "$ROOT/artifacts/p0" "$ROOT/cache/packages" "$ROOT/cache/mkosi" "$ROOT/cache/qemu"

printf '%s\n' "[clean] Workspace cleaned and rebuild caches reset."
