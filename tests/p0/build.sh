#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT/image"

echo "[P0] Starting mkosi build..."
mkosi -f

echo "[P0] Build completed."
