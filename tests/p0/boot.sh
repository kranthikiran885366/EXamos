#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_DIR="$ROOT/image"

IMAGE="$(find "$IMAGE_DIR" -maxdepth 1 -type f \( -name "*.raw" -o -name "*.img" -o -name "*.efi" \) | head -n 1)"

if [[ -z "$IMAGE" ]]; then
    echo "[FAIL] No bootable image artifact found."
    exit 1
fi

echo "[P0] Booting:"
echo "      $IMAGE"

mkosi vm
