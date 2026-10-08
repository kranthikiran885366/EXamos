#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

required_dirs=(
  "$ROOT/image"
  "$ROOT/image/config"
  "$ROOT/image/overlay"
  "$ROOT/image/scripts"
  "$ROOT/kiosk"
  "$ROOT/agent"
  "$ROOT/proctoring"
  "$ROOT/server"
  "$ROOT/tests"
  "$ROOT/tests/p0"
  "$ROOT/docs"
  "$ROOT/docs/development"
  "$ROOT/docs/releases"
  "$ROOT/artifacts"
)

required_files=(
  "$ROOT/README.md"
  "$ROOT/.gitignore"
  "$ROOT/docs/releases/version.yaml"
  "$ROOT/image/mkosi.conf"
)

for dir in "${required_dirs[@]}"; do
  if [[ ! -d "$dir" ]]; then
    echo "[FAIL] Missing required directory: $dir"
    exit 1
  fi
done

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "[FAIL] Missing required file: $file"
    exit 1
  fi
done

if find "$ROOT" -path "$ROOT/.git" -prune -o -type f \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o -name '*.crt' -o -name '*.der' \) -print | grep -q .; then
  echo "[FAIL] Private key material detected in repository tree."
  exit 1
fi

if find "$ROOT" -path "$ROOT/.git" -prune -o -type d \( -name keys -o -name secrets -o -name private \) -print | grep -q .; then
  echo "[FAIL] Secret directories detected in repository tree."
  exit 1
fi

echo "[PASS] Repository structure is valid and secret material is not committed."
