#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "=== ExamOS Repository Hierarchy & Secret Scan ==="

required_dirs=(
  "$ROOT/image"
  "$ROOT/image/config"
  "$ROOT/image/overlay"
  "$ROOT/image/scripts"
  "$ROOT/kiosk"
  "$ROOT/kiosk/launcher"
  "$ROOT/kiosk/policies"
  "$ROOT/agent"
  "$ROOT/agent/attestation"
  "$ROOT/agent/device-state"
  "$ROOT/agent/environment"
  "$ROOT/agent/heartbeat"
  "$ROOT/proctoring"
  "$ROOT/proctoring/client"
  "$ROOT/proctoring/analysis"
  "$ROOT/server"
  "$ROOT/server/gateway"
  "$ROOT/server/attestation"
  "$ROOT/server/exam"
  "$ROOT/server/events"
  "$ROOT/server/risk"
  "$ROOT/tests"
  "$ROOT/tests/p0"
  "$ROOT/docs"
  "$ROOT/docs/development"
  "$ROOT/docs/releases"
  "$ROOT/artifacts"
)

required_files=(
  "$ROOT/README.md"
  "$ROOT/Makefile"
  "$ROOT/.gitignore"
  "$ROOT/docs/releases/version.yaml"
  "$ROOT/image/mkosi.conf"
  "$ROOT/kiosk/launcher/launcher.c"
  "$ROOT/kiosk/launcher/Makefile"
  "$ROOT/agent/main.c"
  "$ROOT/agent/Makefile"
  "$ROOT/proctoring/main.cpp"
  "$ROOT/proctoring/Makefile"
  "$ROOT/server/main.c"
  "$ROOT/server/Makefile"
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

# Secret Material Scan: check for accidentally committed private keys or certificates
if find "$ROOT" -path "$ROOT/.git" -prune -o -type f \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o -name '*.crt' -o -name '*.der' \) -print | grep -q .; then
  echo "[FAIL] Private key/certificate material detected in repository tree."
  exit 1
fi

if find "$ROOT" -path "$ROOT/.git" -prune -o -type d \( -name keys -o -name secrets -o -name private \) -print | grep -q .; then
  echo "[FAIL] Secret directory detected in repository tree."
  exit 1
fi

echo "[PASS] All required directories/files present; no secret material committed."
