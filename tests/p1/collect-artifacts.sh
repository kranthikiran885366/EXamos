#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

VERSIONS_FILE="$ARTIFACT_DIR/versions.txt"
echo "=== ExamOS P1 Tool Versions ===" > "$VERSIONS_FILE"

mkosi --version >> "$VERSIONS_FILE" 2>&1 || true
qemu-system-x86_64 --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || true
gcc --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || true
g++ --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || true
swtpm --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || true

echo "[P1-ARTIFACTS] Collected versions into $VERSIONS_FILE"
