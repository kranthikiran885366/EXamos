#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

VERSIONS_FILE="$ARTIFACT_DIR/tool-versions.txt"
echo "=== ExamOS P1 Tool Versions ===" > "$VERSIONS_FILE"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" >> "$VERSIONS_FILE"

echo -n "mkosi: " >> "$VERSIONS_FILE"
mkosi --version >> "$VERSIONS_FILE" 2>&1 || echo "UNKNOWN" >> "$VERSIONS_FILE"

echo -n "qemu: " >> "$VERSIONS_FILE"
qemu-system-x86_64 --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || echo "UNKNOWN" >> "$VERSIONS_FILE"

echo -n "gcc: " >> "$VERSIONS_FILE"
gcc --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || echo "UNKNOWN" >> "$VERSIONS_FILE"

echo -n "g++: " >> "$VERSIONS_FILE"
g++ --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || echo "UNKNOWN" >> "$VERSIONS_FILE"

echo -n "swtpm: " >> "$VERSIONS_FILE"
swtpm --version | head -n 1 >> "$VERSIONS_FILE" 2>&1 || echo "UNKNOWN" >> "$VERSIONS_FILE"

cp "$VERSIONS_FILE" "$ARTIFACT_DIR/versions.txt"

# Record image size and sha256
IMAGE_FILE=""
for cand in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$cand" ]; then
        IMAGE_FILE="$cand"
        break
    fi
done

if [ -n "$IMAGE_FILE" ]; then
    sha256sum "$IMAGE_FILE" > "$ARTIFACT_DIR/image.sha256"
    ls -lh "$IMAGE_FILE" > "$ARTIFACT_DIR/image-size.txt"
fi

echo "[P1-ARTIFACTS] Collected versions and image metadata into $ARTIFACT_DIR"
