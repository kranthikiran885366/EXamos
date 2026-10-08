#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P1-BUILD] ExamOS Image Build Test ==="

# Check mkosi.conf
if [ ! -f "$WORKSPACE/image/mkosi.conf" ]; then
    echo "[P1-BUILD] FAIL: mkosi.conf missing"
    exit 1
fi

# Check required overlays
for req in "image/overlay/etc/examos/exam.conf" \
           "image/overlay/etc/systemd/system/examos-kiosk.service" \
           "image/overlay/etc/systemd/system/examos-server.service" \
           "image/overlay/etc/nftables.conf" \
           "image/overlay/usr/lib/sysusers.d/examos.conf"; do
    if [ ! -f "$WORKSPACE/$req" ]; then
        echo "[P1-BUILD] FAIL: Required overlay file missing: $req"
        exit 1
    fi
done

# Compile subsystems
echo "[P1-BUILD] Compiling native subsystems..."
(cd "$WORKSPACE" && make clean && make all) > "$ARTIFACT_DIR/build.log" 2>&1

# Build disk image with mkosi
echo "[P1-BUILD] Building mkosi image..."
(cd "$WORKSPACE/image" && mkosi build) >> "$ARTIFACT_DIR/build.log" 2>&1

# Locate built image
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
    echo "[P1-BUILD] PASS: Image built at $IMAGE_FILE"
    exit 0
else
    echo "[P1-BUILD] FAIL: No output disk image produced"
    exit 1
fi
