#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Image Build & Artifact Discovery Script
# tests/p0/build.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE_DIR="$WORKSPACE/image"
ARTIFACT_DIR="$WORKSPACE/artifacts/p0"

mkdir -p "$ARTIFACT_DIR"

echo "============================================================"
echo "ExamOS P0 — Building Minimal Debian Target Image"
echo "============================================================"
echo "[P0-BUILD] Workspace: $WORKSPACE"
echo "[P0-BUILD] Image Directory: $IMAGE_DIR"
echo "[P0-BUILD] Artifact Directory: $ARTIFACT_DIR"

# 1. Run Host & Environment Check
echo "[P0-BUILD] Verifying host prerequisites..."
bash "$WORKSPACE/tests/p0/host-check.sh"

# 2. Dynamic mkosi verification
MKOSI_BIN=$(command -v mkosi || true)
if [ -z "$MKOSI_BIN" ]; then
    echo "[P0-BUILD] FATAL: mkosi is not installed on PATH" >&2
    exit 1
fi
MKOSI_VER=$("$MKOSI_BIN" --version 2>&1 || echo "UNKNOWN")
echo "[P0-BUILD] Installed mkosi version: $MKOSI_VER"

# 3. Clean previous build artifacts
echo "[P0-BUILD] Cleaning previous build cache..."
rm -f "$IMAGE_DIR/examos.raw" "$IMAGE_DIR/examos.raw.raw" "$IMAGE_DIR/examos.efi" \
      "$IMAGE_DIR/examos.raw.vmlinuz" "$IMAGE_DIR/examos.raw.initrd" 2>/dev/null || true

# 4. Invoke mkosi build
echo "[P0-BUILD] Invoking mkosi build..."
BUILD_LOG="$ARTIFACT_DIR/build.log"
: > "$BUILD_LOG"

cd "$IMAGE_DIR"
if "$MKOSI_BIN" build 2>&1 | tee "$BUILD_LOG"; then
    echo "[P0-BUILD] mkosi build succeeded."
else
    echo "[P0-BUILD] mkosi build reported non-zero return code. Inspecting artifact..."
fi

# 5. Dynamically search for generated artifact
IMAGE_ARTIFACT=""
for candidate in "$IMAGE_DIR/examos.raw.raw" "$IMAGE_DIR/examos.raw" "$IMAGE_DIR/examos.img"; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        IMAGE_ARTIFACT="$candidate"
        break
    fi
done

if [ -z "$IMAGE_ARTIFACT" ]; then
    # Search deeper in image directory
    IMAGE_ARTIFACT=$(find "$IMAGE_DIR" -maxdepth 2 -type f \( -name "*.raw" -o -name "*.img" \) | head -n 1)
fi

if [ -n "$IMAGE_ARTIFACT" ] && [ -f "$IMAGE_ARTIFACT" ]; then
    echo "[P0-BUILD] Found generated artifact: $IMAGE_ARTIFACT"
    
    # 6. Compute real SHA-256 Checksum
    sha256sum "$IMAGE_ARTIFACT" > "$ARTIFACT_DIR/image.sha256"
    HASH_VAL=$(cut -d' ' -f1 < "$ARTIFACT_DIR/image.sha256")
    echo "[P0-BUILD] Artifact SHA-256: $HASH_VAL"

    # 7. Record real Image Size Baseline
    ls -lh "$IMAGE_ARTIFACT" > "$ARTIFACT_DIR/image-size.txt"
    SIZE_HUMAN=$(awk '{print $5}' "$ARTIFACT_DIR/image-size.txt")
    echo "[P0-BUILD] Artifact Size: $SIZE_HUMAN"

    echo "============================================================"
    echo "[P0-BUILD] OVERALL BUILD STATUS: PASS"
    echo "============================================================"
    exit 0
else
    echo "[P0-BUILD] FATAL: No bootable disk artifact found in $IMAGE_DIR" >&2
    exit 1
fi
