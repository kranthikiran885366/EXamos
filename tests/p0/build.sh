#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Image Build & Artifact Discovery Script
# tests/p0/build.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE_DIR="$WORKSPACE/image"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_load_format "$WORKSPACE" || {
    echo "[P0-BUILD] BLOCKED: canonical P0 partition format is missing or invalid." >&2
    exit 2
}
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-BUILD] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}
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

# 3. Invoke the canonical, pinned P0 mkosi configuration with fresh isolated
# output, cache, and build directories. A stale developer image cannot qualify.
echo "[P0-BUILD] Invoking mkosi build..."
BUILD_LOG="$ARTIFACT_DIR/build.log"
: > "$BUILD_LOG"
BUILD_WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/examos-p0-build.XXXXXX")"
trap 'rm -rf -- "$BUILD_WORK_DIR"' EXIT
"$MKOSI_BIN" --force -C "$WORKSPACE/image/p0" \
    --cache-directory "$BUILD_WORK_DIR/cache" \
    --output-directory "$BUILD_WORK_DIR/out" \
    --build-directory "$BUILD_WORK_DIR/build" \
    build 2>&1 | tee "$BUILD_LOG"
echo "[P0-BUILD] mkosi build succeeded."

mapfile -d '' -t IMAGE_CANDIDATES < <(find "$BUILD_WORK_DIR/out" -maxdepth 2 -type f \
    \( -name '*.raw' -o -name '*.img' \) -size +0c -print0)
[ "${#IMAGE_CANDIDATES[@]}" -eq 1 ] || {
    echo "[P0-BUILD] FATAL: expected exactly one non-empty disk image from the canonical P0 mkosi config; found ${#IMAGE_CANDIDATES[@]}." >&2
    exit 1
}
IMAGE_ARTIFACT="${IMAGE_CANDIDATES[0]}"
[ ! -L "$IMAGE_ARTIFACT" ] || { echo "[P0-BUILD] FATAL: mkosi output is a symlink." >&2; exit 1; }
if [ -f "$IMAGE_ARTIFACT" ]; then
    echo "[P0-BUILD] Found generated artifact: $IMAGE_ARTIFACT"
    cp --no-clobber -- "$IMAGE_ARTIFACT" "$ARTIFACT_DIR/examos-p0.raw"
    [ -s "$ARTIFACT_DIR/examos-p0.raw" ] && cmp -s -- "$IMAGE_ARTIFACT" "$ARTIFACT_DIR/examos-p0.raw" || {
        echo "[P0-BUILD] FATAL: run-bound image copy does not match mkosi output." >&2
        exit 1
    }
    
    # 6. Compute real SHA-256 Checksum
    sha256sum "$ARTIFACT_DIR/examos-p0.raw" > "$ARTIFACT_DIR/image.sha256"
    HASH_VAL=$(cut -d' ' -f1 < "$ARTIFACT_DIR/image.sha256")
    printf '%s\n' "$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.raw")" > "$ARTIFACT_DIR/image-path.txt"
    echo "[P0-BUILD] Artifact SHA-256: $HASH_VAL"

    # 7. Record real Image Size Baseline
    stat -c '%s' "$ARTIFACT_DIR/examos-p0.raw" > "$ARTIFACT_DIR/image-size.txt"
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
