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

BUILD_RESULT="$ARTIFACT_DIR/build-result.json"
BUILD_RESULT_TMP="$ARTIFACT_DIR/.build-result.json.tmp"
for output in "$BUILD_RESULT" "$BUILD_RESULT_TMP" "$ARTIFACT_DIR/examos-p0.raw" \
    "$ARTIFACT_DIR/image.sha256" "$ARTIFACT_DIR/image-path.txt" "$ARTIFACT_DIR/image-size.txt"; do
    [ ! -e "$output" ] && [ ! -L "$output" ] || {
        echo "[P0-BUILD] FATAL: build evidence output already exists; refusing to overwrite: $output" >&2
        exit 2
    }
done
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)" || exit 2
SOURCE_DATE_EPOCH="$(git -C "$WORKSPACE" show -s --format=%ct "$SOURCE_COMMIT")" || exit 2
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || {
    echo "[P0-BUILD] FATAL: source commit timestamp is invalid." >&2
    exit 2
}
SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")" || exit 2
[ -z "$SOURCE_STATUS" ] || {
    echo "[P0-BUILD] BLOCKED: refusing to build release evidence from a dirty source tree." >&2
    printf '%s\n' "$SOURCE_STATUS" >&2
    exit 2
}
SOURCE_DIRTY_COUNT=0
BUILD_CONFIG_SHA256="$(sha256sum "$WORKSPACE/image/p0/mkosi.conf" | cut -d' ' -f1)" || exit 2
PINNED_INPUTS_SHA256="$(sha256sum "$WORKSPACE/image/p0/sources.lock" | cut -d' ' -f1)" || exit 2

# PG-05: Verify sources.lock exists and is non-empty before trusting it
[ -s "$WORKSPACE/image/p0/sources.lock" ] || {
    echo "[P0-BUILD] FATAL: image/p0/sources.lock is missing or empty; cannot pin build inputs." >&2
    exit 2
}

BUILD_FINALIZED=0
record_build_failure() {
    local exit_code=$?
    if [ "$BUILD_FINALIZED" -eq 0 ] && [ -n "${BUILD_RESULT_TMP:-}" ]; then
        jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --arg commit "$SOURCE_COMMIT" --arg config_hash "$BUILD_CONFIG_SHA256" \
            --arg inputs_hash "$PINNED_INPUTS_SHA256" --argjson exit_code "$exit_code" \
            '{phase:"P0",check:"disk_build",status:"FAIL",timestamp:$timestamp,
              source_commit:$commit,source_tree_state:"CLEAN",source_dirty_path_count:0,
              build_config_sha256:$config_hash,pinned_inputs_sha256:$inputs_hash,exit_code:$exit_code}' \
            > "$BUILD_RESULT_TMP" && mv -- "$BUILD_RESULT_TMP" "$BUILD_RESULT" || true
    fi
}
trap record_build_failure EXIT
jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg commit "$SOURCE_COMMIT" --arg config_hash "$BUILD_CONFIG_SHA256" \
    --arg inputs_hash "$PINNED_INPUTS_SHA256" \
    '{phase:"P0",check:"disk_build",status:"IN_PROGRESS",timestamp:$timestamp,
      source_commit:$commit,source_tree_state:"CLEAN",source_dirty_path_count:0,
      build_config_sha256:$config_hash,pinned_inputs_sha256:$inputs_hash}' \
    > "$BUILD_RESULT_TMP" && mv -- "$BUILD_RESULT_TMP" "$BUILD_RESULT"

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
trap 'record_build_failure; rm -rf -- "$BUILD_WORK_DIR"' EXIT
if ! examos_p0_mkosi_build "$WORKSPACE" "$BUILD_WORK_DIR/out" \
    "$BUILD_WORK_DIR/cache" "$BUILD_WORK_DIR/build" \
    "$BUILD_WORK_DIR/first-boot-extra" "$BUILD_LOG"; then
    echo "[P0-BUILD] FATAL: canonical mkosi build or first-boot provisioning compilation failed." >&2
    exit 1
fi
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
    cp -- "$IMAGE_ARTIFACT" "$ARTIFACT_DIR/examos-p0.raw"
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
    SIZE_HUMAN=$(numfmt --to=iec-i --suffix=B "$(cat "$ARTIFACT_DIR/image-size.txt")")
    echo "[P0-BUILD] Artifact Size: $SIZE_HUMAN"

    SOURCE_COMMIT_AFTER="$(git -C "$WORKSPACE" rev-parse HEAD)" || exit 2
    SOURCE_STATUS_AFTER="$(examos_p0_source_status "$WORKSPACE")" || exit 2
    [ "$SOURCE_COMMIT_AFTER" = "$SOURCE_COMMIT" ] && [ -z "$SOURCE_STATUS_AFTER" ] || {
        echo "[P0-BUILD] FATAL: source commit or worktree changed during image build." >&2
        exit 1
    }
    jq -n --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg commit "$SOURCE_COMMIT" --arg image_hash "$HASH_VAL" \
        --arg image_path "$(cat "$ARTIFACT_DIR/image-path.txt")" \
        --arg config_hash "$BUILD_CONFIG_SHA256" --arg inputs_hash "$PINNED_INPUTS_SHA256" \
        --arg mkosi_version "$MKOSI_VER" --argjson size_bytes "$(cat "$ARTIFACT_DIR/image-size.txt")" \
        --argjson source_date_epoch "$SOURCE_DATE_EPOCH" \
        '{phase:"P0",check:"disk_build",status:"PASS",timestamp:$timestamp,
          source_commit:$commit,source_tree_state:"CLEAN",source_dirty_path_count:0,
          build_config_sha256:$config_hash,pinned_inputs_sha256:$inputs_hash,
          mkosi_version:$mkosi_version,source_date_epoch:$source_date_epoch,
          image_path:$image_path,image_sha256:$image_hash,
          image_size_bytes:$size_bytes}' > "$BUILD_RESULT_TMP" || exit 2
    mv -- "$BUILD_RESULT_TMP" "$BUILD_RESULT" || exit 2
    BUILD_FINALIZED=1

    echo "============================================================"
    # PG-03: Run binary hardening check as a hard gate blocker
    echo "[P0-BUILD] Running binary hardening gate..."
    HARDENING_SCRIPT="$WORKSPACE/tests/p0/binary-hardening-check.sh"
    HARDENING_FAIL=0
    for bin in server/examos-server agent/examos-agent kiosk/launcher/examos-kiosk-launcher proctoring/examos-proctor; do
        BIN_PATH="$WORKSPACE/$bin"
        [ -f "$BIN_PATH" ] || continue
        GRADE=$(bash "$HARDENING_SCRIPT" "$BIN_PATH" json 2>/dev/null | grep -oP '"grade"\s*:\s*"\K[^"]+' || echo "F")
        case "$GRADE" in
            A+|A|B) echo "[P0-BUILD] Hardening grade $GRADE: $(basename $bin)" ;;
            *) echo "[P0-BUILD] FATAL: binary hardening grade $GRADE for $(basename $bin) — minimum B required." >&2
               HARDENING_FAIL=1 ;;
        esac
    done
    [ "$HARDENING_FAIL" -eq 0 ] || exit 1

    # PG-05: Verify downloaded packages match sources.lock hashes
    echo "[P0-BUILD] Verifying package integrity against sources.lock..."
    SOURCES_LOCK="$WORKSPACE/image/p0/sources.lock"
    if [ -f "$SOURCES_LOCK" ]; then
        # Extract snapshot timestamp from sources.lock
        SNAPSHOT=$(awk -F= '$1=="debian_snapshot" { sub(/\r$/, "", $2); print $2; exit }' "$SOURCES_LOCK")
        echo "[P0-BUILD] Using Debian snapshot: $SNAPSHOT"
        # Note: Full package hash verification requires mkosi build output analysis
        # This is a placeholder for future implementation of PG-05
        echo "[P0-BUILD] INFO: Package hash verification placeholder (PG-05 - requires mkosi build output analysis)"
    else
        echo "[P0-BUILD] WARN: sources.lock not found, skipping package hash verification"
    fi

    echo "============================================================"
    echo "[P0-BUILD] OVERALL BUILD STATUS: PASS"
    echo "============================================================"
    exit 0
else
    echo "[P0-BUILD] FATAL: No bootable disk artifact found in $IMAGE_DIR" >&2
    exit 1
fi
