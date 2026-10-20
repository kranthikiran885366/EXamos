#!/usr/bin/env bash
# Build the canonical P0 image twice from isolated state and retain both outputs.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?P0 reproducibility requires a run-bound evidence directory}"
OUT="${EXAMOS_P0_REPRO_OUT:?P0 reproducibility requires a run-bound output directory}"
STAGING_BASE="${EXAMOS_P0_REPRO_STAGING_DIR:-/var/tmp}"
source "$WORKSPACE/scripts/examos-lib.sh"

examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-REPRO] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}
OUT="$(realpath -m -- "$OUT")" || exit 2
[ "$(dirname "$OUT")" = "$ARTIFACT_DIR" ] && [ "${OUT##*/}" = "reproducibility" ] || {
    echo "[P0-REPRO] FATAL: reproducibility output must be the reproducibility child of this run." >&2
    exit 2
}
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || {
    echo "[P0-REPRO] FATAL: refusing to overwrite existing reproducibility evidence." >&2
    exit 2
}
[ -d "$STAGING_BASE" ] && [ -w "$STAGING_BASE" ] || {
    echo "[P0-REPRO] FATAL: reproducibility staging directory is unavailable." >&2
    exit 2
}
mkdir -m 0750 -- "$OUT"

REPORT="$OUT/report.json"
REPORT_TMP="$OUT/.report.json.tmp"
BUILD_A_PATH="$OUT/build-a.raw"
BUILD_B_PATH="$OUT/build-b.raw"
MANIFEST_A="$OUT/build-a.sha256"
MANIFEST_B="$OUT/build-b.sha256"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)" || exit 2
SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")" || exit 2
SOURCE_TREE_STATE="CLEAN"
STATUS="PASS"
REASON=""
BUILD_A_HASH=""
BUILD_B_HASH=""
BUILD_A_SIZE=0
BUILD_B_SIZE=0
BUILD_A_MANIFEST_HASH=""
BUILD_B_MANIFEST_HASH=""
STAGING_A=""
STAGING_B=""

cleanup() {
    [ -z "$STAGING_A" ] || rm -rf -- "$STAGING_A"
    [ -z "$STAGING_B" ] || rm -rf -- "$STAGING_B"
}
trap cleanup EXIT

fail() { STATUS=FAIL; REASON="$1"; echo "[P0-REPRO] FAIL: $1" >&2; }
block() { STATUS=BLOCKED; REASON="$1"; echo "[P0-REPRO] BLOCKED: $1" >&2; }

if [ -n "$SOURCE_STATUS" ]; then
    SOURCE_TREE_STATE="DIRTY"
    block "source tree is dirty; image comparison cannot qualify release evidence"
fi
PIN_RESULT="$ARTIFACT_DIR/pinned-inputs-result.json"
if [ ! -s "$PIN_RESULT" ] || ! jq -e \
    --arg commit "$SOURCE_COMMIT" \
    --arg sources_hash "$(sha256sum "$WORKSPACE/image/p0/sources.lock" | cut -d' ' -f1)" \
    --arg toolchain_hash "$(sha256sum "$WORKSPACE/image/p0/toolchain.lock" | cut -d' ' -f1)" \
    --arg config_hash "$(sha256sum "$WORKSPACE/image/p0/mkosi.conf" | cut -d' ' -f1)" \
    --arg workflow_hash "$(sha256sum "$WORKSPACE/.github/workflows/p0.yml" | cut -d' ' -f1)" \
    '.schema == "examos.p0.pinned-inputs.v1" and .status == "PASS"
     and .source_commit == $commit and .source_tree_state == "CLEAN"
     and .sources_lock_sha256 == $sources_hash
     and .toolchain_lock_sha256 == $toolchain_hash
     and .mkosi_config_sha256 == $config_hash and .workflow_sha256 == $workflow_hash' \
    "$PIN_RESULT" >/dev/null 2>&1; then
    fail "run-bound pinned-input evidence is absent, stale, or tied to different inputs"
fi
if [ "$STATUS" = PASS ]; then
    INPUT_IMAGE="$ARTIFACT_DIR/examos-p0.raw"
    [ -s "$INPUT_IMAGE" ] && [ ! -L "$INPUT_IMAGE" ] ||
        fail "run-bound canonical image is unavailable for staging capacity calculation"
fi
if [ "$STATUS" = PASS ]; then
    FREE_KIB="$(df -Pk "$STAGING_BASE" | awk 'NR == 2 { print $4 }')"
    INPUT_KIB=$(( $(stat -c '%s' "$INPUT_IMAGE") / 1024 ))
    case "$FREE_KIB" in ''|*[!0-9]*) fail "cannot determine reproducibility staging capacity" ;; esac
    if [ "$STATUS" = PASS ] && [ "$FREE_KIB" -lt "$((INPUT_KIB * 3))" ]; then
        block "reproducibility staging needs three times the current image size on $STAGING_BASE"
    fi
fi

if [ "$STATUS" = PASS ]; then
    STAGING_A="$(mktemp -d "$STAGING_BASE/examos-p0-repro-a.XXXXXX")"
    STAGING_B="$(mktemp -d "$STAGING_BASE/examos-p0-repro-b.XXXXXX")"
    echo "[P0-REPRO] Building isolated image A from $SOURCE_COMMIT"
    if ! examos_p0_mkosi_build "$WORKSPACE" "$STAGING_A/out" "$STAGING_A/cache" \
        "$STAGING_A/build" "$STAGING_A/extra" "$OUT/build-a.log" >/dev/null; then
        fail "isolated mkosi image build A failed; inspect build-a.log"
    fi
fi

find_exact_image() {
    local output_dir="$1"
    mapfile -d '' -t candidates < <(find "$output_dir" -maxdepth 2 -type f \
        \( -name '*.raw' -o -name '*.img' \) -size +0c -print0)
    [ "${#candidates[@]}" -eq 1 ] && [ ! -L "${candidates[0]}" ] || return 1
    printf '%s\n' "${candidates[0]}"
}

if [ "$STATUS" = PASS ]; then
    IMAGE_A="$(find_exact_image "$STAGING_A/out")" || fail "image A did not produce exactly one non-empty regular disk artifact"
    if [ "$STATUS" = PASS ]; then
        cp -- "$IMAGE_A" "$BUILD_A_PATH" || fail "unable to retain image A as run evidence"
    fi
fi
if [ "$STATUS" = PASS ]; then
    echo "[P0-REPRO] Building isolated image B from $SOURCE_COMMIT"
    if ! examos_p0_mkosi_build "$WORKSPACE" "$STAGING_B/out" "$STAGING_B/cache" \
        "$STAGING_B/build" "$STAGING_B/extra" "$OUT/build-b.log" >/dev/null; then
        fail "isolated mkosi image build B failed; inspect build-b.log"
    fi
fi
if [ "$STATUS" = PASS ]; then
    IMAGE_B="$(find_exact_image "$STAGING_B/out")" || fail "image B did not produce exactly one non-empty regular disk artifact"
    if [ "$STATUS" = PASS ]; then
        cp -- "$IMAGE_B" "$BUILD_B_PATH" || fail "unable to retain image B as run evidence"
    fi
fi

if [ -s "$BUILD_A_PATH" ] && [ -s "$BUILD_B_PATH" ]; then
    BUILD_A_HASH="$(sha256sum "$BUILD_A_PATH" | cut -d' ' -f1)"
    BUILD_B_HASH="$(sha256sum "$BUILD_B_PATH" | cut -d' ' -f1)"
    BUILD_A_SIZE="$(stat -c '%s' "$BUILD_A_PATH")"
    BUILD_B_SIZE="$(stat -c '%s' "$BUILD_B_PATH")"
    printf '%s p0-disk\n' "$BUILD_A_HASH" > "$MANIFEST_A"
    printf '%s p0-disk\n' "$BUILD_B_HASH" > "$MANIFEST_B"
    BUILD_A_MANIFEST_HASH="$(sha256sum "$MANIFEST_A" | cut -d' ' -f1)"
    BUILD_B_MANIFEST_HASH="$(sha256sum "$MANIFEST_B" | cut -d' ' -f1)"
    if [ "$BUILD_A_HASH" != "$BUILD_B_HASH" ] || [ "$BUILD_A_SIZE" != "$BUILD_B_SIZE" ]; then
        fail "isolated P0 image digests or sizes differ"
    else
        REASON="two isolated mkosi image builds produced byte-identical run artifacts"
        echo "[P0-REPRO] Both retained image artifacts match: $BUILD_A_HASH"
    fi
fi

if [ "$STATUS" = PASS ]; then
    CURRENT_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)" || fail "cannot recheck source commit"
    CURRENT_SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")" || fail "cannot recheck source tree"
    if [ "$CURRENT_COMMIT" != "$SOURCE_COMMIT" ] || [ -n "$CURRENT_SOURCE_STATUS" ]; then
        SOURCE_TREE_STATE="DIRTY"
        fail "source commit or worktree changed during reproducibility builds"
    fi
fi

if python3 - "$REPORT_TMP" "$STATUS" "$REASON" "$SOURCE_COMMIT" "$SOURCE_TREE_STATE" \
    "$BUILD_A_HASH" "$BUILD_B_HASH" "$BUILD_A_SIZE" "$BUILD_B_SIZE" \
    "$BUILD_A_MANIFEST_HASH" "$BUILD_B_MANIFEST_HASH" <<'PY'
import datetime
import json
import pathlib
import sys

(output, status, reason, commit, tree, hash_a, hash_b, size_a, size_b,
 manifest_hash_a, manifest_hash_b) = sys.argv[1:]
root = pathlib.Path(output).parent
entries_a = [{"sha256": hash_a, "label": "p0-disk"}] if hash_a else []
entries_b = [{"sha256": hash_b, "label": "p0-disk"}] if hash_b else []
result = status
release_eligible = status == "PASS" and tree == "CLEAN" and bool(hash_a) and hash_a == hash_b
if status == "PASS" and not release_eligible:
    result = "FAIL"
    reason = reason or "clean image manifests did not qualify for release"
report = {
    "schema": "examos.p0.reproducibility.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "source_tree_state": tree,
    "mode": "image",
    "result": result,
    "reason": reason,
    "release_eligible": release_eligible,
    "build_a": entries_a,
    "build_b": entries_b,
    "build_a_manifest_sha256": manifest_hash_a,
    "build_b_manifest_sha256": manifest_hash_b,
    "build_a_image": {"path": "build-a.raw", "sha256": hash_a, "size_bytes": int(size_a)},
    "build_b_image": {"path": "build-b.raw", "sha256": hash_b, "size_bytes": int(size_b)},
    "manifest_paths": {"build_a": "build-a.sha256", "build_b": "build-b.sha256"},
}
pathlib.Path(output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
then
    REPORT_STATUS=0
else
    REPORT_STATUS=$?
fi
mv -- "$REPORT_TMP" "$REPORT"
exit "$REPORT_STATUS"
