#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 - Real Labelled Dataset Fetcher
#
# Fetches the COCO 2017 validation split (real photographs) and its instance
# and person-keypoint annotations, verifies the archive digests, then builds
# labelled short clips for the detection-quality gate.
#
# The dataset is real: every clip is derived from a photograph in COCO
# val2017 and its ground truth comes from the COCO annotations.  No synthetic
# patterns are produced, so the dataset manifest records "synthetic": false.
#
# No image or clip is committed to the repository.  The archives are cached
# under ~/.cache/examos-p4/coco and the generated clips live under
# tests/p4/dataset (both gitignored).
#
# Usage:
#   bash tests/p4/fetch-real-dataset.sh [--cache DIR] [--out DIR]
#
# Requires: curl, python3, ffmpeg
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE="${EXAMOS_P4_COCO_CACHE:-$HOME/.cache/examos-p4/coco}"
OUT="${EXAMOS_P4_DATASET_DIR:-$WORKSPACE/tests/p4/dataset}"

while [ $# -gt 0 ]; do
    case "$1" in
        --cache) CACHE="$2"; shift 2 ;;
        --out)   OUT="$2"; shift 2 ;;
        *) echo "usage: $0 [--cache DIR] [--out DIR]" >&2; exit 2 ;;
    esac
done

VAL_URL="http://images.cocodataset.org/zips/val2017.zip"
ANN_URL="http://images.cocodataset.org/annotations/annotations_trainval2017.zip"
VAL_SHA="4f7e2ccb2866ec5041993c9cf2a952bbed69647b115d0f74da7ce8f4bef82f05"
ANN_SHA="113a836d90195ee1f884e704da6304dfaaecff1f023f49b6ca93c4aaae470268"

mkdir -p "$CACHE" "$OUT"

fetch_verified() {
    local url="$1" dest="$2" expected="$3"
    if [ -f "$dest" ]; then
        local actual
        actual="$(sha256sum "$dest" | cut -d' ' -f1)"
        if [ "$actual" = "$expected" ]; then
            echo "[dataset] cached and verified: $(basename "$dest")"
            return 0
        fi
        echo "[dataset] cached archive has the wrong digest; re-fetching: $(basename "$dest")"
        rm -f "$dest"
    fi
    echo "[dataset] downloading $(basename "$dest") ..."
    curl -fL --retry 3 --retry-delay 2 --max-time 3600 "$url" -o "$dest.part"
    local actual
    actual="$(sha256sum "$dest.part" | cut -d' ' -f1)"
    if [ "$actual" != "$expected" ]; then
        rm -f "$dest.part"
        echo "[dataset] FATAL: $(basename "$dest") digest mismatch (expected $expected, got $actual)" >&2
        exit 1
    fi
    mv "$dest.part" "$dest"
    echo "[dataset] verified: $(basename "$dest")"
}

fetch_verified "$VAL_URL" "$CACHE/val2017.zip" "$VAL_SHA"
fetch_verified "$ANN_URL" "$CACHE/annotations_trainval2017.zip" "$ANN_SHA"

python3 "$WORKSPACE/tests/p4/build-real-dataset.py" \
    --cache "$CACHE" --out "$OUT" \
    --val-sha "$VAL_SHA" --ann-sha "$ANN_SHA" \
    --val-url "$VAL_URL" --ann-url "$ANN_URL"
