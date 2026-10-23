#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 - Detection Model Provisioning
#
# Downloads the detector artefacts the proctoring worker uses and writes a
# model manifest that records each artefact's SHA-256 digest. The proctoring
# worker verifies every artefact against that manifest before it is used, so
# a substituted or corrupted model cannot become examination evidence.
#
# Artefacts:
#   face     YuNet ONNX face detector (OpenCV Zoo, MIT)
#   object   YOLOX-S trained on COCO (OpenCV Zoo, Apache-2.0) - supplies the
#            "cell phone" and "book" classes used by the proctoring taxonomy
#   landmark LBF 68-point facial landmark model - makes head pose estimation
#            possible instead of deriving it from unrelated measurements
#
# No model is committed to the repository. This script must be run on the
# build host or on the appliance, and the digest of every artefact it
# downloads is recorded so that the result can be reviewed.
#
# Usage:
#   bash scripts/download-vision-models.sh [--dest /path/to/models]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_MODELS="$SCRIPT_DIR/../proctoring/models"

DEST="${EXAMOS_MODEL_DIR:-/etc/examos/models}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) DEST="$2"; shift 2 ;;
    *) echo "usage: $0 [--dest DIR]" >&2; exit 2 ;;
  esac
done

log()  { echo "[models] $*"; }
fail() { echo "[models] FATAL: $*" >&2; exit 1; }

mkdir -p "$DEST" 2>/dev/null || { echo "[models] FATAL: cannot create $DEST (run as root)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Artefact inventory.
#
# Each entry is: role | file | url | sha256 | size | licence | framework
#
# The digests are the ones recorded in proctoring/models/MODEL-MANIFEST.json.
# A download that does not match its digest is rejected, so a mirror that
# serves an error page or a truncated file cannot be accepted.
# ---------------------------------------------------------------------------
FACE_WEIGHTS_URL="https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
OBJECT_URL="https://github.com/opencv/opencv_zoo/raw/main/models/object_detection_yolox/object_detection_yolox_2022nov.onnx"
LANDMARK_URL="https://github.com/kurnianggoro/GSOC2017/raw/master/data/lbfmodel.yaml"

# role|file|url|sha256|size|licence|framework
INVENTORY=(
  "face-dnn-weights|face_detection_yunet_2023mar.onnx|${FACE_WEIGHTS_URL}|8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4|232589|MIT (OpenCV Zoo / YuNet)|opencv-yunet"
  "object-dnn-weights|object_detection_yolox_2022nov.onnx|${OBJECT_URL}|c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063|35858002|Apache-2.0 (OpenCV Zoo / YOLOX)|onnx"
  "landmarks|lbfmodel.yaml|${LANDMARK_URL}|70dd8b1657c42d1595d6bd13d97d932877b3bed54a95d3c4733a0f740d1fd66b|56375857|MIT (GSOC2017 landmark model)|"
)

for entry in "${INVENTORY[@]}"; do
  IFS='|' read -r role file url expected_sha expected_size licence framework <<< "$entry"
  target="$DEST/$file"

  if [ -f "$target" ]; then
    actual_sha=$(sha256sum "$target" | cut -d' ' -f1)
    if [ "$actual_sha" = "$expected_sha" ]; then
      log "present and verified: $file"
      continue
    fi
    log "present but the digest does not match; re-fetching: $file"
    rm -f "$target"
  fi

  log "downloading $file ..."
  if ! curl -fsSL --retry 3 --retry-delay 2 --max-time 900 "$url" -o "$target.part"; then
    rm -f "$target.part"
    fail "cannot download $file from $url"
  fi

  actual_sha=$(sha256sum "$target.part" | cut -d' ' -f1)
  actual_size=$(stat -c%s "$target.part")
  if [ "$actual_sha" != "$expected_sha" ]; then
    rm -f "$target.part"
    fail "$file does not match its published digest (expected $expected_sha, got $actual_sha)"
  fi
  if [ "$actual_size" != "$expected_size" ]; then
    rm -f "$target.part"
    fail "$file has an unexpected size (expected $expected_size, got $actual_size)"
  fi

  mv "$target.part" "$target"
  log "verified: $file ($actual_size bytes)"
done

# ---------------------------------------------------------------------------
# Face cascade and manifest
#
# The Haar cascade ships with the repository and is the required fallback when
# the DNN face detector is unavailable.  The canonical manifest records the
# approved digest of every artefact, so it is copied next to the downloads
# rather than regenerated with different metadata.
# ---------------------------------------------------------------------------
CASCADE="$REPO_MODELS/haarcascade_frontalface_default.xml"
CASCADE_SHA="0f7d4527844eb514d4a4948e822da90fbb16a34a0bbbbc6adc6498747a5aafb0"
[ -f "$CASCADE" ] || fail "bundled face cascade not found at $CASCADE"
cp "$CASCADE" "$DEST/haarcascade_frontalface_default.xml"
actual_sha=$(sha256sum "$DEST/haarcascade_frontalface_default.xml" | cut -d' ' -f1)
[ "$actual_sha" = "$CASCADE_SHA" ] || fail "bundled face cascade does not match its approved digest"

MANIFEST="$DEST/MODEL-MANIFEST.json"
cp "$REPO_MODELS/MODEL-MANIFEST.json" "$MANIFEST"

chmod 0644 "$MANIFEST"
chmod 0644 "$DEST"/*.xml "$DEST"/*.onnx "$DEST"/*.prototxt "$DEST"/*.caffemodel "$DEST"/*.yaml 2>/dev/null || true

log ""
log "Model inventory at $DEST:"
for entry in "${INVENTORY[@]}"; do
  IFS='|' read -r role file url expected_sha expected_size licence framework <<< "$entry"
  if [ -f "$DEST/$file" ]; then
    log "  ok       $file ($(stat -c%s "$DEST/$file") bytes)"
  else
    log "  MISSING  $file"
    exit 1
  fi
done
log ""
log "Manifest written to $MANIFEST"
log "Set EXAMOS_PROCTOR_DETECTOR_CONFIG=$MANIFEST and"
log "EXAMOS_PROCTOR_MODEL_NAME / EXAMOS_PROCTOR_MODEL_VERSION for the proctoring worker."
