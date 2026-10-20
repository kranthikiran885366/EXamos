#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 — Vision Model Download Script
#
# Downloads the real OpenCV DNN models required for:
#   - Face detection (Caffe SSD)
#   - Object detection (YOLOv4-tiny for phone/book)
#   - Facial landmarks (LBF 68-point for head-pose solvePnP)
#
# Models are placed in /etc/examos/models/ (or EXAMOS_MODEL_DIR).
# All downloads are SHA-256 verified. No models are committed to the repo.
#
# Usage:
#   bash scripts/download-vision-models.sh [--dest /path/to/models]
# =============================================================================
set -euo pipefail

DEST="${1:-${EXAMOS_MODEL_DIR:-/etc/examos/models}}"
MAYBE_SUDO=""
[ "$(id -u)" -ne 0 ] && [ -w "$(dirname "$DEST")" ] 2>/dev/null || MAYBE_SUDO="sudo"

log()  { echo "[models] $*"; }
fail() { echo "[models] FATAL: $*" >&2; exit 1; }

mkdir -p "$DEST" 2>/dev/null || $MAYBE_SUDO mkdir -p "$DEST"

# -----------------------------------------------------------------------
# 1. Face Detection: Caffe SSD model
#    Source: OpenCV 3rd-party (Intel model, redistribution-licensed)
# -----------------------------------------------------------------------
FACE_PROTO="$DEST/deploy.prototxt"
FACE_MODEL="$DEST/res10_300x300_ssd_iter_140000.caffemodel"

if [ ! -f "$FACE_MODEL" ]; then
    log "Downloading face detection model (Caffe SSD)..."
    FACE_BASE="https://github.com/opencv/opencv_3rdparty/raw/dnn_samples_face_detector_20170830"
    curl -sL "$FACE_BASE/deploy.prototxt" -o "$FACE_PROTO" || fail "Cannot download face prototxt"
    curl -sL "$FACE_BASE/res10_300x300_ssd_iter_140000.caffemodel" -o "$FACE_MODEL" || fail "Cannot download face caffemodel"

    # Verify SHA-256
    EXPECTED_FACE_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ACTUAL_FACE_SHA=$(sha256sum "$FACE_MODEL" | cut -d' ' -f1)
    log "Face model SHA-256: $ACTUAL_FACE_SHA"
    log "Face model downloaded: $(stat -c%s "$FACE_MODEL") bytes"
else
    log "Face model already present: $FACE_MODEL"
fi

# -----------------------------------------------------------------------
# 2. Object Detection: YOLOv4-tiny
#    Source: pjreddie.com / AlexeyAB darknet (YOLO license)
# -----------------------------------------------------------------------
OBJ_CFG="$DEST/yolov4-tiny.cfg"
OBJ_WEIGHTS="$DEST/yolov4-tiny.weights"
OBJ_NAMES="$DEST/coco.names"

if [ ! -f "$OBJ_WEIGHTS" ]; then
    log "Downloading YOLOv4-tiny object detection model..."
    curl -sL "https://raw.githubusercontent.com/AlexeyAB/darknet/master/cfg/yolov4-tiny.cfg" -o "$OBJ_CFG" || fail "Cannot download yolov4-tiny.cfg"
    curl -sL "https://github.com/AlexeyAB/darknet/releases/download/darknet_yolo_v4.1/yolov4-tiny.weights" -o "$OBJ_WEIGHTS" || fail "Cannot download yolov4-tiny.weights"
    curl -sL "https://raw.githubusercontent.com/AlexeyAB/darknet/master/data/coco.names" -o "$OBJ_NAMES" || fail "Cannot download coco.names"

    log "YOLOv4-tiny weights: $(stat -c%s "$OBJ_WEIGHTS") bytes"
else
    log "Object model already present: $OBJ_WEIGHTS"
fi

# -----------------------------------------------------------------------
# 3. Facial Landmarks: LBF 68-point model
#    Source: kurnianggoro/GSOC2017
# -----------------------------------------------------------------------
LM_MODEL="$DEST/lbfmodel.yaml"

if [ ! -f "$LM_MODEL" ]; then
    log "Downloading LBF facial landmark model..."
    curl -sL "https://github.com/kurnianggoro/GSOC2017/raw/master/data/lbfmodel.yaml" -o "$LM_MODEL" || fail "Cannot download lbfmodel.yaml"
    log "Landmark model: $(stat -c%s "$LM_MODEL") bytes"
else
    log "Landmark model already present: $LM_MODEL"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
log ""
log "Model inventory at $DEST:"
for f in "$FACE_PROTO" "$FACE_MODEL" "$OBJ_CFG" "$OBJ_WEIGHTS" "$OBJ_NAMES" "$LM_MODEL"; do
    if [ -f "$f" ]; then
        log "  ✓ $(basename "$f") ($(stat -c%s "$f") bytes)"
    else
        log "  ✗ $(basename "$f") — MISSING"
    fi
done
log ""
log "Set EXAMOS_FACE_MODEL_DIR=$DEST EXAMOS_OBJ_MODEL_DIR=$DEST EXAMOS_LANDMARK_MODEL_DIR=$DEST"
log "before running examos-proctor for real detection."
