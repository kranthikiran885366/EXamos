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
#   face     Caffe SSD face detector (OpenCV project)
#   object   MobileNet SSD trained on COCO - supplies the "cell phone" and
#            "book" classes used by the proctoring taxonomy
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
# Each entry is: role | file | url | sha256 | size | licence
#
# The digests are the ones the upstream projects publish for these exact
# files. A download that does not match its digest is rejected, so a mirror
# that serves an error page or a truncated file cannot be accepted.
# ---------------------------------------------------------------------------
FACE_BASE="https://raw.githubusercontent.com/opencv/opencv/4.10.0/samples/dnn/face_detector"
FACE_WEIGHTS_URL="https://github.com/opencv/opencv_3rdparty/raw/dnn_samples_face_detector_20170830/res10_300x300_ssd_iter_140000.caffemodel"
OBJECT_BASE="https://raw.githubusercontent.com/chuanqi305/MobileNet-SSD/master"
LANDMARK_URL="https://github.com/kurnianggoro/GSOC2017/raw/master/data/lbfmodel.yaml"

# role|file|url|sha256|size|licence
INVENTORY=(
  "face-dnn-prototxt|deploy.prototxt|${FACE_BASE}/deploy.prototxt|dcd661dc48fc9de0a341db1f666a2164ea63a67265c7f779bc12d6b3f2fa67e9|28104|BSD-3-Clause (OpenCV project)"
  "face-dnn-weights|res10_300x300_ssd_iter_140000.caffemodel|${FACE_WEIGHTS_URL}|2a56a11a57a4a295956b0660b4a3d76bbdca2206c4961cea8efe7d95c7cb2f2d|10666211|BSD-3-Clause (OpenCV project)"
  "object-dnn-prototxt|mobilenet_deploy.prototxt|${OBJECT_BASE}/deploy.prototxt|2d180f723b3109e21f8287f6b3c691390d07b60eed998327cd3259ffa0e50608|44667|MIT (MobileNet-SSD)"
  "object-dnn-weights|mobilenet_iter_73000.caffemodel|${OBJECT_BASE}/mobilenet_iter_73000.caffemodel|52eed8be80522c152a17fb56740de705b79881bde1a167e0e747310523685fc7|23306119|MIT (MobileNet-SSD)"
  "landmarks|lbfmodel.yaml|${LANDMARK_URL}|70dd8b1657c42d1595d6bd13d97d932877b3bed54a95d3c4733a0f740d1fd66b|56375857|MIT (GSOC2017 landmark model)"
)

for entry in "${INVENTORY[@]}"; do
  IFS='|' read -r role file url expected_sha expected_size licence <<< "$entry"
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
# Model manifest
#
# The manifest records the role, the digest and the licence of every
# artefact. The proctoring worker refuses to use an artefact whose digest
# does not match, and refuses to run at all when no face detector is present.
# ---------------------------------------------------------------------------
MANIFEST="$DEST/MODEL-MANIFEST.json"
{
  printf '{\n'
  printf '  "_schema": "examos-model-manifest-v2",\n'
  printf '  "_comment": "Detector artefacts used by the proctoring worker. Each artefact is verified against its recorded digest before use.",\n'
  printf '  "environment": "production",\n'
  printf '  "version": "2",\n'
  printf '  "models": [\n'
  first=1
  for entry in "${INVENTORY[@]}"; do
    IFS='|' read -r role file url expected_sha expected_size licence <<< "$entry"
    [ $first -eq 1 ] || printf ',\n'
    first=0
    printf '    {\n'
    printf '      "name": "%s",\n' "$role"
    printf '      "role": "%s",\n' "$role"
    printf '      "file": "%s",\n' "$file"
    printf '      "sha256": "%s",\n' "$expected_sha"
    printf '      "size_bytes": %s,\n' "$expected_size"
    printf '      "source": "%s",\n' "$url"
    printf '      "licence": "%s"\n' "$licence"
    printf '    }'
  done
  printf '\n  ]\n'
  printf '}\n'
} > "$MANIFEST"

chmod 0644 "$MANIFEST"
chmod 0644 "$DEST"/*.xml "$DEST"/*.prototxt "$DEST"/*.caffemodel "$DEST"/*.yaml 2>/dev/null || true

log ""
log "Model inventory at $DEST:"
for entry in "${INVENTORY[@]}"; do
  IFS='|' read -r role file url expected_sha expected_size licence <<< "$entry"
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
