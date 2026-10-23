#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 — Synthetic Test Dataset Generator
#
# Generates 50 real labelled test clips using ffmpeg test patterns and
# synthetic face/object overlays. Each clip has a JSON ground-truth label.
#
# Labels produced:
#   single_face    × 20 clips  (test pattern with single oval region)
#   multiple_faces × 15 clips  (test pattern with 2 oval regions)
#   no_face        × 10 clips  (solid color or noise, no face-like region)
#   phone_present  ×  3 clips  (rectangular overlay simulating phone)
#   book_present   ×  2 clips  (rectangular overlay simulating book)
#
# These are NOT real photographs — they are deterministic synthetic patterns
# designed to test the detection pipeline end-to-end. The JSON labels are
# ground truth. The actual detection results depend on the loaded models.
#
# Usage:
#   bash tests/p4/generate-test-dataset.sh
#
# Requires: ffmpeg, python3
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
DATASET_DIR="$WORKSPACE/tests/p4/dataset"
mkdir -p "$DATASET_DIR"

log() { echo "[dataset] $*"; }

if ! command -v ffmpeg >/dev/null 2>&1; then
    log "FATAL: ffmpeg not found. Install: apt-get install ffmpeg"
    exit 1
fi

log "Generating 50 labelled test clips in $DATASET_DIR"

# -----------------------------------------------------------------------
# Generate a single clip using ffmpeg lavfi (test source) + overlay
# -----------------------------------------------------------------------
generate_clip() {
    local clip_id="$1" label="$2" pattern="$3" extra_filter="$4"

    local out_file="$DATASET_DIR/${clip_id}.mp4"
    local label_file="$DATASET_DIR/${clip_id}.json"

    # Build ffmpeg filter chain
    local filter="${pattern}"
    if [ -n "$extra_filter" ]; then
        filter="${filter},${extra_filter}"
    fi

    # Generate 3-second clip at 5 fps, 640x480
    ffmpeg -y -loglevel error \
        -f lavfi -i "$filter" \
        -t 3 -r 5 -s 640x480 -pix_fmt yuv420p \
        "$out_file" 2>/dev/null

    if [ ! -s "$out_file" ]; then
        log "WARNING: Failed to generate $clip_id — ffmpeg returned empty file"
        return 1
    fi

    # Write ground-truth label
    cat > "$label_file" <<EOF
{
  "clip_id": "$clip_id",
  "label": "$label",
  "duration_sec": 3,
  "resolution": "640x480",
  "fps": 5,
  "camera_condition": "synthetic_test_pattern",
  "lighting_condition": "determined",
  "annotation_version": "1.0",
  "source": "generate-test-dataset.sh",
  "note": "Synthetic test pattern — not a real photograph. Tests pipeline integration."
}
EOF

    log "  ✓ $clip_id ($label) — $(stat -c%s "$out_file") bytes"
    return 0
}

# -----------------------------------------------------------------------
# Dataset provenance manifest
#
# This generator produces synthetic luminance patterns, not photographs of
# people. Metrics computed over it describe the pipeline, not the detector,
# so the manifest declares the dataset synthetic and the detection gate
# reports BLOCKED rather than a quality verdict.
# -----------------------------------------------------------------------
cat > "$DATASET_DIR/DATASET-MANIFEST.json" <<'MANIFEST'
{
  "_schema": "examos-detection-dataset-manifest-v1",
  "synthetic": true,
  "provenance": "ffmpeg-generated luminance patterns",
  "contains_real_faces": false,
  "consent_recorded": false,
  "annotation_protocol": "programmatic labels derived from the generator",
  "note": "Pipeline integration only. Detection quality cannot be attested from this dataset."
}
MANIFEST

# -----------------------------------------------------------------------
# Single face: testsrc with a bright oval region (face-like luminance pattern)
# -----------------------------------------------------------------------
log "Generating single_face clips (20)..."
for i in $(seq 1 20); do
    clip_id=$(printf "clip-single-%03d" "$i")
    # Create a test pattern with a central bright oval to simulate face luminance
    generate_clip "$clip_id" "single_face" \
        "testsrc2=size=640x480:rate=5" \
        "drawbox=x=200:y=120:w=240:h=300:color=white@0.6:t=fill,format=yuv420p" \
        || true
done

# -----------------------------------------------------------------------
# Multiple faces: two bright oval regions
# -----------------------------------------------------------------------
log "Generating multiple_faces clips (15)..."
for i in $(seq 1 15); do
    clip_id=$(printf "clip-multi-%03d" "$i")
    generate_clip "$clip_id" "multiple_faces" \
        "testsrc2=size=640x480:rate=5" \
        "drawbox=x=80:y=120:w=200:h=280:color=white@0.7:t=fill,drawbox=x=360:y=120:w=200:h=280:color=white@0.7:t=fill,format=yuv420p" \
        || true
done

# -----------------------------------------------------------------------
# No face: solid color or pure noise, no face-like region
# -----------------------------------------------------------------------
log "Generating no_face clips (10)..."
for i in $(seq 1 10); do
    clip_id=$(printf "clip-noface-%03d" "$i")
    generate_clip "$clip_id" "no_face" \
        "color=c=0x202020:s=640x480:r=5" \
        "noise=alls=20:allf=t+u,format=yuv420p" \
        || true
done

# -----------------------------------------------------------------------
# Phone present: dark frame with a bright rectangle (phone shape)
# -----------------------------------------------------------------------
log "Generating phone_present clips (3)..."
for i in $(seq 1 3); do
    clip_id=$(printf "clip-phone-%03d" "$i")
    generate_clip "$clip_id" "phone_present" \
        "color=c=0x101010:s=640x480:r=5" \
        "drawbox=x=250:y=150:w=140:h=280:color=white@0.8:t=fill,format=yuv420p" \
        || true
done

# -----------------------------------------------------------------------
# Book present: dark frame with a wide rectangle (book shape)
# -----------------------------------------------------------------------
log "Generating book_present clips (2)..."
for i in $(seq 1 2); do
    clip_id=$(printf "clip-book-%03d" "$i")
    generate_clip "$clip_id" "book_present" \
        "color=c=0x101010:s=640x480:r=5" \
        "drawbox=x=150:y=200:w=340:h=200:color=white@0.6:t=fill,format=yuv420p" \
        || true
done

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
CLIP_COUNT=$(ls "$DATASET_DIR"/*.mp4 2>/dev/null | wc -l)
LABEL_COUNT=$(ls "$DATASET_DIR"/*.json 2>/dev/null | wc -l)

log ""
log "Dataset generation complete:"
log "  Clips:  $CLIP_COUNT"
log "  Labels: $LABEL_COUNT"
log "  Path:   $DATASET_DIR"
log ""
log "NOTE: These are synthetic test patterns, not real photographs."
log "They test pipeline integration (capture → analyze → event → verify)."
log "Real detection accuracy depends on the loaded ML models."
log "For production evaluation, replace with a real annotated dataset."
