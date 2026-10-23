#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 — Detection Quality Evaluation Gate (Gate P4.1)
#
# Evaluates the vision engine against a real labelled dataset.
#
# Dataset location: tests/p4/dataset/
#   Each clip has a JSON label file with ground truth.
#   Format: tests/p4/dataset/<clip_id>.json
#     {
#       "clip_id": "clip-001",
#       "label": "single_face" | "multiple_faces" | "no_face" | "phone_present" | "book_present",
#       "duration_sec": 5,
#       "resolution": "640x480",
#       "annotation_version": "1.0"
#     }
#
# The proctoring binary processes each clip and the evaluator compares
# the emitted events against the ground truth labels.
#
# Targets:
#   multiple-face recall ≥ 90%
#   no-face recall ≥ 90%
#   false-positive rate < 5%
#
# Reports ACTUAL values even when targets are missed.
# NEVER converts NOT_TESTED into PASS.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
DATASET_DIR="$WORKSPACE/tests/p4/dataset"
PROCTOR_BIN="$WORKSPACE/proctoring/examos-proctor"
# PG-42: Support production mode testing (EXAMOS_TEST_MODE=production uses
# EXAMOS_ALLOW_UNPROVISIONED_DEV=0 + EXAMOS_TPM_MODE=production instead of dev mode)
EXAMOS_TEST_MODE="${EXAMOS_TEST_MODE:-dev}"
SERVER_PORT="${EXAMOS_P4_SERVER_PORT:-9102}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
EVENT_LOG="$ARTIFACT_DIR/detection-events.log"
DETAIL_CSV="$ARTIFACT_DIR/detection-clips.csv"
MODEL_DIR="${EXAMOS_FACE_MODEL_DIR:-$WORKSPACE/tests/p4/models}"
MODEL_MANIFEST="$MODEL_DIR/MODEL-MANIFEST.json"
PROCTOR_TOKEN="$(openssl rand -hex 32)"

mkdir -p "$ARTIFACT_DIR"
: > "$EVENT_LOG"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

echo "=== [P4-DETECTION] Detection Quality Evaluation ==="
echo "  Dataset: $DATASET_DIR"
echo "  Proctor: $PROCTOR_BIN"
echo ""

# -----------------------------------------------------------------------
# Check dataset exists
# -----------------------------------------------------------------------
if [ ! -d "$DATASET_DIR" ] || [ -z "$(ls -A "$DATASET_DIR"/*.json 2>/dev/null)" ]; then
    echo "  BLOCKED: No labelled dataset found at $DATASET_DIR" >&2
    echo "  Provide ≥50 labelled clips with ground-truth JSON labels." >&2
    echo "  Run: bash tests/p4/fetch-real-dataset.sh (COCO val2017 real photographs)" >&2
    echo "  Or:  bash tests/p4/generate-test-dataset.sh (synthetic pipeline check; gate stays BLOCKED)" >&2

    # Write BLOCKED result — never PASS
    cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "status": "BLOCKED",
  "reason": "No labelled dataset found at $DATASET_DIR. Provide ≥50 clips with ground-truth labels.",
  "total_clips": 0,
  "metrics": {"true_positives":0,"true_negatives":0,"false_positives":0,"false_negatives":0,
              "accuracy_percent":0,"recall_percent":0,"precision_percent":0,
              "false_positive_rate_percent":0},
  "targets": {"multiple_face_recall_min":90,"no_face_recall_min":90,"max_false_positive_rate":5},
  "timestamp": "$(ts)"
}
EOF
    exit 2
fi

# Count clips (the provenance manifest is not a clip)
CLIP_COUNT=$(ls "$DATASET_DIR"/*.json 2>/dev/null | grep -v 'DATASET-MANIFEST.json' | wc -l)
echo "  Clips found: $CLIP_COUNT"

if [ "$CLIP_COUNT" -lt 50 ]; then
    echo "  WARNING: Dataset has $CLIP_COUNT clips — target is ≥50" >&2
fi

# -----------------------------------------------------------------------
# Check proctor binary & vision models
# -----------------------------------------------------------------------
if [ ! -x "$PROCTOR_BIN" ]; then
    echo "  BLOCKED: Proctor binary not found at $PROCTOR_BIN" >&2
    echo "  Run: make -C proctoring all" >&2
    cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "status": "BLOCKED",
  "reason": "Proctor binary not built. Run: make -C proctoring all",
  "total_clips": $CLIP_COUNT,
  "timestamp": "$(ts)"
}
EOF
    exit 2
fi

if [ ! -f "$MODEL_DIR/face_detection_yunet_2023mar.onnx" ] ||
   [ ! -f "$MODEL_DIR/object_detection_yolox_2022nov.onnx" ] ||
   [ ! -f "$MODEL_MANIFEST" ]; then
    echo "  BLOCKED: vision engine weights are not provisioned in $MODEL_DIR" >&2
    echo "  Run: bash scripts/download-vision-models.sh --dest tests/p4/models" >&2
    cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "status": "BLOCKED",
  "reason": "Vision engine models (YuNet face detector, YOLOX object detector and MODEL-MANIFEST.json) not installed in $MODEL_DIR. Run scripts/download-vision-models.sh.",
  "total_clips": $CLIP_COUNT,
  "timestamp": "$(ts)"
}
EOF
    exit 2
fi

# -----------------------------------------------------------------------
# Start server for event collection
# -----------------------------------------------------------------------
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_PID=""

if [ -x "$SERVER_BIN" ]; then
    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="/tmp/examos-p4-detection-ledger-$$.log" \
    EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)" \
    EXAMOS_EVENT_CHAIN_PATH="$EVENT_LOG" \
    EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)" \
    EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
    EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)" \
    EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)" \
    EXAMOS_TPM_MODE="${EXAMOS_TPM_MODE:-development}" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV="${EXAMOS_ALLOW_UNPROVISIONED_DEV:-1}" \
    EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json" \
    EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json" \
        "$SERVER_BIN" >/tmp/examos-p4-detection-server.log 2>&1 &
    SERVER_PID=$!
    for i in $(seq 1 15); do
        curl -sf "${SERVER_URL}/api/v1/health" >/dev/null 2>&1 && break
        sleep 0.5
    done
    if ! curl -sf "${SERVER_URL}/api/v1/health" >/dev/null 2>&1; then
        echo "  BLOCKED: the event-collection server did not become ready at $SERVER_URL" >&2
        cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "status": "BLOCKED",
  "reason": "Event-collection server did not become ready; detections cannot be attested.",
  "total_clips": $CLIP_COUNT,
  "timestamp": "$(ts)"
}
EOF
        exit 2
    fi
else
    echo "  BLOCKED: server binary not found at $SERVER_BIN" >&2
    cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "status": "BLOCKED",
  "reason": "Server binary not built. Run make -C server all.",
  "total_clips": $CLIP_COUNT,
  "timestamp": "$(ts)"
}
EOF
    exit 2
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# -----------------------------------------------------------------------
# Detector environment.  The warm-up below uses the same provisioned manifest
# and credentials as every evaluated clip, so it warms YuNet, YOLOX and LBF
# rather than merely the dynamic loader.
# -----------------------------------------------------------------------
export EXAMOS_PROCTOR_DETECTOR_CONFIG="$MODEL_MANIFEST"
export EXAMOS_PROCTOR_MODEL_NAME="yolox-s_yunet"
export EXAMOS_PROCTOR_MODEL_VERSION="5"
export EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN"
if [ "$EXAMOS_TEST_MODE" != "production" ]; then
    export EXAMOS_TPM_MODE="${EXAMOS_TPM_MODE:-development}"
    export EXAMOS_ALLOW_UNPROVISIONED_DEV=1
fi

# -----------------------------------------------------------------------
# Warm the dynamic loader and the model files.  The first proctor start on a
# cold WSL page cache spends most of its budget loading OpenCV and hashing the
# 92 MB model inventory; without this warm-up the first evaluated clip would
# measure process start-up rather than detection quality.
# -----------------------------------------------------------------------
echo "  Warming detector libraries and model cache..."
timeout 30 "$PROCTOR_BIN" --session "p4-warmup" --server "$SERVER_URL" \
    --device "$DATASET_DIR/empty-001.mp4" >/dev/null 2>&1 || true

# -----------------------------------------------------------------------
# Process each clip through the proctor and collect events
# -----------------------------------------------------------------------
echo "  Processing clips..."

TP=0; TN=0; FP=0; FN=0
MULTI_FACE_TP=0; MULTI_FACE_FN=0
NO_FACE_TP=0; NO_FACE_FN=0
SINGLE_FACE_OK=0; SINGLE_FACE_TOTAL=0
PHONE_TP=0; PHONE_FN=0
BOOK_TP=0; BOOK_FN=0
TOTAL_PROCESSED=0
FAILURES=0

# Per-clip audit trail.  Every recognised clip gets a row, including clips that
# produced no detector event, so a timing failure cannot hide inside an
# aggregate recall number.
echo "clip_id,label,face_events,multiple_faces,phone_detected,book_detected,events" > "$DETAIL_CSV"

# The proctor attributes every event to the detector that produced it, and
# authenticates to the server.  The environment was exported before the warm-up
# so both the warm-up and every clip use the same approved detector.

for label_file in "$DATASET_DIR"/*.json; do
    [ -f "$label_file" ] || continue
    case "$(basename "$label_file")" in
        DATASET-MANIFEST.json) continue ;;
    esac

    # Read label
    CLIP_ID=$(python3 -c "import json; print(json.load(open('$label_file')).get('clip_id','unknown'))" 2>/dev/null || echo "unknown")
    LABEL=$(python3 -c "import json; print(json.load(open('$label_file')).get('label','unknown'))" 2>/dev/null || echo "unknown")

    # Check if video clip exists
    CLIP_VIDEO=""
    for ext in mp4 avi mov mkv webm; do
        if [ -f "$DATASET_DIR/${CLIP_ID}.${ext}" ]; then
            CLIP_VIDEO="$DATASET_DIR/${CLIP_ID}.${ext}"
            break
        fi
    done

    TOTAL_PROCESSED=$((TOTAL_PROCESSED + 1))

    # If no video file, this clip is BLOCKED — count as failure
    if [ -z "$CLIP_VIDEO" ]; then
        echo "  SKIP: $CLIP_ID — no video file found"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    # Run the proctor in the foreground under GNU timeout.  timeout sends
    # SIGTERM to the worker and waits for it to finish its current frame and
    # flush the event that frame produced.  Killing a background timeout
    # wrapper could return before the worker had delivered its event.  The
    # budget is long enough for model verification, LBF landmarks and several
    # one-second samples even on a frame with multiple faces.
    SESSION_ID="detect-${CLIP_ID}"
    timeout --signal=TERM --kill-after=4 20 "$PROCTOR_BIN" --session "$SESSION_ID" \
        --server "$SERVER_URL" --device "$CLIP_VIDEO" >/dev/null 2>&1 || true
    sleep 1

    # Read events from server log
    FACE_POSITIVE=0
    DETECTED_MULTIPLE=false
    DETECTED_NO_FACE=false
    DETECTED_PHONE=false
    DETECTED_BOOK=false
    SESSION_EVENTS=""

    if [ -f "$EVENT_LOG" ]; then
        SESSION_EVENTS=$(grep -F "\"session_id\":\"${SESSION_ID}\"" "$EVENT_LOG" 2>/dev/null || true)
        FACE_POSITIVE=$(printf '%s\n' "$SESSION_EVENTS" | grep -c -E 'FACE_PRESENT|MULTIPLE_FACES' 2>/dev/null || true)
        FACE_POSITIVE=${FACE_POSITIVE:-0}
        DETECTED_MULTIPLE=$(printf '%s\n' "$SESSION_EVENTS" | grep -q "MULTIPLE_FACES" && echo true || echo false)
        DETECTED_NO_FACE=$(printf '%s\n' "$SESSION_EVENTS" | grep -q "NO_FACE" && echo true || echo false)
        DETECTED_PHONE=$(printf '%s\n' "$SESSION_EVENTS" | grep -q "PHONE_DETECTED" && echo true || echo false)
        DETECTED_BOOK=$(printf '%s\n' "$SESSION_EVENTS" | grep -q "BOOK_DETECTED" && echo true || echo false)
    fi

    # Compare against ground truth.
    #
    # The face task is binary: is a face present in the frame or not.
    # single_face / multiple_faces are positive examples; no_face is a
    # negative example. Every clip therefore contributes to exactly one of
    # TP, FN, FP or TN, so the false-positive rate is measured rather than
    # assumed.
    DETECTED_FACE=false
    if [ "$FACE_POSITIVE" -gt 0 ]; then
        DETECTED_FACE=true
    fi

    EVENTS_COUNT=$(printf '%s\n' "$SESSION_EVENTS" | grep -c . 2>/dev/null || true)
    EVENTS_COUNT=${EVENTS_COUNT:-0}
    echo "  ${CLIP_ID} [${LABEL}] face=${FACE_POSITIVE} multiple=${DETECTED_MULTIPLE} phone=${DETECTED_PHONE} book=${DETECTED_BOOK} events=${EVENTS_COUNT}"
    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$CLIP_ID" "$LABEL" "$FACE_POSITIVE" "$DETECTED_MULTIPLE" \
        "$DETECTED_PHONE" "$DETECTED_BOOK" "$EVENTS_COUNT" >> "$DETAIL_CSV"

    case "$LABEL" in
        single_face|multiple_faces)
            if [ "$LABEL" = "single_face" ]; then
                SINGLE_FACE_TOTAL=$((SINGLE_FACE_TOTAL + 1))
            fi
            if [ "$DETECTED_FACE" = "true" ]; then
                TP=$((TP + 1))
                if [ "$LABEL" = "single_face" ]; then
                    SINGLE_FACE_OK=$((SINGLE_FACE_OK + 1))
                fi
                if [ "$LABEL" = "multiple_faces" ]; then
                    if [ "$DETECTED_MULTIPLE" = "true" ]; then
                        MULTI_FACE_TP=$((MULTI_FACE_TP + 1))
                    else
                        MULTI_FACE_FN=$((MULTI_FACE_FN + 1))
                    fi
                fi
            else
                FN=$((FN + 1))
                if [ "$LABEL" = "multiple_faces" ]; then
                    MULTI_FACE_FN=$((MULTI_FACE_FN + 1))
                fi
            fi
            ;;
        no_face)
            if [ "$DETECTED_FACE" = "false" ]; then
                TN=$((TN + 1))
                NO_FACE_TP=$((NO_FACE_TP + 1))
            else
                FP=$((FP + 1))
                NO_FACE_FN=$((NO_FACE_FN + 1))
            fi
            ;;
        phone_present)
            if [ "$DETECTED_PHONE" = "true" ]; then
                TP=$((TP + 1))
                PHONE_TP=$((PHONE_TP + 1))
            else
                FN=$((FN + 1))
                PHONE_FN=$((PHONE_FN + 1))
            fi
            ;;
        book_present)
            if [ "$DETECTED_BOOK" = "true" ]; then
                TP=$((TP + 1))
                BOOK_TP=$((BOOK_TP + 1))
            else
                FN=$((FN + 1))
                BOOK_FN=$((BOOK_FN + 1))
            fi
            ;;
        *)
            # Unknown label - not part of the evaluated set.
            TOTAL_PROCESSED=$((TOTAL_PROCESSED - 1))
            ;;
    esac
done

# Calculate metrics.
#
# Precision and recall are computed from the confusion matrix. The false
# positive rate is the proportion of genuinely negative clips in which a
# face was reported, which is the quantity the gate actually constrains.
if [ $((TP + FN)) -gt 0 ]; then
    RECALL=$(echo "scale=2; $TP * 100 / ($TP + FN)" | bc 2>/dev/null || echo "0")
else
    RECALL="0"
fi

if [ $((TP + FP)) -gt 0 ]; then
    PRECISION=$(echo "scale=2; $TP * 100 / ($TP + FP)" | bc 2>/dev/null || echo "0")
else
    PRECISION="0"
fi

NEGATIVE_TOTAL=$((TN + FP))
if [ $NEGATIVE_TOTAL -gt 0 ]; then
    FPR=$(echo "scale=2; $FP * 100 / $NEGATIVE_TOTAL" | bc 2>/dev/null || echo "0")
else
    FPR="0"
fi

if [ $TOTAL_PROCESSED -gt 0 ]; then
    ACCURACY=$(echo "scale=2; ($TP + $TN) * 100 / $TOTAL_PROCESSED" | bc 2>/dev/null || echo "0")
else
    ACCURACY="0"
fi

# Multi-face recall
if [ $((MULTI_FACE_TP + MULTI_FACE_FN)) -gt 0 ]; then
    MULTI_RECALL=$(echo "scale=2; $MULTI_FACE_TP * 100 / ($MULTI_FACE_TP + $MULTI_FACE_FN)" | bc 2>/dev/null || echo "0")
else
    MULTI_RECALL="N/A"
fi

# No-face recall
if [ $((NO_FACE_TP + NO_FACE_FN)) -gt 0 ]; then
    NOFACE_RECALL=$(echo "scale=2; $NO_FACE_TP * 100 / ($NO_FACE_TP + $NO_FACE_FN)" | bc 2>/dev/null || echo "0")
else
    NOFACE_RECALL="N/A"
fi

# Single-face and object-class recall.  These are reported for transparency:
# the P4 gate targets constrain multiple-face recall, no-face recall and the
# false-positive rate, not object-class recall.
if [ "$SINGLE_FACE_TOTAL" -gt 0 ]; then
    SINGLE_RECALL=$(echo "scale=2; $SINGLE_FACE_OK * 100 / $SINGLE_FACE_TOTAL" | bc 2>/dev/null || echo "0")
else
    SINGLE_RECALL="N/A"
fi
if [ $((PHONE_TP + PHONE_FN)) -gt 0 ]; then
    PHONE_RECALL=$(echo "scale=2; $PHONE_TP * 100 / ($PHONE_TP + $PHONE_FN)" | bc 2>/dev/null || echo "0")
else
    PHONE_RECALL="N/A"
fi
if [ $((BOOK_TP + BOOK_FN)) -gt 0 ]; then
    BOOK_RECALL=$(echo "scale=2; $BOOK_TP * 100 / ($BOOK_TP + $BOOK_FN)" | bc 2>/dev/null || echo "0")
else
    BOOK_RECALL="N/A"
fi

# Gate decision
GATE="PASS"
REASON="All targets met"
if [ "$MULTI_RECALL" != "N/A" ] && [ "$(echo "$MULTI_RECALL < 90" | bc 2>/dev/null)" = "1" ]; then
    GATE="FAIL"; REASON="multiple-face recall ${MULTI_RECALL}% < 90%"
fi
if [ "$NOFACE_RECALL" != "N/A" ] && [ "$(echo "$NOFACE_RECALL < 90" | bc 2>/dev/null)" = "1" ]; then
    GATE="FAIL"; REASON="no-face recall ${NOFACE_RECALL}% < 90%"
fi
if [ "$(echo "$FPR >= 5" | bc 2>/dev/null)" = "1" ]; then
    GATE="FAIL"; REASON="false-positive rate ${FPR}% >= 5%"
fi
if [ $((TP + FN + FP + TN)) -ne $TOTAL_PROCESSED ]; then
    GATE="FAIL"; REASON="the confusion matrix does not account for every processed clip"
fi

# Dataset provenance.
#
# Metrics computed over synthetic test patterns describe the pipeline, not
# the detector. A gate verdict over such a dataset would be misleading, so
# the gate reports BLOCKED instead of PASS.
DATASET_MANIFEST="$DATASET_DIR/DATASET-MANIFEST.json"
if [ ! -f "$DATASET_MANIFEST" ]; then
    GATE="BLOCKED"; REASON="the dataset has no provenance manifest; detection quality cannot be attested"
elif python3 - "$DATASET_MANIFEST" <<'PY' 2>/dev/null
import json, sys
manifest = json.load(open(sys.argv[1]))
raise SystemExit(0 if manifest.get("synthetic") is False else 1)
PY
then
    :
else
    GATE="BLOCKED"; REASON="the dataset is synthetic; detection quality cannot be attested from it"
fi

echo ""
echo "  Clips processed:     $TOTAL_PROCESSED"
echo "  True positives:       $TP"
echo "  False negatives:      $FN"
echo "  False positives:      $FP"
echo "  Recall:               ${RECALL}%"
echo "  Precision:            ${PRECISION}%"
echo "  Multi-face recall:    ${MULTI_RECALL}% (target ≥ 90%)"
echo "  No-face recall:       ${NOFACE_RECALL}% (target ≥ 90%)"
echo "  Single-face recall:   ${SINGLE_RECALL}% (informational)"
echo "  Phone recall:         ${PHONE_RECALL}% (informational)"
echo "  Book recall:          ${BOOK_RECALL}% (informational)"
echo "  False positive rate:  ${FPR}% (target < 5%)"
echo "  Gate:                 $GATE"
[ "$GATE" = "FAIL" ] && echo "  Reason: $REASON"

# Write JSON
cat > "$ARTIFACT_DIR/detection-evaluation.json" <<EOF
{
  "phase": "P4",
  "test": "detection_quality",
  "dataset_version": "coco-val2017-v1",
  "total_clips": $TOTAL_PROCESSED,
  "per_clip_csv": "detection-clips.csv",
  "event_log": "detection-events.log",
  "metrics": {
    "true_positives": $TP,
    "true_negatives": $TN,
    "false_positives": $FP,
    "false_negatives": $FN,
    "accuracy_percent": $ACCURACY,
    "recall_percent": $RECALL,
    "precision_percent": $PRECISION,
    "false_positive_rate_percent": $FPR,
    "multiple_face_recall_percent": "$MULTI_RECALL",
    "no_face_recall_percent": "$NOFACE_RECALL",
    "single_face_recall_percent": "$SINGLE_RECALL",
    "phone_recall_percent": "$PHONE_RECALL",
    "book_recall_percent": "$BOOK_RECALL"
  },
  "informational_metrics": {
    "single_face_recall_percent": "$SINGLE_RECALL",
    "phone_recall_percent": "$PHONE_RECALL",
    "book_recall_percent": "$BOOK_RECALL",
    "note": "Phone and book recall are measured and reported but are not part of the existing P4 gate targets (multiple-face recall, no-face recall, false-positive rate)."
  },
  "targets": {
    "multiple_face_recall_min": 90,
    "no_face_recall_min": 90,
    "max_false_positive_rate": 5
  },
  "status": "$GATE",
  "reason": "$REASON",
  "timestamp": "$(ts)"
}
EOF

# Write CSV
cat > "$ARTIFACT_DIR/detection-evaluation.csv" <<EOF
metric,value
total_clips,$TOTAL_PROCESSED
true_positives,$TP
true_negatives,$TN
false_positives,$FP
false_negatives,$FN
recall_percent,$RECALL
precision_percent,$PRECISION
multiple_face_recall_percent,$MULTI_RECALL
no_face_recall_percent,$NOFACE_RECALL
single_face_recall_percent,$SINGLE_RECALL
phone_recall_percent,$PHONE_RECALL
book_recall_percent,$BOOK_RECALL
false_positive_rate_percent,$FPR
gate,$GATE
EOF

echo ""
echo "=== [P4-DETECTION] $GATE ==="

[ "$GATE" = "PASS" ]
