#!/usr/bin/env bash
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
DATASET_MANIFEST="${EXAMOS_VISION_DATASET_MANIFEST:-$WORKSPACE/tests/phase4/dataset/manifest.csv}"
EVALUATOR="${EXAMOS_VISION_EVALUATOR:-$WORKSPACE/tools/exam-vision-eval}"
mkdir -p "$ARTIFACT_DIR"

if [ ! -r "$DATASET_MANIFEST" ]; then
    echo "[EVALUATION] FAIL: real labelled dataset manifest is required: $DATASET_MANIFEST" >&2
    exit 1
fi
if [ ! -x "$EVALUATOR" ]; then
    echo "[EVALUATION] FAIL: native vision evaluator is required: $EVALUATOR" >&2
    exit 1
fi

"$EVALUATOR" --manifest "$DATASET_MANIFEST" \
    --json "$ARTIFACT_DIR/detection-evaluation.json" \
    --csv "$ARTIFACT_DIR/detection-evaluation.csv"

awk '
BEGIN { passed=0 }
/"status"[[:space:]]*:[[:space:]]*"PASS"/ { passed=1 }
END { exit passed ? 0 : 1 }
' "$ARTIFACT_DIR/detection-evaluation.json"
echo "[EVALUATION] PASS: metrics were produced from real labelled media"
