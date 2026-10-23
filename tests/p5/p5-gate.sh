#!/usr/bin/env bash
# =============================================================================
# ExamOS P5 — Overall Gate Evaluator
#
# Gates:
#   P5.1: Behaviour Engine (features, baseline, risk score)
#   P5.2: Variant Engine (generation, grading, watermark tracing)
#   P5.3: Viva Engine (generation, response, reviewer workflow)
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P5_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase5}"
mkdir -p "$ARTIFACT_DIR"
if [ -z "${EXAMOS_P5_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$ARTIFACT_DIR/runs"
    ARTIFACT_DIR="$(mktemp -d "$ARTIFACT_DIR/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
export EXAMOS_P5_ARTIFACT_DIR="$ARTIFACT_DIR"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
SOURCE_TREE_STATE="CLEAN"
if [ -n "$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' ':(exclude)cache/**')" ]; then
    SOURCE_TREE_STATE="DIRTY"
fi

echo "========================================================"
echo "          ExamOS Phase 5 Gate Evaluation               "
echo "========================================================"
echo ""

# P5.1
echo "[P5-GATE] P5.1: Behaviour Engine..."
BEHAVIOUR_STATUS="FAIL"
if bash "$WORKSPACE/tests/p5/p5-behaviour-test.sh"; then
    BEHAVIOUR_STATUS="PASS"
else
    [ $? -eq 2 ] && BEHAVIOUR_STATUS="BLOCKED"
fi
echo "[P5-GATE] P5.1 Behaviour: $BEHAVIOUR_STATUS"
echo ""

# P5.2
echo "[P5-GATE] P5.2: Variant Engine..."
VARIANT_STATUS="FAIL"
if bash "$WORKSPACE/tests/p5/p5-variant-test.sh"; then
    VARIANT_STATUS="PASS"
else
    [ $? -eq 2 ] && VARIANT_STATUS="BLOCKED"
fi
echo "[P5-GATE] P5.2 Variant: $VARIANT_STATUS"
echo ""

# P5.3
echo "[P5-GATE] P5.3: Viva Engine..."
VIVA_STATUS="FAIL"
if bash "$WORKSPACE/tests/p5/p5-viva-test.sh"; then
    VIVA_STATUS="PASS"
else
    [ $? -eq 2 ] && VIVA_STATUS="BLOCKED"
fi
echo "[P5-GATE] P5.3 Viva: $VIVA_STATUS"
echo ""

# Verdict
GATE="PASS"
GATE_REASON="All P5 gates passed"
for ns in "P5.1:$BEHAVIOUR_STATUS" "P5.2:$VARIANT_STATUS" "P5.3:$VIVA_STATUS"; do
    name="${ns%%:*}"; status="${ns##*:}"
    if [ "$status" = "FAIL" ]; then GATE="FAIL"; GATE_REASON="$name failed"; break; fi
    if [ "$status" = "BLOCKED" ] && [ "$GATE" = "PASS" ]; then GATE="BLOCKED"; GATE_REASON="$name blocked"; fi
done

if [ "$SOURCE_TREE_STATE" = "DIRTY" ] && [ "$GATE" = "PASS" ]; then
    GATE="BLOCKED"
    GATE_REASON="source tree is dirty; results are diagnostic and not release evidence"
fi

cat > "$ARTIFACT_DIR/phase5-manifest.json" <<EOF
{
  "schema": "examos.p5.results.v1",
  "phase": "P5",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_commit": "$SOURCE_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
  "gate_results": {
    "behaviour_engine": "$BEHAVIOUR_STATUS",
    "variant_engine": "$VARIANT_STATUS",
    "viva_engine": "$VIVA_STATUS"
  },
  "gate": "$GATE",
  "gate_reason": "$GATE_REASON"
}
EOF

echo "========================================================"
echo " [P5-GATE] Final Verdict: $GATE"
echo "========================================================"

[ "$GATE" = "PASS" ] && exit 0
[ "$GATE" = "BLOCKED" ] && exit 2
exit 1
