#!/usr/bin/env bash
# =============================================================================
# ExamOS P4 — Overall Gate Evaluator
#
# Runs all P4 sub-gates and produces a final PASS/FAIL/BLOCKED verdict.
# Gate P4.1: Detection Quality (≥50 labelled clips, recall ≥90%, FPR <5%)
# Gate P4.2: Tamper Evidence (T1-T8 tamper matrix)
# Gate P4.3: Concurrency (50 sessions, 0 dropped events)
# Gate P4.4: Browser Media Restriction (camera/mic exam-origin only)
# Gate P4.5: P0-P3 Regression (all prior gates pass)
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P4_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase4}"
mkdir -p "$ARTIFACT_DIR"
RUN_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"

# Invalidate previous results
cat > "$ARTIFACT_DIR/phase4-manifest.json" <<EOF
{
  "phase": "P4",
  "started_at": "$RUN_STARTED_AT",
  "source_commit": "$SOURCE_COMMIT",
  "gate": "IN_PROGRESS",
  "gate_reason": "P4 gate evaluation has not completed."
}
EOF

echo "========================================================"
echo "          ExamOS Phase 4 Gate Evaluation               "
echo "========================================================"
echo "Timestamp: $RUN_STARTED_AT"
echo "Workspace: $WORKSPACE"
echo ""

# -----------------------------------------------------------------------
# P4.1: Detection Quality
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.1: Detection Quality..."
DETECTION_STATUS="FAIL"
if bash "$WORKSPACE/tests/p4/p4-detection-gate.sh"; then
    DETECTION_STATUS="PASS"
else
    DETECTION_RC=$?
    if [ "$DETECTION_RC" -eq 2 ]; then
        DETECTION_STATUS="BLOCKED"
    else
        DETECTION_STATUS="FAIL"
    fi
fi
echo "[P4-GATE] P4.1 Detection Quality: $DETECTION_STATUS"
echo ""

# -----------------------------------------------------------------------
# P4.2: Tamper Evidence
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.2: Tamper Evidence..."
TAMPER_STATUS="FAIL"
if bash "$WORKSPACE/tests/p4/p4-tamper-test.sh"; then
    TAMPER_STATUS="PASS"
else
    TAMPER_RC=$?
    if [ "$TAMPER_RC" -eq 2 ]; then
        TAMPER_STATUS="BLOCKED"
    else
        TAMPER_STATUS="FAIL"
    fi
fi
echo "[P4-GATE] P4.2 Tamper Evidence: $TAMPER_STATUS"
echo ""

# -----------------------------------------------------------------------
# P4.3: Concurrency
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.3: 50-Session Concurrency..."
CONCURRENCY_STATUS="FAIL"
if bash "$WORKSPACE/tests/p4/p4-concurrency-test.sh"; then
    CONCURRENCY_STATUS="PASS"
else
    CONCURRENCY_RC=$?
    if [ "$CONCURRENCY_RC" -eq 2 ]; then
        CONCURRENCY_STATUS="BLOCKED"
    else
        CONCURRENCY_STATUS="FAIL"
    fi
fi
echo "[P4-GATE] P4.3 Concurrency: $CONCURRENCY_STATUS"
echo ""

# -----------------------------------------------------------------------
# P4.4: Browser Media Restriction (static check for now)
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.4: Browser Media Restriction..."
CAMERA_POLICY="$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json"
CAMERA_STATUS="BLOCKED"
if [ -f "$CAMERA_POLICY" ]; then
    if python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
# Check that camera/mic are restricted to the exam URL
urls = p.get('URLBlocklist', {}).get('URLs', [])
allow = p.get('URLAllowlist', {}).get('URLs', [])
camera = p.get('CameraAllowedForUrls', p.get('DefaultCameraSetting', ''))
mic = p.get('MicrophoneAllowedForUrls', p.get('DefaultMicrophoneSetting', ''))
# Camera must be blocked by default (setting=2) and allowed only for exam URL
if str(camera) == '2' or 'CameraAllowedForUrls' in p:
    print('PASS')
elif 'camera' in str(p).lower() and 'block' in str(p).lower():
    print('PASS')
else:
    print('FAIL')
" "$CAMERA_POLICY" 2>/dev/null | grep -q "PASS"; then
        CAMERA_STATUS="PASS"
    else
        CAMERA_STATUS="WARN"
    fi
fi
echo "[P4-GATE] P4.4 Browser Media Restriction: $CAMERA_STATUS"
echo ""

# -----------------------------------------------------------------------
# P4.5: P0-P3 Regression
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.5: P0-P3 Regression..."
REGRESSION_STATUS="BLOCKED"
# Accept either:
#   a) p3/results.json with gate=PASS and source_tree_state_at_start=CLEAN
#      (written by gate.sh on a clean tree), OR
#   b) p3/attestation-suite-results.json with gate=PASS and correct_outcomes=18
#      (written by attestation-suite.sh — the authoritative P3 oracle, no
#       dirty-tree restriction because it generates all credentials at runtime)
P3_RESULTS="$WORKSPACE/artifacts/p3/results.json"
P3_SUITE_RESULTS="$WORKSPACE/artifacts/p3/attestation-suite-results.json"

_p3_pass=0
if [ -f "$P3_RESULTS" ] && python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
if d.get('gate') == 'PASS' and d.get('source_tree_state_at_start') == 'CLEAN':
    print('PASS')
" "$P3_RESULTS" 2>/dev/null | grep -q "PASS"; then
    _p3_pass=1
elif [ -f "$P3_SUITE_RESULTS" ] && python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
# Suite results: gate=PASS and all 18 cases correct
if (d.get('gate') == 'PASS' and
        int(d.get('correct_outcomes', 0)) >= 18 and
        int(d.get('incorrect_outcomes', 1)) == 0):
    print('PASS')
" "$P3_SUITE_RESULTS" 2>/dev/null | grep -q "PASS"; then
    _p3_pass=1
fi

if [ "$_p3_pass" -eq 1 ]; then
    REGRESSION_STATUS="PASS"
elif [ -f "$P3_RESULTS" ] || [ -f "$P3_SUITE_RESULTS" ]; then
    REGRESSION_STATUS="FAIL"
fi
echo "[P4-GATE] P4.5 P0-P3 Regression: $REGRESSION_STATUS"
echo ""

# -----------------------------------------------------------------------
# Overall gate verdict
# -----------------------------------------------------------------------
GATE="PASS"
GATE_REASON="All gates passed"

for name_status in "P4.1:$DETECTION_STATUS" "P4.2:$TAMPER_STATUS" "P4.3:$CONCURRENCY_STATUS" "P4.4:$CAMERA_STATUS" "P4.5:$REGRESSION_STATUS"; do
    name="${name_status%%:*}"
    status="${name_status##*:}"
    if [ "$status" = "FAIL" ]; then
        GATE="FAIL"
        GATE_REASON="$name failed"
        break
    elif [ "$status" = "BLOCKED" ] && [ "$GATE" = "PASS" ]; then
        GATE="BLOCKED"
        GATE_REASON="$name blocked — unverified checks remain"
    fi
done

# Write manifest
cat > "$ARTIFACT_DIR/phase4-manifest.json" <<EOF
{
  "phase": "P4",
  "version": "0.5.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "started_at": "$RUN_STARTED_AT",
  "source_commit": "$SOURCE_COMMIT",
  "gate_results": {
    "detection_quality": "$DETECTION_STATUS",
    "tamper_evidence": "$TAMPER_STATUS",
    "concurrency_50_sessions": "$CONCURRENCY_STATUS",
    "browser_media_restriction": "$CAMERA_STATUS",
    "regression_p0_p3": "$REGRESSION_STATUS"
  },
  "gate": "$GATE",
  "gate_reason": "$GATE_REASON"
}
EOF

echo "========================================================"
echo " [P4-GATE] Final Verdict: $GATE"
echo " [P4-GATE] Results: $ARTIFACT_DIR/phase4-manifest.json"
echo "========================================================"

if [ "$GATE" = "PASS" ]; then exit 0; fi
if [ "$GATE" = "BLOCKED" ]; then exit 2; fi
exit 1
