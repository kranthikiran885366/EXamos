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
if [ -z "${EXAMOS_P4_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$ARTIFACT_DIR/runs"
    ARTIFACT_DIR="$(mktemp -d "$ARTIFACT_DIR/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
export EXAMOS_P4_ARTIFACT_DIR="$ARTIFACT_DIR"
RUN_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
SOURCE_TREE_STATE="CLEAN"
if [ -n "$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' ':(exclude)cache/**')" ]; then
    SOURCE_TREE_STATE="DIRTY"
fi

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
CAMERA_POLICIES=(
    "$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json"
    "$WORKSPACE/image/overlay/etc/opt/chrome/policies/managed/examos_policies.json"
)
EXAM_CONFIG="$WORKSPACE/image/overlay/etc/examos/exam.conf"
CAMERA_STATUS="FAIL"
POLICY_FILES_PRESENT=true
for policy_path in "${CAMERA_POLICIES[@]}"; do
    [ -f "$policy_path" ] || POLICY_FILES_PRESENT=false
done
if [ "$POLICY_FILES_PRESENT" = true ]; then
    CAMERA_RESULT=""
    GENERATED_POLICY="$(mktemp)"
    if EXAM_CONF="$EXAM_CONFIG" bash "$WORKSPACE/image/scripts/generate-chromium-policy.sh" --dry-run >"$GENERATED_POLICY" 2>"$GENERATED_POLICY.log" &&
        CAMERA_RESULT=$(python3 - "$GENERATED_POLICY" "$GENERATED_POLICY" "$EXAM_CONFIG" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys
from urllib.parse import urlsplit

def fail(message, code=1):
    print(message)
    raise SystemExit(code)

try:
    policies = [json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
                for path in sys.argv[1:-1]]
    config_lines = pathlib.Path(sys.argv[-1]).read_text(encoding="utf-8").splitlines()
except (OSError, json.JSONDecodeError) as error:
    fail("policy/config cannot be read or parsed: " + str(error))
if not policies or any(policy != policies[0] for policy in policies[1:]):
    fail("Chromium and Chrome managed policies differ")
policy = policies[0]

config = {}
for line in config_lines:
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()
exam_url = config.get("EXAM_URL", "")
if not exam_url or exam_url == "NOT_CONFIGURED":
    fail("EXAM_URL is not provisioned; runtime media policy cannot be qualified", 2)

def canonical_origin(raw, allow_path):
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host or parsed.username is not None or parsed.password is not None:
        return None
    if allow_path:
        if parsed.path and parsed.path != "/":
            return None
    elif not parsed.path.startswith("/"):
        return None
    if parsed.query or parsed.fragment:
        return None
    try:
        address = ipaddress.ip_address(host)
        name = address.compressed.lower()
        if address.version == 6:
            if address.scope_id if hasattr(address, "scope_id") else False:
                return None
            name = "[" + name + "]"
        loopback = address.is_loopback
    except ValueError:
        try:
            name = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if not re.fullmatch(label + r"(?:\." + label + r")*", name):
            return None
        loopback = name == "localhost"
    if scheme not in ("https", "http") or (scheme == "http" and (not loopback or port != 8000)):
        return None
    authority = name + ((":" + str(port)) if port is not None else "")
    return scheme + "://" + authority

exam_origin = canonical_origin(exam_url, allow_path=False)
if not exam_origin:
    fail("configured EXAM_URL is invalid")
expected = [exam_origin + "/*"]
for raw in filter(None, (item.strip() for item in config.get("ALLOWED_ORIGINS", "").split(","))):
    origin = canonical_origin(raw, allow_path=True)
    if not origin:
        fail("ALLOWED_ORIGINS contains an invalid origin")
    pattern = origin + "/*"
    if origin in ("http://127.0.0.1:8000", "http://localhost:8000"):
        fail("loopback admin origins cannot be used for exam camera/microphone access")
    if pattern not in expected:
        expected.append(pattern)

if policy.get("URLBlocklist") != ["*"]:
    fail("URLBlocklist is not default-deny")
if policy.get("URLAllowlist") != expected:
    fail("URLAllowlist does not exactly match configured origins")
for key in ("VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"):
    if policy.get(key) != expected:
        fail(key + " does not exactly match configured origins")
if policy.get("VideoCaptureAllowed") is True or policy.get("AudioCaptureAllowed") is True:
    fail("global camera/microphone capture is enabled")
print("PASS: deny-by-default and media capture limited to explicitly configured origins")
PY
    ); then
        CAMERA_STATUS="PASS"
        rm -f "$GENERATED_POLICY" "$GENERATED_POLICY.log"
    else
        CAMERA_RC=$?
        if [ "$CAMERA_RC" -eq 2 ]; then
            CAMERA_STATUS="BLOCKED"
        else
            CAMERA_STATUS="FAIL"
        fi
        echo "$CAMERA_RESULT"
        cat "$GENERATED_POLICY.log" >&2 2>/dev/null || true
        rm -f "$GENERATED_POLICY" "$GENERATED_POLICY.log"
    fi
fi
echo "[P4-GATE] P4.4 Browser Media Restriction: $CAMERA_STATUS"
echo ""

# -----------------------------------------------------------------------
# P4.5: P0-P3 Regression
# -----------------------------------------------------------------------
echo "[P4-GATE] Gate P4.5: P0-P3 Regression..."
REGRESSION_STATUS="BLOCKED"
# P3 results must identify the current commit and attest that the source tree
# was clean when evidence was collected. The retired synthetic suite result is
# deliberately ignored; it cannot qualify a production regression.
P3_RESULTS="${EXAMOS_P3_ARTIFACT_DIR:-}"
if [ -n "$P3_RESULTS" ]; then
    P3_RESULTS="$P3_RESULTS/results.json"
else
    P3_RESULTS="$(find "$WORKSPACE/artifacts/p3/runs" -mindepth 2 -maxdepth 2 \
        -type f -name results.json -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)"
    [ -n "$P3_RESULTS" ] || P3_RESULTS="$WORKSPACE/artifacts/p3/results.json"
fi
P3_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
if [ -f "$P3_RESULTS" ]; then
    REGRESSION_STATUS="$(python3 - "$P3_RESULTS" "$P3_COMMIT" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        result = json.load(stream)
except (OSError, json.JSONDecodeError):
    print("FAIL")
    raise SystemExit(0)

if result.get("gate") == "FAIL":
    print("FAIL")
elif (result.get("gate") == "PASS" and
      result.get("source_tree_state", result.get("source_tree_state_at_start")) == "CLEAN" and
      result.get("source_commit") == sys.argv[2]):
    print("PASS")
else:
    print("BLOCKED")
PY
)"
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
if [ "$SOURCE_TREE_STATE" = "DIRTY" ] && [ "$GATE" = "PASS" ]; then
    GATE="BLOCKED"
    GATE_REASON="source tree is dirty; results are diagnostic and not release evidence"
fi

# Write manifest
cat > "$ARTIFACT_DIR/phase4-manifest.json" <<EOF
{
  "phase": "P4",
  "version": "0.5.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "started_at": "$RUN_STARTED_AT",
  "source_commit": "$SOURCE_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
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
