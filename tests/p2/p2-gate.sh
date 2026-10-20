#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 Gate — Aggregates all P2 test results and produces the final
# gate decision, mandatory test counts, and phase2-manifest.json.
#
# Rules:
#   - PASS requires ALL 20 mandatory tests PASS (no NOT_RUN).
#   - Any mandatory test FAIL → overall FAIL.
#   - BLOCKED tests hold the gate at BLOCKED until resolved.
#   - NOT_RUN tests → FAIL (a test that did not run cannot count as passing).
# =============================================================================
set -uo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P2_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase2}"
mkdir -p "$ARTIFACT_DIR"
export EXAMOS_P2_ARTIFACT_DIR="$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/p2-gate.log"
exec > >(tee "$LOG") 2>&1
SUITE_ARTIFACT_DIR=$(mktemp -d "$ARTIFACT_DIR/gate-run.XXXXXX")
trap 'rm -rf "$SUITE_ARTIFACT_DIR"' EXIT

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
GIT_COMMIT=$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo "unknown")
echo "=== [P2-GATE] Phase 2 Gate Evaluation: $(ts) ==="
echo "[P2-GATE] Commit: ${GIT_COMMIT}"

# ---------------------------------------------------------------------------
# Run all test layers and collect exit codes
# ---------------------------------------------------------------------------
declare -A GATE_RESULTS

run_suite() {
    local name="$1" script="$2" evidence="$3"
    echo ""
    echo "--- Running: ${name} ---"
    local rc=0
    ARTIFACT_DIR="$SUITE_ARTIFACT_DIR" EXAMOS_P1_ARTIFACT_DIR="$SUITE_ARTIFACT_DIR/p1" bash "$script" 2>&1 || rc=$?
    if [ ! -s "$evidence" ]; then
        if [ "$rc" -eq 0 ]; then
            GATE_RESULTS["$name"]="NOT_RUN"
        else
            GATE_RESULTS["$name"]="FAIL"
        fi
    elif ! GATE_RESULTS["$name"]=$(python3 - "$evidence" "$rc" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        result = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    print(f"invalid suite evidence: {e}", file=sys.stderr)
    sys.exit(1)

try:
    passed = int(result["pass"])
    failed = int(result["fail"])
    blocked = int(result["blocked"])
    not_run = int(result.get("not_run", 0))
    declared = result["overall"]
except (KeyError, TypeError, ValueError) as e:
    print(f"missing/invalid suite counts: {e}", file=sys.stderr)
    sys.exit(1)

if min(passed, failed, blocked, not_run) < 0:
    print("negative suite count", file=sys.stderr)
    sys.exit(1)

expected = "FAIL" if failed else "BLOCKED" if blocked else "NOT_RUN" if not_run else "PASS" if passed else "NOT_RUN"
if declared != expected:
    print(f"inconsistent suite status: declared {declared}, counts require {expected}", file=sys.stderr)
    sys.exit(1)
rc = int(sys.argv[2])
if expected == "FAIL" and rc == 0:
    print(f"suite exit code {rc} is inconsistent with {expected} evidence", file=sys.stderr)
    sys.exit(1)
if expected == "PASS" and rc != 0:
    print(f"suite exit code {rc} is inconsistent with {expected} evidence", file=sys.stderr)
    sys.exit(1)
if expected == "NOT_RUN" and rc == 0:
    print(f"suite exit code {rc} is inconsistent with {expected} evidence", file=sys.stderr)
    sys.exit(1)
if expected == "BLOCKED" and rc not in (0, 2):
    print(f"suite exit code {rc} is inconsistent with {expected} evidence", file=sys.stderr)
    sys.exit(1)
print(expected)
PY
    ); then
        GATE_RESULTS["$name"]="FAIL"
    fi
    echo "--- ${name}: ${GATE_RESULTS[$name]} ---"
}

run_suite "static-audit" "$WORKSPACE/tests/p2/p2-static-audit.sh" \
    "$SUITE_ARTIFACT_DIR/p2-static-summary.json"
run_suite "p1-regression" "$WORKSPACE/tests/p2/p2-p1-regression.sh" \
    "$SUITE_ARTIFACT_DIR/p1-regression-results.json"
run_suite "chromium-policy" "$WORKSPACE/tests/p2/p2-chromium-policy-tests.sh" \
    "$SUITE_ARTIFACT_DIR/chromium-policy-validation.json"
run_suite "usb-policy" "$WORKSPACE/tests/p2/p2-usb-tests.sh" \
    "$SUITE_ARTIFACT_DIR/usb-policy-tests.json"
run_suite "verity-tests" "$WORKSPACE/tests/p2/p2-verity-tests.sh" \
    "$SUITE_ARTIFACT_DIR/dm-verity-test-results.json"

# These runtime suites are not executed by this host-side gate. Never consume
# files from earlier runs: their timestamps and commit may not match this build.
GATE_RESULTS["guest-integration"]="BLOCKED"
GATE_RESULTS["network-tests"]="BLOCKED"
echo "--- guest-integration: BLOCKED (no current booted-guest execution in this gate) ---"
echo "--- network-tests: BLOCKED (no current guest plus independent port-scan execution) ---"

# ---------------------------------------------------------------------------
# Mandatory P2 acceptance test mapping
# Each mandatory test maps to one or more test suite results
# ---------------------------------------------------------------------------
declare -A MANDATORY_TESTS=(
    ["P2-01"]="${GATE_RESULTS[network-tests]:-NOT_RUN}"
    ["P2-02"]="${GATE_RESULTS[network-tests]:-NOT_RUN}"
    ["P2-03"]="${GATE_RESULTS[network-tests]:-NOT_RUN}"
    ["P2-04"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-05"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-06"]="${GATE_RESULTS[verity-tests]:-NOT_RUN}"
    ["P2-07"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-08"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-09"]="${GATE_RESULTS[network-tests]:-NOT_RUN}"
    ["P2-10"]="${GATE_RESULTS[static-audit]:-NOT_RUN}"
    ["P2-11"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-12"]="${GATE_RESULTS[usb-policy]:-NOT_RUN}"
    ["P2-13"]="${GATE_RESULTS[network-tests]:-NOT_RUN}"
    ["P2-14"]="${GATE_RESULTS[chromium-policy]:-NOT_RUN}"
    ["P2-15"]="${GATE_RESULTS[chromium-policy]:-NOT_RUN}"
    ["P2-16"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-17"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-18"]="${GATE_RESULTS[p1-regression]:-NOT_RUN}"
    ["P2-19"]="${GATE_RESULTS[guest-integration]:-NOT_RUN}"
    ["P2-20"]="${GATE_RESULTS[static-audit]:-NOT_RUN}"
)

# ---------------------------------------------------------------------------
# Count results
# ---------------------------------------------------------------------------
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_BLOCKED=0; TOTAL_NOT_RUN=0
for id in "${!MANDATORY_TESTS[@]}"; do
    status="${MANDATORY_TESTS[$id]}"
    case "$status" in
        PASS)    TOTAL_PASS=$((TOTAL_PASS+1)) ;;
        FAIL)    TOTAL_FAIL=$((TOTAL_FAIL+1)) ;;
        BLOCKED) TOTAL_BLOCKED=$((TOTAL_BLOCKED+1)) ;;
        NOT_RUN) TOTAL_NOT_RUN=$((TOTAL_NOT_RUN+1)) ;;
        *)       TOTAL_FAIL=$((TOTAL_FAIL+1)) ;;
    esac
done

# Gate decision
# Rules (per P2 spec §gate):
#   - PASS requires all 20 mandatory tests PASS.
#   - Any FAIL         → overall FAIL (hard stop).
#   - Any NOT_RUN      → overall FAIL (a test that did not execute cannot count as passing).
#   - Any BLOCKED      → overall BLOCKED (cannot confirm gate; must resolve before release).
#   - BLOCKED takes precedence over PASS but NOT over FAIL.
#
# NOT_RUN is treated as FAIL rather than BLOCKED because it means the test
# infrastructure itself did not attempt the check — that is a CI pipeline
# deficiency, not a legitimate blocker condition.
GATE="PASS"
[ "$TOTAL_FAIL" -gt 0 ]    && GATE="FAIL"
[ "$TOTAL_NOT_RUN" -gt 0 ] && GATE="FAIL"
[ "$TOTAL_BLOCKED" -gt 0 ] && [ "$GATE" = "PASS" ] && GATE="BLOCKED"

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
echo ""
echo "=== [P2-GATE] Mandatory Test Results ==="
printf "%-8s %-12s\n" "Test ID" "Status"
printf "%-8s %-12s\n" "-------" "------"
for id in $(echo "${!MANDATORY_TESTS[@]}" | tr ' ' '\n' | sort); do
    printf "%-8s %-12s\n" "$id" "${MANDATORY_TESTS[$id]}"
done
echo ""
echo "Passed:    ${TOTAL_PASS} / 20"
echo "Failed:    ${TOTAL_FAIL} / 20"
echo "Blocked:   ${TOTAL_BLOCKED} / 20"
echo "Not Run:   ${TOTAL_NOT_RUN} / 20"
echo ""
echo "=== GATE DECISION: ${GATE} ==="

# ---------------------------------------------------------------------------
# Update phase2-manifest.json with final test counts
# ---------------------------------------------------------------------------
MANIFEST="$ARTIFACT_DIR/phase2-manifest.json"
IMAGE_DIGEST="NOT_AVAILABLE"
VERITY_ROOT_HASH="NOT_AVAILABLE"
KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")
CHROMIUM_VERSION=$(chromium --version 2>/dev/null | head -1 || echo "NOT_AVAILABLE")
BUILD_TOOL_VERSION=$(mkosi --version 2>/dev/null | head -1 || echo "NOT_AVAILABLE")

# Find the built image
IMAGE_ARTIFACT="NOT_BUILT"
for cand in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$cand" ] && [ -s "$cand" ]; then
        IMAGE_ARTIFACT="$cand"
        IMAGE_DIGEST="sha256:$(sha256sum "$cand" | awk '{print $1}')"
        break
    fi
done

cat > "$MANIFEST" <<MANIFESTEOF
{
  "phase": "P2",
  "status": "${GATE}",
  "gitCommit": "${GIT_COMMIT}",
  "buildProfile": "release-test",
  "buildTool": "${BUILD_TOOL_VERSION}",
  "imageArtifact": "${IMAGE_ARTIFACT}",
  "imageDigest": "${IMAGE_DIGEST}",
  "verityRootHash": "${VERITY_ROOT_HASH}",
  "kernelVersion": "${KERNEL_VERSION}",
  "chromiumVersion": "${CHROMIUM_VERSION}",
  "firewallBackend": "nftables",
  "configVersion": "p2.1",
  "testExecutionTimestamp": "$(ts)",
  "buildNote": "UNSIGNED_TEST_BUILD — Secure Boot chain and release signing are not applied; this is not production release evidence",
  "mandatoryTests": {
    "passed": ${TOTAL_PASS},
    "failed": ${TOTAL_FAIL},
    "blocked": ${TOTAL_BLOCKED},
    "notRun": ${TOTAL_NOT_RUN}
  },
  "mandatoryTestDetails": {
MANIFESTEOF

# Append per-test results
FIRST=1
for id in $(echo "${!MANDATORY_TESTS[@]}" | tr ' ' '\n' | sort); do
    [ "$FIRST" -eq 0 ] && echo ',' >> "$MANIFEST"
    printf '    "%s": "%s"' "$id" "${MANDATORY_TESTS[$id]}" >> "$MANIFEST"
    FIRST=0
done
cat >> "$MANIFEST" <<'MANIFESTEND'

  },
  "artifacts": []
}
MANIFESTEND

echo ""
echo "[P2-GATE] Manifest written: ${MANIFEST}"

# Exit code drives CI
# PASS   → 0   (all 20 mandatory tests passed)
# FAIL   → 1   (one or more tests failed or NOT_RUN)
# BLOCKED → 2  (all non-blocked tests passed but some require a running guest)
if [ "$GATE" = "PASS" ];    then exit 0; fi
if [ "$GATE" = "BLOCKED" ]; then exit 2; fi
exit 1
