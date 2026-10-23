#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
if [ -z "${EXAMOS_P1_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$WORKSPACE/artifacts/p1/runs"
    EXAMOS_P1_ARTIFACT_DIR="$(mktemp -d "$WORKSPACE/artifacts/p1/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
ARTIFACT_DIR="$EXAMOS_P1_ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
export EXAMOS_P1_ARTIFACT_DIR="$ARTIFACT_DIR"

echo "=== [P1-GATE] Evaluating Phase 1 Criteria ==="

declare -A RESULTS
STATUS="PASS"
REASON="All P1 checks passed."
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo unknown)"
SOURCE_TREE_STATE="CLEAN"
if [ -n "$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' ':(exclude)cache/**' 2>/dev/null || true)" ]; then
    SOURCE_TREE_STATE="DIRTY"
    STATUS="BLOCKED"
    REASON="source tree is dirty; results are diagnostic and not release evidence"
fi

run_check() {
    local name="$1" script="$2" rc=0 result="PASS"
    bash "$script" || rc=$?
    if [ "$rc" -eq 2 ]; then
        result="BLOCKED"
    elif [ "$rc" -ne 0 ]; then
        result="FAIL"
    fi
    RESULTS["$name"]="$result"
    if [ "$result" = "FAIL" ]; then
        STATUS="FAIL"
        REASON="$name check failed"
    elif [ "$result" = "BLOCKED" ] && [ "$STATUS" = "PASS" ]; then
        STATUS="BLOCKED"
        REASON="$name check is blocked by an unmet prerequisite"
    fi
}

run_check "source_validation" "$WORKSPACE/tests/p1/validate-source.sh"
run_check "kiosk" "$WORKSPACE/tests/p1/kiosk.sh"
run_check "network" "$WORKSPACE/tests/p1/network.sh"
run_check "boot" "$WORKSPACE/tests/p1/boot.sh"
run_check "performance" "$WORKSPACE/tests/p1/performance.sh"
# PG-10: Chromium policy generator correctness is a mandatory P1 gate check
run_check "chromium_policy" "$WORKSPACE/tests/p1/chromium-policy-generator-test.sh"

python3 - "$ARTIFACT_DIR/results.json" "$STATUS" "$REASON" "$SOURCE_COMMIT" "$SOURCE_TREE_STATE" "${RESULTS[source_validation]}" "${RESULTS[kiosk]}" "${RESULTS[network]}" "${RESULTS[boot]}" "${RESULTS[performance]}" "${RESULTS[chromium_policy]}" <<'PY'
import datetime
import json
import pathlib
import sys

out, status, reason, commit, tree_state, source, kiosk, network, boot, performance, chromium_policy = sys.argv[1:]
checks = {
    "source_validation": source,
    "kiosk": kiosk,
    "network": network,
    "boot": boot,
    "performance": performance,
    "chromium_policy": chromium_policy,
}
report = {
    "phase": "P1",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "source_tree_state_at_start": tree_state,
    "status": status,
    "checks": checks,
    "gate": status,
    "gate_reason": reason,
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
PY

echo "[P1-GATE] Result: $STATUS ($REASON)"
case "$STATUS" in
    PASS) exit 0 ;;
    BLOCKED) exit 2 ;;
    *) exit 1 ;;
esac
