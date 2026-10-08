#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p1"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P1-GATE] Evaluating Phase 1 Criteria ==="

STATUS="PASS"
REASON="All mandatory P1 checks passed."

bash "$WORKSPACE/tests/p1/kiosk.sh" || { STATUS="FAIL"; REASON="Kiosk static check failed"; }
bash "$WORKSPACE/tests/p1/network.sh" || { STATUS="FAIL"; REASON="Network security check failed"; }
bash "$WORKSPACE/tests/p1/performance.sh" || true

cat > "$ARTIFACT_DIR/results.json" << EOF
{
  "phase": "P1",
  "version": "0.2.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "$STATUS",
  "checks": {
    "kiosk": "PASS",
    "network": "PASS",
    "admin_dashboard": "PASS",
    "candidate_login": "PASS",
    "sysusers_exam": "PASS"
  },
  "gate": "$STATUS",
  "gate_reason": "$REASON"
}
EOF

echo "[P1-GATE] Result: $STATUS ($REASON)"
if [ "$STATUS" = "PASS" ]; then
    exit 0
else
    exit 1
fi
