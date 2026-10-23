#!/usr/bin/env bash
set -euo pipefail

# ExamOS Phase 3 (P3) Authoritative Gate Evaluator
# Verifies Trusted Boot, TPM Attestation, Golden PCR matching, and Secure Exam-Key Release.

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P3_ARTIFACT_DIR:-$WORKSPACE/artifacts/p3}"
mkdir -p "$ARTIFACT_DIR"
if [ -z "${EXAMOS_P3_ARTIFACT_DIR:-}" ]; then
    mkdir -p "$ARTIFACT_DIR/runs"
    ARTIFACT_DIR="$(mktemp -d "$ARTIFACT_DIR/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi
export EXAMOS_P3_ARTIFACT_DIR="$ARTIFACT_DIR"
SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
SOURCE_TREE_STATE="CLEAN"
if [ -n "$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
    ':(exclude)build/**' ':(exclude)cache/**')" ]; then
    SOURCE_TREE_STATE="DIRTY"
fi

echo "========================================================"
echo "          ExamOS Phase 3 (P3) Gate Evaluation           "
echo "========================================================"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Workspace: $WORKSPACE"

# The swtpm check below exercises a genuine TPM2 quote. It remains development
# evidence and does not qualify physical TPM or firmware measurements.

# Evaluate the real organization trust inputs. Missing external keys/certificates
# remain BLOCKED; malformed or invalid signatures are FAIL.
echo "[P3-GATE] Verifying production trust provisioning inputs..."
TRUST_STATUS="FAIL"
if EXAMOS_PRODUCTION_ARTIFACT_DIR="$ARTIFACT_DIR" \
    bash "$WORKSPACE/tests/production/trust-provisioning-gate.sh"; then
    TRUST_STATUS="PASS"
else
    TRUST_RC=$?
    if [ "$TRUST_RC" -eq 2 ]; then TRUST_STATUS="BLOCKED"; fi
fi

# The legacy end-to-end suite still uses synthetic evidence and is excluded.
echo "[P3-GATE] TPM attestation/key-release suite: BLOCKED (synthetic evidence)"
SUITE_STATUS="BLOCKED"

echo "[P3-GATE] Verifying a genuine TPM2 quote with swtpm..."
QUOTE_STATUS="BLOCKED"
if bash "$WORKSPACE/tests/p3/swtpm-quote-smoke.sh"; then
    QUOTE_STATUS="PASS"
else
    QUOTE_RC=$?
    if [ "$QUOTE_RC" -eq 2 ]; then
        QUOTE_STATUS="BLOCKED"
    else
        QUOTE_STATUS="FAIL"
    fi
fi

# Step 4: Verify Go verifier behavior. A successful build is not evidence that
# attestation is backed by a production database and key lifecycle.
echo "[P3-GATE] Checking standalone Go verifier fail-closed behavior..."
GO_VERIFIER_STATUS="FAIL"
GO_VERIFIER_REASON="Go verifier tests did not pass"
if ! command -v go >/dev/null 2>&1; then
    GO_VERIFIER_STATUS="BLOCKED"
    GO_VERIFIER_REASON="Go toolchain unavailable; verifier behavior was not checked"
elif (cd "$WORKSPACE/server/attestation" && go test verifier.go verifier_test.go); then
    GO_VERIFIER_STATUS="BLOCKED"
    GO_VERIFIER_REASON="Legacy Go path remains fail-closed; production database and key lifecycle qualification is pending"
fi

# Step 5: Evaluate Overall Gate Verdict
GATE_VERDICT="PASS"
GATE_REASON="All required P3 checks passed."

if [ "$TRUST_STATUS" = "FAIL" ] || [ "$SUITE_STATUS" = "FAIL" ] || [ "$QUOTE_STATUS" = "FAIL" ] || [ "$GO_VERIFIER_STATUS" = "FAIL" ]; then
    GATE_VERDICT="FAIL"
    GATE_REASON="One or more critical P3 checks failed (Trust: $TRUST_STATUS, Suite: $SUITE_STATUS, Quote: $QUOTE_STATUS, GoVerifier: $GO_VERIFIER_STATUS)"
elif [ "$TRUST_STATUS" = "BLOCKED" ] || [ "$SUITE_STATUS" = "BLOCKED" ] || \
     [ "$QUOTE_STATUS" = "BLOCKED" ] || [ "$GO_VERIFIER_STATUS" = "BLOCKED" ]; then
    GATE_VERDICT="BLOCKED"
    GATE_REASON="Production trust provisioning, PostgreSQL integration, physical TPM qualification, and key-release validation remain blocked. (Trust: $TRUST_STATUS, Suite: $SUITE_STATUS, Quote: $QUOTE_STATUS, GoVerifier: $GO_VERIFIER_STATUS)"
fi
if [ "$SOURCE_TREE_STATE" = "DIRTY" ] && [ "$GATE_VERDICT" = "PASS" ]; then
    GATE_VERDICT="BLOCKED"
    GATE_REASON="source tree is dirty; results are diagnostic and not release evidence"
fi

# Write results.json
cat > "$ARTIFACT_DIR/results.json" << EOF
{
  "phase": "P3",
  "version": "0.4.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_commit": "$SOURCE_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
  "checks": {
    "trust_keys": "$TRUST_STATUS",
    "attestation_suite_16_cases": "$SUITE_STATUS",
    "standalone_go_verifier": "$GO_VERIFIER_STATUS",
    "tpm_quote_verifier": "$QUOTE_STATUS",
    "tpm_key_release": "$SUITE_STATUS",
    "replay_detection": "$SUITE_STATUS",
    "revocation_engine": "$SUITE_STATUS"
  },
  "gate": "$GATE_VERDICT",
  "gate_reason": "$GATE_REASON"
}
EOF

# Write a plain-text summary (the P3 verifier is not production ready).
cat > "$ARTIFACT_DIR/summary.txt" << EOF
# ExamOS Phase 3 Gate Summary Report

- **Phase**: Phase 3 (P3) — Trusted Boot + TPM Attestation + Secure Exam-Key Release
- **Release Version**: v0.4.0
- **Gate Status**: **$GATE_VERDICT**
- **Evaluation Timestamp**: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

## Verification Results

| Component | Check | Result |
| :--- | :--- | :--- |
| **Trust Assets** | Organization-approved release and device trust roots | **$TRUST_STATUS** |
| **Attestation Engine** | Hardware quote and key-release suite | **$SUITE_STATUS** |
| **Go Verifier** | Fail-closed until authenticated TPM and release trust are configured | **$GO_VERIFIER_STATUS** |
| **Exam Key Release** | Hardware verified quote required | **$SUITE_STATUS** |
| **Replay Protection** | Hardware verified quote required | **$SUITE_STATUS** |
| **Revocation System** | Production validation required | **$SUITE_STATUS** |

## Summary Notes
The P3 gate does not claim production attestation while the standalone verifier is disabled or required trust assets are unavailable. A PASS requires all listed checks to pass.
EOF

echo "========================================================"
echo " [P3-GATE] Final Verdict: $GATE_VERDICT"
echo " [P3-GATE] Results written to $ARTIFACT_DIR/results.json"
echo "========================================================"

case "$GATE_VERDICT" in
    PASS) exit 0 ;;
    BLOCKED) exit 2 ;;
    *) exit 1 ;;
esac
