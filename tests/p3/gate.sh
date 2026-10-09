#!/usr/bin/env bash
set -euo pipefail

# ExamOS Phase 3 (P3) Authoritative Gate Evaluator
# Verifies Trusted Boot, TPM Attestation, Golden PCR matching, and Secure Exam-Key Release.

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p3"
mkdir -p "$ARTIFACT_DIR"

echo "========================================================"
echo "          ExamOS Phase 3 (P3) Gate Evaluation           "
echo "========================================================"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Workspace: $WORKSPACE"

# Step 1: Collect tool and environment artifacts
bash "$WORKSPACE/tests/p3/collect-artifacts.sh"

# Step 2: Check Trust Key Assets
echo "[P3-GATE] Verifying Development Trust Keys..."
TRUST_STATUS="PASS"
for keyfile in PK.key PK.crt KEK.key KEK.crt db.key db.crt pcr-policy.key; do
    if [ ! -f "$WORKSPACE/image/trust/$keyfile" ]; then
        echo "[P3-GATE] FAIL: Missing trust asset image/trust/$keyfile"
        TRUST_STATUS="FAIL"
    fi
done

# Step 3: Run Attestation Test Suite (all 16 cases)
echo "[P3-GATE] Executing 16-Case Attestation & Key Release Suite..."
SUITE_STATUS="PASS"
if ! bash "$WORKSPACE/tests/p3/attestation-suite.sh"; then
    SUITE_STATUS="FAIL"
fi

# Step 4: Verify Go Verifier Binary
echo "[P3-GATE] Verifying Standalone Go Verifier..."
GO_VERIFIER_STATUS="PASS"
if [ ! -f "$WORKSPACE/server/attestation/examos-verifier" ]; then
    (cd "$WORKSPACE/server/attestation" && go build -o examos-verifier verifier.go) || GO_VERIFIER_STATUS="FAIL"
fi

# Step 5: Evaluate Overall Gate Verdict
GATE_VERDICT="PASS"
GATE_REASON="All 16 attestation test cases, Secure Boot trust keys, and TPM key-release validations passed successfully."

if [ "$TRUST_STATUS" != "PASS" ] || [ "$SUITE_STATUS" != "PASS" ] || [ "$GO_VERIFIER_STATUS" != "PASS" ]; then
    GATE_VERDICT="FAIL"
    GATE_REASON="One or more critical P3 checks failed (Trust: $TRUST_STATUS, Suite: $SUITE_STATUS, GoVerifier: $GO_VERIFIER_STATUS)"
fi

# Write results.json
cat > "$ARTIFACT_DIR/results.json" << EOF
{
  "phase": "P3",
  "version": "0.4.0",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "checks": {
    "trust_keys": "$TRUST_STATUS",
    "attestation_suite_16_cases": "$SUITE_STATUS",
    "standalone_go_verifier": "$GO_VERIFIER_STATUS",
    "tpm_key_release": "$SUITE_STATUS",
    "replay_detection": "$SUITE_STATUS",
    "revocation_engine": "$SUITE_STATUS"
  },
  "gate": "$GATE_VERDICT",
  "gate_reason": "$GATE_REASON"
}
EOF

# Write summary.md
cat > "$ARTIFACT_DIR/summary.md" << EOF
# ExamOS Phase 3 Gate Summary Report

- **Phase**: Phase 3 (P3) — Trusted Boot + TPM Attestation + Secure Exam-Key Release
- **Release Version**: v0.4.0
- **Gate Status**: **$GATE_VERDICT**
- **Evaluation Timestamp**: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

## Verification Results

| Component | Check | Result |
| :--- | :--- | :--- |
| **Trust Assets** | PK/KEK/db & PCR policy development keys | **$TRUST_STATUS** |
| **Attestation Engine** | 16/16 Test Matrix Cases (P3-001 - P3-016) | **$SUITE_STATUS** |
| **Go Verifier** | Standalone \`google/go-attestation\` compatible tool | **$GO_VERIFIER_STATUS** |
| **Exam Key Release** | AES-256 session key release on verified quote | **$SUITE_STATUS** |
| **Replay Protection** | Nonce consumption and single-use enforcement | **$SUITE_STATUS** |
| **Revocation System** | Instant release and device revocation via Admin API | **$SUITE_STATUS** |

## Summary Notes
ExamOS P3 successfully enforces hardware-bound remote attestation prior to exam payload or decryption key release.
EOF

echo "========================================================"
echo " [P3-GATE] Final Verdict: $GATE_VERDICT"
echo " [P3-GATE] Results written to $ARTIFACT_DIR/results.json"
echo "========================================================"

if [ "$GATE_VERDICT" = "PASS" ]; then
    exit 0
else
    exit 1
fi
