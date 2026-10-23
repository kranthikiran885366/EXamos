#!/usr/bin/env bash
set -euo pipefail

# ExamOS Phase 3 (P3) Artifact Collection Script

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="$WORKSPACE/artifacts/p3"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P3-COLLECT] Collecting P3 Verification Artifacts ==="

# 1. Tool Versions
cat > "$ARTIFACT_DIR/tool-versions.txt" << EOF
ExamOS Phase 3 Toolchain and Dependencies
=========================================
OS Kernel: $(uname -srm)
GCC Version: $(gcc --version | head -n 1)
G++ Version: $(g++ --version | head -n 1)
Go Version: $(go version 2>/dev/null || echo "NOT_INSTALLED")
OpenSSL Version: $(openssl version)
QEMU Version: $(qemu-system-x86_64 --version 2>/dev/null | head -n 1 || echo "NOT_INSTALLED")
SWTPM Version: $(swtpm --version 2>/dev/null | head -n 1 || echo "NOT_INSTALLED")
MKOSI Version: $(mkosi --version 2>/dev/null | head -n 1 || echo "NOT_INSTALLED")
Git Commit: $(git log -1 --pretty=format:'%H %an %ai %s' 2>/dev/null || echo "UNKNOWN")
Collection Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

# 2. Golden PCR Reference Values
#
# No signed release with measured boot PCR values has been produced, so no
# PCR values are recorded. Placeholder hex strings are never written here:
# a placeholder that resembles a measurement can be mistaken for evidence.
cat > "$ARTIFACT_DIR/golden-pcr.json" << 'EOF'
{
  "_schema": "examos-golden-pcr-v2",
  "status": "NOT_PROVISIONED",
  "measured": false,
  "reason": "No signed release with measured boot PCR values has been produced. Placeholder values are not recorded, because a placeholder that resembles a measurement can be mistaken for evidence.",
  "release_id": null,
  "build_timestamp": null,
  "pcr_bank": "SHA256",
  "pcr_spec": {},
  "composite_digest": null
}
EOF

# 3. Attestation Failures Aggregated Schema
cat > "$ARTIFACT_DIR/attestation-failures.json" << 'EOF'
{
  "phase": "P3",
  "evaluated_failure_modes": [
    {
      "code": "P3_PCR_MISMATCH",
      "cause": "PCR 0, 4, 7, or 11 diverged from enrolled release values",
      "security_impact": "Firmware tampering, unauthorized UKI boot, or disabled Secure Boot detected",
      "mitigation": "Quarantine node, abort session, reject exam key release"
    },
    {
      "code": "P3_NONCE_REPLAY",
      "cause": "Quote submitted with expired or previously verified nonce",
      "security_impact": "Replay attack detected; prevents pre-recorded legitimate TPM evidence reuse",
      "mitigation": "Invalidate session, alert SIEM"
    },
    {
      "code": "P3_UNKNOWN_DEVICE",
      "cause": "Device ID or EK certificate/fingerprint not in enrolled hardware inventory",
      "security_impact": "Unapproved physical hardware or software TPM emulator attempting admission",
      "mitigation": "Drop session, reject challenge"
    },
    {
      "code": "P3_SESSION_BINDING_FAIL",
      "cause": "Session token presented with mismatched device ID",
      "security_impact": "Session hijacking or relay attack between candidate machines",
      "mitigation": "Terminate session immediately"
    },
    {
      "code": "P3_REVOKED_RELEASE",
      "cause": "ExamOS release ID flagged as vulnerable or obsolete",
      "security_impact": "Prevents boot of retired or compromised appliance versions",
      "mitigation": "Enforce USB reflash of latest authenticated release"
    },
    {
      "code": "P3_INVALID_SIGNATURE",
      "cause": "TPM Quote signature could not be mathematically validated against enrolled AK",
      "security_impact": "Forged evidence or corrupted TPM quote transmission",
      "mitigation": "Reject session, mark hardware untrusted"
    }
  ]
}
EOF

echo "[P3-COLLECT] Artifact collection complete."
