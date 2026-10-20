#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Repository Structure & Secret Check Script
# tests/p0/repository-check.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"

echo "============================================================"
echo "ExamOS P0 — Repository Structure & Secret Integrity Check"
echo "============================================================"

FAILED=0

# 1. Directory Structure Check
for DIR in \
    image image/config image/overlay image/scripts \
    kiosk kiosk/launcher kiosk/policies \
    agent agent/attestation agent/heartbeat agent/device-state agent/environment \
    proctoring proctoring/client proctoring/analysis \
    server server/gateway server/attestation server/exam server/events server/risk \
    server/environment server/proctoring server/review server/admin server/fleet server/releases server/identity \
    tests tests/p0 tests/p1 tests/p2 tests/p3 tests/p4 tests/p5 tests/p6 \
    docs docs/architecture docs/development docs/security docs/testing docs/releases docs/runbooks \
    artifacts; do
    if [ -d "$WORKSPACE/$DIR" ]; then
        echo "[REPO-CHECK] Directory ($DIR): PASS"
    else
        echo "[REPO-CHECK] Directory ($DIR): MISSING"
        FAILED=$((FAILED + 1))
    fi
done

# 2. Secret Material Check (Prevent accidental private keys or secret commits)
echo "[REPO-CHECK] Scanning for prohibited private keys and credentials..."
SECRET_FINDINGS=$(find "$WORKSPACE" -type f \( -name "*.pem" -o -name "*.key" -o -name "*.pfx" -o -name "*.p12" -o -name "id_rsa" -o -name "id_ed25519" \) ! -path "*/.git/*" ! -path "*/build/*" ! -path "*/image/trust/*" 2>/dev/null || true)

if [ -n "$SECRET_FINDINGS" ]; then
    echo "[REPO-CHECK] SECURITY FAIL: Found private key material in repository:"
    echo "$SECRET_FINDINGS"
    FAILED=$((FAILED + 1))
else
    echo "[REPO-CHECK] Secret Material Check: PASS (zero private keys found)"
fi

# 3. .gitignore Check
if [ -f "$WORKSPACE/.gitignore" ]; then
    echo "[REPO-CHECK] .gitignore file: PASS"
else
    echo "[REPO-CHECK] .gitignore file: FAIL"
    FAILED=$((FAILED + 1))
fi

echo "============================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "[REPO-CHECK] REPOSITORY INTEGRITY: PASS"
    exit 0
else
    echo "[REPO-CHECK] REPOSITORY INTEGRITY: FAIL"
    exit 1
fi
