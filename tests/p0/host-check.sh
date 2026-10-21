#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Host Check Script
# tests/p0/host-check.sh
# =============================================================================
set -euo pipefail

echo "============================================================"
echo "ExamOS P0 — Linux Build Host Verification"
echo "============================================================"

FAILED=0

# 1. Architecture
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    echo "[HOST-CHECK] Architecture ($ARCH): PASS"
else
    echo "[HOST-CHECK] Architecture ($ARCH): FAIL (expected x86_64)"
    FAILED=$((FAILED + 1))
fi

# 2. Virtualization acceleration
# P0 can run under QEMU TCG when nested virtualization/KVM is unavailable.
# Probe the accelerator with QEMU itself; CPU flags and /dev/kvm alone do not
# prove that KVM initialization will work in a container or WSL guest.
source "$(cd "$(dirname "$0")/../.." && pwd)/scripts/examos-lib.sh"
if examos_kvm_available; then
    echo "[HOST-CHECK] QEMU KVM acceleration: PASS"
else
    echo "[HOST-CHECK] QEMU KVM acceleration: UNAVAILABLE (using QEMU TCG fallback)"
fi
if examos_tcg_available; then
    echo "[HOST-CHECK] QEMU TCG fallback: AVAILABLE"
else
    echo "[HOST-CHECK] QEMU TCG fallback: FAIL (QEMU cannot initialize TCG)"
    FAILED=$((FAILED + 1))
fi

# 4. Storage Check (Min 20GB available for build)
AVAIL_GB=$(df -BG / | tail -1 | awk '{print $4}' | tr -d 'G')
if [ "$AVAIL_GB" -ge 20 ]; then
    echo "[HOST-CHECK] Disk Storage (${AVAIL_GB}GB available): PASS"
else
    echo "[HOST-CHECK] Disk Storage (${AVAIL_GB}GB available): FAIL (min 20GB required)"
    FAILED=$((FAILED + 1))
fi

# 5. Core Tools
for TOOL in git mkosi gcc g++ qemu-system-x86_64 qemu-img swtpm tpm2_pcrread sbsign veritysetup mksquashfs; do
    if command -v "$TOOL" >/dev/null 2>&1; then
        echo "[HOST-CHECK] Tool ($TOOL): PASS"
    else
        echo "[HOST-CHECK] Tool ($TOOL): FAIL (not found on PATH)"
        FAILED=$((FAILED + 1))
    fi
done

# 6. OVMF Firmware
if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] || [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    echo "[HOST-CHECK] OVMF Firmware: PASS"
else
    echo "[HOST-CHECK] OVMF Firmware: FAIL (OVMF_CODE.fd not found in /usr/share/OVMF)"
    FAILED=$((FAILED + 1))
fi

echo "============================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "[HOST-CHECK] OVERALL STATUS: PASS"
    exit 0
else
    echo "[HOST-CHECK] OVERALL STATUS: FAIL ($FAILED checks failed)"
    exit 1
fi
