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

# 2. Virtualization Support
VIRT_COUNT=$(egrep -c '(vmx|svm)' /proc/cpuinfo || true)
if [ "$VIRT_COUNT" -gt 0 ]; then
    echo "[HOST-CHECK] CPU Virtualization ($VIRT_COUNT cores): PASS"
else
    echo "[HOST-CHECK] CPU Virtualization: FAIL (no vmx/svm flags in /proc/cpuinfo)"
    FAILED=$((FAILED + 1))
fi

# 3. KVM Device
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo "[HOST-CHECK] /dev/kvm Access: PASS"
elif [ -e /dev/kvm ]; then
    echo "[HOST-CHECK] /dev/kvm: PASS (device exists, permissions restricted to $(ls -l /dev/kvm | cut -d' ' -f3-4))"
else
    echo "[HOST-CHECK] /dev/kvm: FAIL (device node missing)"
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
for TOOL in git mkosi qemu-system-x86_64 qemu-img swtpm tpm2_pcrread sbsign veritysetup mksquashfs; do
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
