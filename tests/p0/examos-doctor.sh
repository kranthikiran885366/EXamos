#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Environment Doctor Script
# tests/p0/examos-doctor.sh
# =============================================================================
set -euo pipefail

echo "========================================"
echo "          EXAMOS P0 DOCTOR"
echo "========================================"

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
source "$WORKSPACE/scripts/examos-lib.sh"

print_item() {
    local name="$1"
    local status="$2"
    printf "%-25s %s\n" "$name" "$status"
}

# 1. Host OS
if [ -f /etc/os-release ]; then
    OS_NAME=$(grep -oP '(?<=PRETTY_NAME=")[^"]*' /etc/os-release || echo "Linux")
    print_item "Host OS ($OS_NAME)" "PASS"
else
    print_item "Host OS" "UNKNOWN"
fi

# 2. Architecture
if [ "$(uname -m)" = "x86_64" ]; then
    print_item "Architecture (x86_64)" "PASS"
else
    print_item "Architecture" "FAIL"
fi

# 3. QEMU acceleration
# KVM is optional because the P0 boot checks select TCG when KVM cannot be
# initialized (common in nested virtualization and container environments).
if examos_kvm_available; then
    print_item "QEMU KVM acceleration" "PASS"
else
    print_item "QEMU KVM acceleration" "UNAVAILABLE (TCG fallback)"
fi
if examos_tcg_available; then
    print_item "QEMU TCG fallback" "AVAILABLE"
else
    print_item "QEMU TCG fallback" "FAIL (cannot initialize)"
fi

# 5. UEFI Capability (OVMF)
if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] || [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    print_item "OVMF / UEFI" "PASS"
else
    print_item "OVMF / UEFI" "FAIL"
fi

# 6. QEMU
if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    QVER=$(qemu-system-x86_64 --version | head -1 | awk '{print $4}')
    print_item "QEMU ($QVER)" "PASS"
else
    print_item "QEMU" "FAIL"
fi

# 7. swtpm
if command -v swtpm >/dev/null 2>&1; then
    SWTPM_VER=$(swtpm --version 2>&1 | head -1 | awk '{print $4}' | tr -d ',')
    print_item "swtpm ($SWTPM_VER)" "PASS"
else
    print_item "swtpm" "FAIL"
fi

# 8. TPM Tools
if command -v tpm2_pcrread >/dev/null 2>&1; then
    print_item "TPM tools (tpm2-tools)" "PASS"
else
    print_item "TPM tools" "FAIL"
fi

# 9. Secure Boot Tools
if command -v sbsign >/dev/null 2>&1 && command -v sbverify >/dev/null 2>&1; then
    print_item "Secure Boot (sbsign)" "PASS"
else
    print_item "Secure Boot" "FAIL"
fi

# 10. dm-verity
if command -v veritysetup >/dev/null 2>&1; then
    print_item "dm-verity (cryptsetup)" "PASS"
else
    print_item "dm-verity" "FAIL"
fi

# 11. SquashFS
if command -v mksquashfs >/dev/null 2>&1; then
    print_item "SquashFS" "PASS"
else
    print_item "SquashFS" "FAIL"
fi

# 12. mkosi
if command -v mkosi >/dev/null 2>&1; then
    MK_VER=$(mkosi --version | awk '{print $2}')
    print_item "mkosi ($MK_VER)" "PASS"
else
    print_item "mkosi" "FAIL"
fi

# 13. Disk Capacity
FREE_GB=$(df -BG / | tail -1 | awk '{print $4}' | tr -d 'G')
if [ "$FREE_GB" -ge 20 ]; then
    print_item "Disk (${FREE_GB}GB free)" "PASS"
else
    print_item "Disk (${FREE_GB}GB free)" "FAIL"
fi

# 14. Repository Structure
if [ -d "image" ] && [ -d "tests" ] && [ -d "docs" ] && [ -d "artifacts" ]; then
    print_item "Repository Layout" "PASS"
else
    print_item "Repository Layout" "FAIL"
fi

echo "========================================"
echo "EXAMOS P0 DOCTOR: COMPLETED"
echo "========================================"
