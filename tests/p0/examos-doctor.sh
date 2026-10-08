#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

printf '%s\n' "========================================"
printf '%s\n' "             EXAMOS DOCTOR              "
printf '%s\n' "========================================"

total=0
passed=0
failed=0

check() {
  label="$1"
  shift
  total=$((total + 1))
  if "$@" >/dev/null 2>&1; then
    printf '%-28s PASS\n' "$label"
    passed=$((passed + 1))
  else
    printf '%-28s FAIL\n' "$label"
    failed=$((failed + 1))
  fi
}

check "Host OS (Linux)" bash -lc 'test "$(uname -s 2>/dev/null)" = "Linux"'
check "Architecture (x86_64)" bash -lc 'test "$(uname -m 2>/dev/null)" = "x86_64"'
check "CPU Virtualization" bash -lc 'test -e /proc/cpuinfo && grep -E -q "(vmx|svm)" /proc/cpuinfo'
check "KVM Device (/dev/kvm)" bash -lc 'test -e /dev/kvm && test -r /dev/kvm && test -w /dev/kvm'
check "UEFI / OVMF Firmware" bash -lc 'test -d /sys/firmware/efi || test -f /usr/share/OVMF/OVMF_CODE_4M.fd || test -f /usr/share/OVMF/OVMF_CODE.fd || test -f /usr/share/edk2/ovmf/OVMF_CODE_4M.fd || test -f /usr/share/qemu/OVMF.fd'
check "QEMU Emulator" bash -lc 'command -v qemu-system-x86_64'
check "OVMF Firmware" bash -lc 'test -f /usr/share/OVMF/OVMF_CODE_4M.fd || test -f /usr/share/OVMF/OVMF_CODE.fd || test -f /usr/share/edk2/ovmf/OVMF_CODE_4M.fd || test -f /usr/share/edk2-ovmf/x64/OVMF_CODE.fd || test -f /usr/share/qemu/OVMF.fd'
check "Virtual TPM (swtpm)" bash -lc 'command -v swtpm && command -v swtpm_setup'
check "TPM 2.0 Tools" bash -lc 'command -v tpm2_pcrread && command -v tpm2_getrandom && command -v tpm2_startup'
check "Secure Boot Tooling" bash -lc 'command -v sbsign'
check "dm-verity Tooling" bash -lc 'command -v veritysetup'
check "SquashFS Tooling" bash -lc 'command -v mksquashfs'
check "mkosi Builder" bash -lc 'command -v mkosi'
check "Git" bash -lc 'command -v git'
check "Disk Storage (>=50 GB)" bash -lc 'avail_kb=$(df -k "$HOME" 2>/dev/null | tail -n 1 | awk "{print \$4}"); test "$((avail_kb / 1024 / 1024))" -ge 50'
check "Repository Structure" bash -lc 'test -f "'"$ROOT"'/README.md" && test -f "'"$ROOT"'/image/mkosi.conf" && test -d "'"$ROOT"'/tests/p0"'

printf '%s\n' "----------------------------------------"
printf 'Summary: %d total, %d passed, %d failed\n' "$total" "$passed" "$failed"
printf '%s\n' "========================================"

if [[ "$failed" -eq 0 ]]; then
  printf '%s\n' "RESULT: READY FOR P0"
  exit 0
else
  printf '%s\n' "RESULT: BLOCKED (Prerequisites missing)"
  exit 1
fi
