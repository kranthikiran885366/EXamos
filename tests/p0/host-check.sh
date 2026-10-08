#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $1"
  exit 1
}

uname_out="$(uname -s 2>/dev/null || echo unknown)"
arch_out="$(uname -m 2>/dev/null || echo unknown)"

echo "[P0] Checking host OS..."
[[ "$uname_out" == "Linux" ]] || fail "Linux host required; found: ${uname_out}"

echo "[P0] Checking architecture..."
[[ "$arch_out" == "x86_64" ]] || fail "x86-64 host required; found: ${arch_out}"

echo "[P0] Checking virtualization support..."
if [[ -e /proc/cpuinfo ]]; then
  if egrep -q '(vmx|svm)' /proc/cpuinfo; then
    echo "[P0] Virtualization support detected"
  else
    fail "Hardware virtualization extensions not detected"
  fi
else
  fail "/proc/cpuinfo not available"
fi

echo "[P0] Checking /dev/kvm..."
[[ -e /dev/kvm ]] || fail "/dev/kvm not available"

echo "[P0] Checking QEMU..."
command -v qemu-system-x86_64 >/dev/null || fail "QEMU missing"

echo "[P0] Checking OVMF..."
if [[ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]] || [[ -f /usr/share/edk2/ovmf/OVMF_CODE_4M.fd ]]; then
  echo "[P0] OVMF firmware found"
else
  fail "OVMF firmware not found"
fi

echo "[P0] Checking swtpm..."
command -v swtpm >/dev/null || fail "swtpm missing"

echo "[P0] Checking mkosi..."
command -v mkosi >/dev/null || fail "mkosi missing"

echo "[P0] Checking TPM tools..."
command -v tpm2_pcrread >/dev/null || fail "tpm2-tools missing"

echo "[P0] Checking disk capacity..."
if command -v df >/dev/null; then
  df -h "$HOME" 2>/dev/null | tail -n +2 | awk '{print $4}' | head -n 1 | grep -Eq '[1-9][0-9]+G|[5-9][0-9]+G|[0-9]+T' || fail "Insufficient free disk space in the build filesystem"
else
  fail "df not available"
fi

echo "[P0] HOST CHECK PASS"
