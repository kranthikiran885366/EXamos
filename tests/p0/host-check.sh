#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $1"
  exit 1
}

echo "=== ExamOS P0 Host Check ==="

echo "[1/10] Checking Host OS..."
uname_out="$(uname -s 2>/dev/null || echo unknown)"
[[ "$uname_out" == "Linux" ]] || fail "Linux host required; found: ${uname_out}"
echo "       Host OS: ${uname_out} (PASS)"

echo "[2/10] Checking Architecture..."
arch_out="$(uname -m 2>/dev/null || echo unknown)"
[[ "$arch_out" == "x86_64" ]] || fail "x86-64 host required; found: ${arch_out}"
echo "       Architecture: ${arch_out} (PASS)"

echo "[3/10] Checking CPU Virtualization Extensions..."
if [[ -e /proc/cpuinfo ]]; then
  if grep -E -q '(vmx|svm)' /proc/cpuinfo; then
    echo "       Virtualization: Hardware vmx/svm detected (PASS)"
  else
    fail "Hardware virtualization extensions (vmx/svm) not detected in /proc/cpuinfo"
  fi
else
  fail "/proc/cpuinfo not available"
fi

echo "[4/10] Checking /dev/kvm Access..."
if [[ -e /dev/kvm ]]; then
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    echo "       /dev/kvm: Available and accessible (PASS)"
  else
    fail "/dev/kvm exists but is not read/writable by current user ($(whoami))"
  fi
else
  fail "/dev/kvm device node missing"
fi

echo "[5/10] Checking QEMU System Emulator..."
command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 missing from PATH"
echo "       QEMU: $(qemu-system-x86_64 --version | head -n 1) (PASS)"

echo "[6/10] Checking OVMF UEFI Firmware..."
OVMF_CODE=""
for candidate in \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
  /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
  /usr/share/qemu/OVMF.fd; do
  if [[ -f "$candidate" ]]; then
    OVMF_CODE="$candidate"
    break
  fi
done
if [[ -n "$OVMF_CODE" ]]; then
  echo "       OVMF Firmware: $OVMF_CODE (PASS)"
else
  fail "No OVMF firmware image found in standard system locations"
fi

echo "[7/10] Checking Virtual TPM (swtpm)..."
command -v swtpm >/dev/null || fail "swtpm missing from PATH"
echo "       swtpm: $(swtpm --version | head -n 1) (PASS)"

echo "[8/10] Checking TPM 2.0 Tools..."
command -v tpm2_pcrread >/dev/null || fail "tpm2_pcrread (tpm2-tools) missing from PATH"
echo "       TPM Tools: tpm2-tools present (PASS)"

echo "[9/10] Checking mkosi Image Builder..."
command -v mkosi >/dev/null || fail "mkosi missing from PATH"
echo "       mkosi: $(mkosi --version | head -n 1) (PASS)"

echo "[10/10] Checking Build Storage Capacity (Minimum 50 GB)..."
if command -v df >/dev/null; then
  avail_kb="$(df -k "$HOME" | tail -n 1 | awk '{print $4}')"
  avail_gb=$((avail_kb / 1024 / 1024))
  if [[ "$avail_gb" -ge 50 ]]; then
    echo "       Disk Space: ${avail_gb} GB available on build filesystem (PASS)"
  else
    fail "Insufficient free storage: ${avail_gb} GB available, at least 50 GB required"
  fi
else
  fail "df command unavailable"
fi

echo "=========================================="
echo "HOST CHECK RESULT: PASS"
echo "=========================================="
