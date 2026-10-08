#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

printf '%s\n' "EXAMOS DOCTOR"
printf '%s\n' "============"

check() {
  label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '%-24s PASS\n' "$label"
  else
    printf '%-24s FAIL\n' "$label"
  fi
}

check "Host OS" bash -lc 'test "$(uname -s)" = "Linux"'
check "Architecture" bash -lc 'test "$(uname -m)" = "x86_64"'
check "Virtualization" bash -lc 'egrep -q "(vmx|svm)" /proc/cpuinfo'
check "KVM device" bash -lc 'test -e /dev/kvm'
check "UEFI" bash -lc 'test -d /sys/firmware/efi'
check "QEMU" bash -lc 'command -v qemu-system-x86_64'
check "OVMF" bash -lc 'test -f /usr/share/OVMF/OVMF_CODE_4M.fd || test -f /usr/share/edk2/ovmf/OVMF_CODE_4M.fd'
check "swtpm" bash -lc 'command -v swtpm'
check "TPM tools" bash -lc 'command -v tpm2_pcrread'
check "Secure Boot tools" bash -lc 'command -v sbsign && command -v sbverify'
check "dm-verity" bash -lc 'command -v veritysetup'
check "SquashFS" bash -lc 'command -v mksquashfs'
check "mkosi" bash -lc 'command -v mkosi'
check "Git" bash -lc 'command -v git'
check "Disk capacity" bash -lc 'df -h "$HOME" | tail -n +2 | awk "{print \$4}" | head -n 1 | grep -Eq "[1-9][0-9]+G|[5-9][0-9]+G|[0-9]+T"'
check "Repository" bash -lc 'test -d "$ROOT/image" && test -d "$ROOT/tests/p0"'

printf '%s\n' "RESULT: READY FOR P0 ONLY WHEN ALL REQUIRED CHECKS PASS"
