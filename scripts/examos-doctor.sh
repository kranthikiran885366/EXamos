#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check() {
  if "$@"; then
    echo "PASS: $*"
  else
    echo "FAIL: $*"
    return 1
  fi
}

printf '%s\n' "EXAMOS DOCTOR"
printf '%s\n' "============"

check test -f "$ROOT/README.md"
check test -d "$ROOT/image"
check uname -m
check test -e /dev/kvm
check command -v git
check command -v mkosi
check command -v qemu-system-x86_64
check command -v swtpm
check command -v tpm2_pcrread
check df -h "$ROOT"

printf '%s\n' "RESULT: READY FOR P0"
