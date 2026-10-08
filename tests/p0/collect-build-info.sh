#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/artifacts/p0"

mkdir -p "$OUT"

{
    echo "=== ExamOS P0 Build Information ==="
    date -Is

    echo
    echo "=== Host ==="
    uname -a
    cat /etc/os-release

    echo
    echo "=== CPU ==="
    uname -m
    nproc

    echo
    echo "=== KVM ==="
    if [[ -e /dev/kvm ]]; then
        echo "KVM_PRESENT=true"
    else
        echo "KVM_PRESENT=false"
        exit 1
    fi

    echo
    echo "=== Tools ==="
    git --version
    mkosi --version
    qemu-system-x86_64 --version | head -n 1
    swtpm --version
    tpm2_pcrread --version

} > "$OUT/build-info.txt"

echo "[P0] Wrote $OUT/build-info.txt"
