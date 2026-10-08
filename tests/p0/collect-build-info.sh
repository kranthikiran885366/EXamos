#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/artifacts/p0"

mkdir -p "$OUT"

{
    echo "=== ExamOS P0 Build Information ==="
    date -Is || date

    echo
    echo "=== Git ==="
    git -C "$ROOT" log -n 1 --format="commit: %H%nauthor: %an%ndate:   %ad%nsubject: %s" 2>/dev/null || echo "Git information not available"

    echo
    echo "=== Host Environment ==="
    uname -a 2>/dev/null || true
    test -f /etc/os-release && cat /etc/os-release || echo "No /etc/os-release"

    echo
    echo "=== CPU & Virtualization ==="
    uname -m 2>/dev/null || true
    nproc 2>/dev/null || echo "nproc unavailable"
    if [[ -e /dev/kvm ]]; then
        echo "KVM_PRESENT=true"
    else
        echo "KVM_PRESENT=false"
    fi

    echo
    echo "=== Tools & Compilers ==="
    git --version 2>/dev/null || echo "git missing"
    gcc --version 2>/dev/null | head -n 1 || echo "gcc missing"
    g++ --version 2>/dev/null | head -n 1 || echo "g++ missing"
    make --version 2>/dev/null | head -n 1 || echo "make missing"
    mkosi --version 2>/dev/null || echo "mkosi missing"
    qemu-system-x86_64 --version 2>/dev/null | head -n 1 || echo "qemu-system-x86_64 missing"
    swtpm --version 2>/dev/null || echo "swtpm missing"
    tpm2_pcrread --version 2>/dev/null || echo "tpm2_pcrread missing"

} > "$OUT/build-info.txt"

echo "[P0] Recorded build metadata in $OUT/build-info.txt"
