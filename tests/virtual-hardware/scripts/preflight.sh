#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"

if [[ -z "$RUN_DIR" ]]; then
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    RUN_DIR="$WORKSPACE/tests/virtual-hardware/evidence/$run_id"
    mkdir -p -- "$RUN_DIR"
    export EXAMOS_VH_RUN_DIR="$RUN_DIR"
fi

mkdir -p -- "$RUN_DIR/reports"
python3 "$SCRIPT_DIR/inventory.py" --output-dir "$RUN_DIR/reports"

missing=()
for tool in qemu-system-x86_64 qemu-img swtpm tpm2_getcap openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [[ "${#missing[@]}" -ne 0 ]]; then
    printf '[VH-01] BLOCKED: missing required tool(s): %s\n' "${missing[*]}" >&2
    exit 2
fi

printf '[VH-01] PASS: required QEMU, swtpm, TPM 2.0, OpenSSL, and Python tools are present.\n'
