#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || {
    echo "[VH-TPM] BLOCKED: set EXAMOS_VH_RUN_DIR to an existing evidence run." >&2
    exit 2
}

for tool in swtpm tpm2_startup tpm2_createek tpm2_createak tpm2_readpublic \
            tpm2_getcap tpm2_pcrread tpm2_quote tpm2_checkquote openssl cc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[VH-TPM] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

EVIDENCE="$RUN_DIR/tpm-quote"
mkdir -m 700 -- "$EVIDENCE"
mkdir -m 700 -- "$EVIDENCE/state"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sppio-vh-tpm.XXXXXX")"
TPM_PID=""

cleanup() {
    local rc=$?
    if [[ -n "$TPM_PID" ]] && kill -0 "$TPM_PID" 2>/dev/null; then
        if [[ -r "/proc/$TPM_PID/cmdline" ]] &&
           tr '\0' ' ' < "/proc/$TPM_PID/cmdline" | grep -Fq -- "$EVIDENCE/state"; then
            kill -TERM "$TPM_PID" 2>/dev/null || true
            for _ in $(seq 1 40); do
                kill -0 "$TPM_PID" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$TPM_PID" 2>/dev/null &&
               tr '\0' ' ' < "/proc/$TPM_PID/cmdline" | grep -Fq -- "$EVIDENCE/state"; then
                kill -KILL "$TPM_PID" 2>/dev/null || true
            fi
        else
            echo "[VH-TPM] FAIL: refusing to stop a PID not bound to this run." >&2
            rc=1
        fi
    fi
    rm -rf -- "$TMP_DIR"
    return "$rc"
}
trap cleanup EXIT

read -r TPM_PORT CTRL_PORT < <(python3 - <<'PY'
import socket
for port in range(23000, 59000):
    sockets = []
    try:
        for candidate in (port, port + 1):
            sock = socket.socket()
            sock.bind(("127.0.0.1", candidate))
            sockets.append(sock)
        print(port, port + 1)
        break
    except OSError:
        pass
    finally:
        for sock in sockets:
            sock.close()
else:
    raise SystemExit("no available loopback port pair")
PY
)
[[ "$TPM_PORT" =~ ^[0-9]+$ && "$CTRL_PORT" =~ ^[0-9]+$ ]] || {
    echo "[VH-TPM] BLOCKED: no loopback ports were available." >&2
    exit 2
}

swtpm socket --tpm2 --tpmstate "dir=$EVIDENCE/state" \
    --server "type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1" \
    --ctrl "type=tcp,port=$CTRL_PORT,bindaddr=127.0.0.1" \
    --flags not-need-init,startup-clear \
    > "$EVIDENCE/swtpm.log" 2>&1 &
TPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"

startup_ok=0
for _ in $(seq 1 30); do
    if ! kill -0 "$TPM_PID" 2>/dev/null; then
        cat "$EVIDENCE/swtpm.log" >&2
        echo "[VH-TPM] FAIL: swtpm exited during startup." >&2
        exit 1
    fi
    if tpm2_startup -c > "$EVIDENCE/startup.log" 2>&1; then
        startup_ok=1
        break
    fi
    sleep 0.1
done
if [[ "$startup_ok" -ne 1 ]] &&
   ! grep -qiE 'already|initialized|initialize' "$EVIDENCE/startup.log"; then
    echo "[VH-TPM] FAIL: TPM startup failed unexpectedly." >&2
    cat "$EVIDENCE/startup.log" >&2
    exit 1
fi
tpm2_getcap properties-fixed > "$EVIDENCE/tpm-properties-fixed.txt" 2>&1 || {
    echo "[VH-TPM] FAIL: TPM 2.0 capability query failed after startup." >&2
    exit 1
}
tpm2_getcap properties-variable > "$EVIDENCE/tpm-properties-variable.txt"
tpm2_getcap algorithms > "$EVIDENCE/tpm-algorithms.txt"
tpm2_getcap pcrs > "$EVIDENCE/tpm-pcr-banks.txt"

tpm2_createek -c "$TMP_DIR/ek.ctx" -G rsa -R > "$EVIDENCE/create-ek.log" 2>&1
tpm2_createak -C "$TMP_DIR/ek.ctx" -c "$TMP_DIR/ak.ctx" \
    -G rsa -g sha256 -s rsassa -u "$TMP_DIR/ak.pub" \
    -n "$TMP_DIR/ak.name" -R > "$EVIDENCE/create-ak.log" 2>&1
tpm2_flushcontext -t
tpm2_readpublic -c "$TMP_DIR/ak.ctx" -f pem \
    -o "$EVIDENCE/ak-public.pem" -q "$TMP_DIR/ak.qualified-name" \
    > "$EVIDENCE/read-ak.log" 2>&1
tpm2_flushcontext -t

tpm2_pcrread -o "$EVIDENCE/pcr-values.bin" sha256:0,4,7,11 \
    > "$EVIDENCE/pcr-values.yaml"
NONCE="$(openssl rand -hex 32)"
tpm2_quote -c "$TMP_DIR/ak.ctx" -l sha256:0,4,7,11 -q "$NONCE" \
    -m "$EVIDENCE/quote.attest" -s "$EVIDENCE/quote.signature" \
    -o "$EVIDENCE/quote.pcr" > "$EVIDENCE/quote-generation.log" 2>&1
tpm2_checkquote -u "$EVIDENCE/ak-public.pem" -m "$EVIDENCE/quote.attest" \
    -s "$EVIDENCE/quote.signature" -f "$EVIDENCE/pcr-values.bin" \
    -l sha256:0,4,7,11 -q "$NONCE" > "$EVIDENCE/quote-verification.txt"

cc -Wall -Wextra -Werror -I"$WORKSPACE/server/include" \
    "$WORKSPACE/tests/server/tpm_quote_verify_test.c" \
    "$WORKSPACE/server/attestation/tpm_quote.c" \
    -lssl -lcrypto -o "$TMP_DIR/tpm-quote-verifier-test"
EXAMOS_TEST_TPM_NONCE="$NONCE" "$TMP_DIR/tpm-quote-verifier-test" \
    "$EVIDENCE/quote.attest" "$EVIDENCE/quote.signature" \
    "$EVIDENCE/ak-public.pem" "$TMP_DIR/ak.qualified-name" \
    | tee "$EVIDENCE/backend-quote-verifier.txt"

python3 - "$EVIDENCE" "$NONCE" "$TPM_PORT" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

directory = pathlib.Path(sys.argv[1])
def digest(name):
    return hashlib.sha256((directory / name).read_bytes()).hexdigest()

record = {
    "schema": "sppio.virtual-hardware.tpm-quote.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "evidence_type": "software-emulated-tpm-2.0",
    "production_hardware_evidence": False,
    "tcti": "swtpm loopback",
    "quote_nonce": sys.argv[2],
    "loopback_port": int(sys.argv[3]),
    "pcr_selection": "sha256:0,4,7,11",
    "quote_sha256": digest("quote.attest"),
    "signature_sha256": digest("quote.signature"),
    "public_ak_sha256": digest("ak-public.pem"),
    "local_tpm2_checkquote": "PASS",
    "backend_quote_parser_and_negative_cases": "PASS",
    "negative_cases": ["incorrect nonce", "incorrect PCR values", "modified quote signature"],
}
with (directory / "quote-metadata.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-TPM] PASS: virtual TPM 2.0 capabilities, PCR read, AK-bound fresh quote, signature verification, and tamper rejection.\n'
