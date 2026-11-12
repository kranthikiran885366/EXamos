#!/usr/bin/env bash
set -euo pipefail

for tool in swtpm tpm2_startup tpm2_createprimary tpm2_createak \
            tpm2_createek tpm2_readpublic tpm2_flushcontext tpm2_quote \
            tpm2_pcrread tpm2_checkquote \
            openssl xxd; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[P3-SWTPM] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/examos-p3-swtpm.XXXXXX")
WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
TPM_PID=""
cleanup() {
    if [ -n "$TPM_PID" ]; then
        kill "$TPM_PID" 2>/dev/null || true
        wait "$TPM_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

TPM_PORT=$(python3 -c '
import socket
for port in range(20000, 60000):
    sockets = []
    try:
        for candidate in (port, port + 1):
            sock = socket.socket()
            sock.bind(("127.0.0.1", candidate))
            sockets.append(sock)
        print(port)
        break
    except OSError:
        pass
    finally:
        for sock in sockets:
            sock.close()
else:
    raise SystemExit("no adjacent free TCP ports for swtpm")
')
CTRL_PORT=$((TPM_PORT + 1))

mkdir "$WORK_DIR/state"
swtpm socket --tpm2 --tpmstate "dir=$WORK_DIR/state" \
    --server "type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1" \
    --ctrl "type=tcp,port=$CTRL_PORT,bindaddr=127.0.0.1" \
    --flags not-need-init,startup-clear >"$WORK_DIR/swtpm.log" 2>&1 &
TPM_PID=$!

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"
sleep 0.2
if ! kill -0 "$TPM_PID" 2>/dev/null; then
    echo "[P3-SWTPM] FATAL: swtpm exited during startup" >&2
    cat "$WORK_DIR/swtpm.log" >&2
    exit 1
fi
for _ in $(seq 1 20); do
    if tpm2_startup -c >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

tpm2_createek -c "$WORK_DIR/ek.ctx" -G rsa -R >/dev/null
tpm2_createak -C "$WORK_DIR/ek.ctx" -c "$WORK_DIR/ak.ctx" \
    -G rsa -g sha256 -s rsassa -u "$WORK_DIR/ak.pub" \
    -n "$WORK_DIR/ak.name" -R >/dev/null
tpm2_flushcontext -t
tpm2_readpublic -c "$WORK_DIR/ak.ctx" -f pem \
    -o "$WORK_DIR/ak.pem" -q "$WORK_DIR/ak.qualified-name" >/dev/null
tpm2_readpublic -c "$WORK_DIR/ak.ctx" -f tss \
    -o "$WORK_DIR/ak.public.tss" -n "$WORK_DIR/ak.read-name" >/dev/null
tpm2_flushcontext -t

cc -Wall -Wextra -Werror -Wno-deprecated-declarations -I"$WORKSPACE/server/include" \
    "$WORKSPACE/tests/server/tpm_public_test.c" \
    "$WORKSPACE/server/attestation/tpm_public.c" \
    -lssl -lcrypto -o "$WORK_DIR/tpm-public-test"
"$WORK_DIR/tpm-public-test" "$WORK_DIR/ak.public.tss" \
    "$WORK_DIR/ak.pem" "$WORK_DIR/ak.read-name"

NONCE=$(openssl rand -hex 32)
tpm2_pcrread -o "$WORK_DIR/pcr-read.yaml" sha256:0,4,7,11 >/dev/null
tpm2_quote -c "$WORK_DIR/ak.ctx" -l sha256:0,4,7,11 \
    -q "$NONCE" -m "$WORK_DIR/quote.msg" \
    -s "$WORK_DIR/quote.sig" -o "$WORK_DIR/quote.pcr"
tpm2_checkquote -u "$WORK_DIR/ak.pem" -m "$WORK_DIR/quote.msg" \
    -s "$WORK_DIR/quote.sig" -f "$WORK_DIR/pcr-read.yaml" \
    -l sha256:0,4,7,11 -q "$NONCE"

cc -Wall -Wextra -Werror -I"$WORKSPACE/server/include" \
    "$WORKSPACE/tests/server/tpm_quote_verify_test.c" \
    "$WORKSPACE/server/attestation/tpm_quote.c" \
    -lssl -lcrypto -o "$WORK_DIR/tpm-quote-verifier-test"
EXAMOS_TEST_TPM_NONCE="$NONCE" "$WORK_DIR/tpm-quote-verifier-test" \
    "$WORK_DIR/quote.msg" "$WORK_DIR/quote.sig" "$WORK_DIR/ak.pem" \
    "$WORK_DIR/ak.qualified-name"

echo "[P3-SWTPM] quote message bytes: $(wc -c < "$WORK_DIR/quote.msg")"
echo "[P3-SWTPM] quote signature bytes: $(wc -c < "$WORK_DIR/quote.sig")"
echo "[P3-SWTPM] message hex: $(xxd -p -c 10000 "$WORK_DIR/quote.msg")"
echo "[P3-SWTPM] signature hex: $(xxd -p -c 10000 "$WORK_DIR/quote.sig")"
echo "[P3-SWTPM] TPM quote self-verification passed"
