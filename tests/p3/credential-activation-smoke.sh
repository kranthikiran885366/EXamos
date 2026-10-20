#!/usr/bin/env bash
# Exercises the real TPM2 MakeCredential/ActivateCredential protocol.
set -euo pipefail

for tool in swtpm tpm2_startup tpm2_createek tpm2_createak \
            tpm2_readpublic tpm2_makecredential tpm2_startauthsession \
            tpm2_policysecret tpm2_activatecredential tpm2_flushcontext \
            openssl xxd python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[P3-ACTIVATE] BLOCKED: missing required tool: $tool" >&2
        exit 2
    }
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/examos-p3-activate.XXXXXX")
TPM_PID=""
cleanup() {
    [ -n "$TPM_PID" ] && kill "$TPM_PID" 2>/dev/null || true
    [ -n "$TPM_PID" ] && wait "$TPM_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

read -r TPM_PORT CTRL_PORT < <(python3 - <<'PY'
import socket
for port in range(20000, 60000):
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
    raise SystemExit("no adjacent free ports")
PY
)

mkdir "$WORK_DIR/state"
swtpm socket --tpm2 --tpmstate "dir=$WORK_DIR/state" \
    --server "type=tcp,port=$TPM_PORT,bindaddr=127.0.0.1" \
    --ctrl "type=tcp,port=$CTRL_PORT,bindaddr=127.0.0.1" \
    --flags not-need-init,startup-clear >"$WORK_DIR/swtpm.log" 2>&1 &
TPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"
sleep 0.2
tpm2_startup -c >/dev/null 2>&1 || true

EK_HANDLE=0x81010009
tpm2_createek -G rsa -c "$EK_HANDLE" -u "$WORK_DIR/ek.pub" -R >/dev/null
tpm2_readpublic -c "$EK_HANDLE" -f pem -o "$WORK_DIR/ek.pem" >/dev/null
tpm2_createak -C "$EK_HANDLE" -G rsa -g sha256 -s rsassa \
    -c "$WORK_DIR/ak.ctx" -u "$WORK_DIR/ak.pub" \
    -n "$WORK_DIR/ak.name" -R >/dev/null

AK_NAME_HEX=$(xxd -p -c 1000 "$WORK_DIR/ak.name" | tr -d '\n')
[ ${#AK_NAME_HEX} -eq 68 ] || {
    echo "[P3-ACTIVATE] FAIL: expected 34-byte SHA-256 TPM Name" >&2
    exit 1
}

openssl rand -out "$WORK_DIR/challenge.secret" 32
TPM2TOOLS_TCTI=none tpm2_makecredential -Q -G rsa \
    -u "$WORK_DIR/ek.pem" -s "$WORK_DIR/challenge.secret" \
    -n "$AK_NAME_HEX" -o "$WORK_DIR/credential.blob"

# Clear transient/session slots left by provisioning without touching the
# persistent EK. This mirrors a challenge arriving after enrollment.
tpm2_flushcontext -t >/dev/null 2>&1 || true
tpm2_flushcontext -s >/dev/null 2>&1 || true
tpm2_startauthsession --policy-session -S "$WORK_DIR/policy.ctx"
tpm2_policysecret -S "$WORK_DIR/policy.ctx" -c 0x4000000B >/dev/null
tpm2_activatecredential -c "$WORK_DIR/ak.ctx" -C "$EK_HANDLE" \
    -i "$WORK_DIR/credential.blob" -o "$WORK_DIR/recovered.secret" \
    -P "session:$WORK_DIR/policy.ctx" >/dev/null

if ! cmp -s "$WORK_DIR/challenge.secret" "$WORK_DIR/recovered.secret"; then
    echo "[P3-ACTIVATE] FAIL: activated credential does not match challenge" >&2
    exit 1
fi

echo "[P3-ACTIVATE] PASS: MakeCredential/ActivateCredential proved EK-AK co-residency"
echo "[P3-ACTIVATE] AK TPM Name: $AK_NAME_HEX"
