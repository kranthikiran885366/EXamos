#!/usr/bin/env bash
set -euo pipefail
TMPDIR=$(mktemp -d /tmp/test-swtpm-XXXXXX)
STATE=$(mktemp -d /tmp/test-state-XXXXXX)
SERVER="$TMPDIR/swtpm.sock"
CTRL="$SERVER.ctrl"

swtpm socket --tpm2 --tpmstate "dir=$STATE" \
    --server "type=unixio,path=$SERVER" \
    --ctrl "type=unixio,path=$CTRL" \
    --flags not-need-init,startup-clear \
    > "$TMPDIR/swtpm.log" 2>&1 </dev/null &
TPM_PID=$!
sleep 1
if kill -0 "$TPM_PID" 2>/dev/null; then echo "swtpm running: YES"; else echo "swtpm running: NO"; fi
if [[ -S "$SERVER" ]]; then echo "server sock exists: YES"; else echo "server sock exists: NO"; fi

python3 -c 'import socket, time, sys; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); time.sleep(1); s.close()' "$CTRL"

sleep 1
if kill -0 "$TPM_PID" 2>/dev/null; then echo "after ctrl disconnect, swtpm running: YES"; else echo "after ctrl disconnect, swtpm running: NO"; fi
if [[ -S "$SERVER" ]]; then echo "server sock exists: YES"; else echo "server sock exists: NO"; fi
cat "$TMPDIR/swtpm.log"

kill "$TPM_PID" 2>/dev/null || true
rm -rf "$TMPDIR" "$STATE"
