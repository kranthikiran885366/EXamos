#!/usr/bin/env bash
set -euo pipefail

D=$(mktemp -d /tmp/test-tpm-XXXXXX)
swtpm socket --tpm2 --tpmstate "dir=$D" \
    --server "type=unixio,path=$D/sock" \
    --ctrl "type=unixio,path=$D/sock.ctrl" \
    --flags not-need-init,startup-clear \
    > "$D/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

echo "1. swtpm running: $(kill -0 "$SWTPM_PID" 2>/dev/null && echo YES || echo NO)"
echo "2. testing query via sock:"
TPM2TOOLS_TCTI="swtpm:path=$D/sock" tpm2_startup -c || true
TPM2TOOLS_TCTI="swtpm:path=$D/sock" tpm2_getcap properties-fixed | head -n 3 || true

echo "3. starting minimal qemu connected to ctrl socket:"
qemu-system-x86_64 -machine q35 -m 256 -chardev "socket,id=chrtpm,path=$D/sock.ctrl" \
    -tpmdev "emulator,id=tpm0,chardev=chrtpm" -device tpm-tis,tpmdev=tpm0 \
    -display none -monitor none >/dev/null 2>&1 &
QEMU_PID=$!
sleep 2

echo "4. qemu running: $(kill -0 "$QEMU_PID" 2>/dev/null && echo YES || echo NO)"
echo "5. swtpm running with qemu: $(kill -0 "$SWTPM_PID" 2>/dev/null && echo YES || echo NO)"

echo "6. killing qemu with SIGTERM:"
kill -TERM "$QEMU_PID" || true
sleep 1

echo "7. swtpm running after qemu killed with SIGTERM:"
kill -0 "$SWTPM_PID" 2>/dev/null && echo "YES STILL RUNNING" || echo "NO IT EXITED"
echo "8. swtpm log:"
cat "$D/swtpm.log" || true

kill -9 "$SWTPM_PID" 2>/dev/null || true
rm -rf "$D"
