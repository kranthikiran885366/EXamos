#!/usr/bin/env bash
set -e
cd "/mnt/d/SEB BRO" || exit 1

echo "=== 1. Starting step4-run-kiosk.sh in background ==="
bash "/mnt/d/SEB BRO/scripts/step4-run-kiosk.sh" &
QEMU_PID=$!

echo "QEMU runner PID: $QEMU_PID"
sleep 2

echo "=== 2. Starting monitor-kiosk-live.py ==="
python3 "/mnt/d/SEB BRO/scripts/monitor-kiosk-live.py"

echo "=== 3. Monitoring complete. Kiosk log tail: ==="
tail -n 40 "$HOME/sppio-test/kiosk-test.log"
