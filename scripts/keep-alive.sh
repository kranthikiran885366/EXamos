#!/bin/bash
set -euo pipefail

ROOT="/mnt/d/SEB BRO"
bash "$ROOT/_start_all.sh"

echo "=== Stack started. WSL keep-alive active. ==="
exec tail -f /dev/null
