#!/bin/bash
set -euo pipefail

ROOT="/mnt/d/SEB BRO"
cd "$ROOT"

bash "$ROOT/_start_all.sh"
echo "=== Stack is live. Following server log... ==="
exec tail -f "$ROOT/_logs/server.log"
