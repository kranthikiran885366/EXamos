#!/usr/bin/env bash
# =============================================================================
# ExamOS Server — Local Launch Script
# scripts/launch-server.sh
#
# Launches the ExamOS examination server on all interfaces for local testing.
# Access from Windows browser: http://localhost:8000
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     ExamOS Examination Server — Local Launch            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Ensure binary is built
if [ ! -f "$WORKSPACE/server/examos-server" ]; then
    echo "[LAUNCH] Server binary not found. Building..."
    make -C "$WORKSPACE" all
fi

if [ ! -x "$WORKSPACE/server/examos-server" ]; then
    chmod +x "$WORKSPACE/server/examos-server"
fi

# Create required directories
mkdir -p /tmp/examos-logs
sudo mkdir -p /etc/examos 2>/dev/null || true

if [ ! -s /etc/examos/exam.conf ]; then
    echo "[LAUNCH] No exam configuration is provisioned; exam start remains unavailable."
fi

# Never create a well-known administrator credential from a development
# launcher. Provision credentials through the controlled administrator setup.
if [ ! -s /etc/examos/admin.conf ]; then
    echo "[LAUNCH] No administrator credential is provisioned. Configure an administrator before enabling admin access."
fi

# Set environment
export EXAMOS_SERVER_PORT=${EXAMOS_SERVER_PORT:-8000}
export EXAMOS_ALLOW_UNPROVISIONED_DEV=${EXAMOS_ALLOW_UNPROVISIONED_DEV:-1}
export EXAMOS_LEDGER_PATH=/tmp/examos-logs/event_ledger.log

echo "[LAUNCH] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[LAUNCH] Server Port:      $EXAMOS_SERVER_PORT"
echo "[LAUNCH] Ledger Path:      $EXAMOS_LEDGER_PATH"
echo "[LAUNCH] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[LAUNCH] Access from Windows browser:"
echo "  Candidate Login:   http://localhost:$EXAMOS_SERVER_PORT/"
echo "  Admin Dashboard:   http://localhost:$EXAMOS_SERVER_PORT/admin"
echo "  Health Check:      http://localhost:$EXAMOS_SERVER_PORT/api/v1/health"
echo "  System Status:     http://localhost:$EXAMOS_SERVER_PORT/api/v1/status"
echo "  Event Ledger:      http://localhost:$EXAMOS_SERVER_PORT/api/v1/ledger"
echo ""
echo "[LAUNCH] No default admin credentials are installed."
echo "[LAUNCH] Press Ctrl+C to stop the server."
echo ""
echo "[LAUNCH] Starting ExamOS server..."
echo ""

# Launch server (exec replaces this shell)
exec "$WORKSPACE/server/examos-server"
