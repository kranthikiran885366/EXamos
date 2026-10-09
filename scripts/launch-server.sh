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

# Create default config if missing
if [ ! -f /etc/examos/exam.conf ]; then
    echo "[LAUNCH] Creating default exam configuration..."
    sudo tee /etc/examos/exam.conf > /dev/null <<'CONF'
EXAM_URL=NOT_CONFIGURED
EXAM_NAME=ExamOS Enterprise Examination
EXAM_DURATION_MINUTES=120
CONF
fi

# Create admin credentials if missing
if [ ! -f /etc/examos/admin.conf ]; then
    echo "[LAUNCH] Creating default admin credentials..."
    ADMIN_HASH=$(echo -n 'ExamOS@Admin2025!' | sha256sum | cut -d' ' -f1)
    sudo tee /etc/examos/admin.conf > /dev/null <<CONF
ADMIN_PASSWORD_SHA256=$ADMIN_HASH
CONF
    sudo chmod 600 /etc/examos/admin.conf
fi

# Set environment
export EXAMOS_SERVER_PORT=${EXAMOS_SERVER_PORT:-8000}
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
echo "[LAUNCH] Default admin credentials: admin / ExamOS@Admin2025!"
echo "[LAUNCH] Press Ctrl+C to stop the server."
echo ""
echo "[LAUNCH] Starting ExamOS server..."
echo ""

# Launch server (exec replaces this shell)
exec "$WORKSPACE/server/examos-server"
