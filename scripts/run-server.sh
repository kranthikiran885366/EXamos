#!/bin/bash
# Start the ExamOS C server (backend) for integration with the React console.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source secrets if present
if [ -f "$ROOT_DIR/_secrets/env.sh" ]; then
  source "$ROOT_DIR/_secrets/env.sh"
fi

if [ -f "$ROOT_DIR/deploy/examos.env" ]; then
  set -a; . "$ROOT_DIR/deploy/examos.env"; set +a
fi

export EXAMOS_SERVER_PORT="${EXAMOS_SERVER_PORT:-8000}"
export EXAMOS_PORT="${EXAMOS_PORT:-8000}"
export EXAMOS_BIND_ADDR="${EXAMOS_BIND_ADDR:-127.0.0.1}"
export EXAMOS_CORS_ALLOWED_ORIGINS="${EXAMOS_CORS_ALLOWED_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}"
export EXAMOS_TPM_MODE="${EXAMOS_TPM_MODE:-development}"
export EXAMOS_PRODUCTION_MODE="${EXAMOS_PRODUCTION_MODE:-0}"
export EXAMOS_AGENT_API_TOKEN="${EXAMOS_AGENT_API_TOKEN:-examos_agent_api_token_test_32bytes_val}"
export EXAMOS_PROCTOR_API_TOKEN="${EXAMOS_PROCTOR_API_TOKEN:-examos_proctor_api_token_test_32bytes_v}"
export EXAMOS_EVENT_SIGNING_KEY="${EXAMOS_EVENT_SIGNING_KEY:-0123456789abcdef0123456789abcdef01234567}"
export EXAMOS_VARIANT_SECRET="${EXAMOS_VARIANT_SECRET:-fedcba9876543210fedcba9876543210fedcba98}"
export EXAMOS_LEDGER_HMAC_KEY="${EXAMOS_LEDGER_HMAC_KEY:-abcdef0123456789abcdef0123456789abcdef01}"
export EXAMOS_EXAM_KEY_KEK="${EXAMOS_EXAM_KEY_KEK:-ExamOsKekDevTest2026ExamOsKekDevTest2026}"
export EXAMOS_DATABASE_URL_FILE="${EXAMOS_DATABASE_URL_FILE:-$HOME/_examos_secrets/db_url}"
export EXAMOS_LEDGER_PATH="/tmp/examos_ledger.log"
export EXAMOS_SESSION_JOURNAL="/tmp/examos_session_journal.log"
export EXAMOS_EVENT_CHAIN_PATH="/tmp/examos_events.log"
export EXAMOS_DATA_DIR="/tmp/examos_data"
mkdir -p "$EXAMOS_DATA_DIR/submissions" /tmp

echo "[examos] Starting server on ${EXAMOS_BIND_ADDR}:${EXAMOS_PORT} (mode=${EXAMOS_TPM_MODE})"
echo "[examos] CORS allowed origins: ${EXAMOS_CORS_ALLOWED_ORIGINS}"

cd "$ROOT_DIR/server"
exec ./examos-server
