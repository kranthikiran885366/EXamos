#!/bin/bash
set -e

echo "=========================================================="
echo " Starting Secure Physical Proctoring & Isolation OS (SPPIO)"
echo " Core Enterprise Backend on Render Cloud"
echo "=========================================================="

# 1. Port mapping (Render sets $PORT, default to 10000 on Render free tier)
if [ -n "$PORT" ]; then
    export EXAMOS_SERVER_PORT="$PORT"
elif [ -z "$EXAMOS_SERVER_PORT" ]; then
    export EXAMOS_SERVER_PORT="10000"
fi

# 2. Network bindings
export EXAMOS_BIND_ADDR="0.0.0.0"
export EXAMOS_TLS_TERMINATED="1"

# 3. CORS origin (allows Vercel frontend to query the API)
if [ -z "$EXAMOS_CORS_ALLOWED_ORIGINS" ]; then
    export EXAMOS_CORS_ALLOWED_ORIGINS="https://sppio-os.vercel.app,http://localhost:5173,http://localhost:3000"
fi

# 4. Storage and ledger directories
export EXAMOS_DATA_DIR="${EXAMOS_DATA_DIR:-/var/lib/examos}"
export EXAMOS_LEDGER_PATH="${EXAMOS_LEDGER_PATH:-/var/lib/examos/ledger.log}"
export EXAMOS_EVENT_CHAIN_PATH="${EXAMOS_EVENT_CHAIN_PATH:-/var/lib/examos/events}"
mkdir -p "$EXAMOS_DATA_DIR" "$EXAMOS_EVENT_CHAIN_PATH" /tmp/examos

# 5. Database URL mapping
if [ -n "$DATABASE_URL" ] && [ -z "$EXAMOS_DATABASE_URL" ]; then
    export EXAMOS_DATABASE_URL="$DATABASE_URL"
fi

# 6. Ensure security keys exist (fall back to cryptographically secure urandom if not set)
if [ -z "$EXAMOS_LEDGER_HMAC_KEY" ]; then
    export EXAMOS_LEDGER_HMAC_KEY=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_EXAM_KEY_KEK" ]; then
    export EXAMOS_EXAM_KEY_KEK=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_ADMIN_API_TOKEN" ]; then
    export EXAMOS_ADMIN_API_TOKEN=$(openssl rand -hex 32)
    echo "[SPPIO-Core] Generated ephemeral EXAMOS_ADMIN_API_TOKEN"
fi

if [ -z "$EXAMOS_AGENT_API_TOKEN" ]; then
    export EXAMOS_AGENT_API_TOKEN=$(openssl rand -hex 32)
fi

echo "[SPPIO-Core] Listening on: 0.0.0.0:$EXAMOS_SERVER_PORT"
echo "[SPPIO-Core] CORS Allowed Origins: $EXAMOS_CORS_ALLOWED_ORIGINS"

# 7. Run database migrations if database URL is provisioned
if [ -n "$EXAMOS_DATABASE_URL" ]; then
    echo "[SPPIO-Core] Checking and applying database migrations..."
    if [ -x /usr/local/bin/sppio-db-migrate ] && [ -d /opt/sppio/migrations ]; then
        /usr/local/bin/sppio-db-migrate /opt/sppio/migrations "$EXAMOS_DATABASE_URL" || true
    fi
fi

# 8. Hand off to native C server binary
exec /usr/local/bin/sppio-server
