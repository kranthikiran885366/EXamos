#!/bin/bash
set -e

echo "=========================================================="
echo " Starting Secure Physical Proctoring & Isolation OS (SPPIO)"
echo " Core Enterprise Backend on Render Cloud"
echo "=========================================================="

# 1. Deployment mode & posture (explicit development mode for cloud containers)
export EXAMOS_TPM_MODE="${EXAMOS_TPM_MODE:-development}"
export EXAMOS_ALLOW_UNPROVISIONED_DEV="${EXAMOS_ALLOW_UNPROVISIONED_DEV:-1}"
export EXAMOS_DEV_DISABLE_MFA="${EXAMOS_DEV_DISABLE_MFA:-1}"

# 2. Port mapping (Render sets $PORT, default to 10000 on Render free tier)
if [ -n "$PORT" ]; then
    export EXAMOS_SERVER_PORT="$PORT"
    export EXAMOS_PORT="$PORT"
elif [ -z "$EXAMOS_SERVER_PORT" ]; then
    export EXAMOS_SERVER_PORT="10000"
    export EXAMOS_PORT="10000"
fi

# 3. Network bindings
export EXAMOS_BIND_ADDR="0.0.0.0"
export EXAMOS_TLS_TERMINATED="1"

# 4. CORS origin (allows Vercel frontend to query the API)
if [ -z "$EXAMOS_CORS_ALLOWED_ORIGINS" ]; then
    export EXAMOS_CORS_ALLOWED_ORIGINS="https://sppio-os.vercel.app,http://localhost:5173,http://localhost:3000"
fi

# 5. Storage and ledger directories
export EXAMOS_DATA_DIR="${EXAMOS_DATA_DIR:-/var/lib/examos}"
export EXAMOS_LEDGER_PATH="${EXAMOS_LEDGER_PATH:-/var/lib/examos/ledger.log}"
export EXAMOS_EVENT_CHAIN_PATH="${EXAMOS_EVENT_CHAIN_PATH:-/var/lib/examos/events}"
mkdir -p "$EXAMOS_DATA_DIR" "$EXAMOS_EVENT_CHAIN_PATH" /tmp/examos /tmp/examos_secrets /var/log/examos /etc/examos

# 6. Configuration & Policy Catalogs
export EXAMOS_BROWSER_POLICY_CATALOG="${EXAMOS_BROWSER_POLICY_CATALOG:-/opt/sppio/config/browser_policies.json}"
export EXAMOS_DEVICES_CONFIG="${EXAMOS_DEVICES_CONFIG:-/opt/sppio/config/devices.json}"
export EXAMOS_RELEASES_CONFIG="${EXAMOS_RELEASES_CONFIG:-/opt/sppio/config/releases.json}"

# 7. Database URL mapping
if [ -n "$DATABASE_URL" ] && [ -z "$EXAMOS_DATABASE_URL" ]; then
    export EXAMOS_DATABASE_URL="$DATABASE_URL"
fi

# 7. Ensure all 5 required security tokens exist (32-128 chars alphanumeric)
if [ -z "$EXAMOS_AGENT_API_TOKEN" ]; then
    export EXAMOS_AGENT_API_TOKEN=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_PROCTOR_API_TOKEN" ]; then
    export EXAMOS_PROCTOR_API_TOKEN=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_EVENT_SIGNING_KEY" ]; then
    export EXAMOS_EVENT_SIGNING_KEY=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_VARIANT_SECRET" ]; then
    export EXAMOS_VARIANT_SECRET=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_LEDGER_HMAC_KEY" ]; then
    export EXAMOS_LEDGER_HMAC_KEY=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_EXAM_KEY_KEK" ]; then
    export EXAMOS_EXAM_KEY_KEK=$(openssl rand -hex 32)
fi

if [ -z "$EXAMOS_ADMIN_API_TOKEN" ]; then
    export EXAMOS_ADMIN_API_TOKEN=$(openssl rand -hex 32)
    echo "[SPPIO-Core] Generated ephemeral EXAMOS_ADMIN_API_TOKEN: $EXAMOS_ADMIN_API_TOKEN"
fi

echo "[SPPIO-Core] Mode: $EXAMOS_TPM_MODE"
echo "[SPPIO-Core] Listening on: 0.0.0.0:$EXAMOS_SERVER_PORT"
echo "[SPPIO-Core] CORS Allowed Origins: $EXAMOS_CORS_ALLOWED_ORIGINS"

# 8. Run database migrations if database URL is provisioned
if [ -n "$EXAMOS_DATABASE_URL" ]; then
    export EXAMOS_DATABASE_URL_FILE="/tmp/examos_secrets/db_url"
    export EXAMOS_MIGRATION_DATABASE_URL_FILE="/tmp/examos_secrets/db_url"
    printf "%s" "$EXAMOS_DATABASE_URL" > "$EXAMOS_DATABASE_URL_FILE"
    chmod 0600 "$EXAMOS_DATABASE_URL_FILE"

    echo "[SPPIO-Core] Checking and applying database migrations..."
    if [ -x /usr/local/bin/sppio-db-migrate ] && [ -d /opt/sppio/migrations ]; then
        /usr/local/bin/sppio-db-migrate /opt/sppio/migrations || true
    fi

    # 9. Seed administrative platform accounts (root, admin)
    if command -v psql >/dev/null 2>&1 && [ -f /opt/sppio/seed_admin_users.sql ]; then
        echo "[SPPIO-Core] Seeding administrative platform accounts..."
        psql "$EXAMOS_DATABASE_URL" -f /opt/sppio/seed_admin_users.sql || true
    fi
fi

# 10. Hand off to native C server binary
exec /usr/local/bin/sppio-server
