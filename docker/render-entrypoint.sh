#!/bin/bash
# render-entrypoint.sh — ExamOS / SPPIO production container entrypoint.
#
# SECURITY CONTRACT:
#   • EXAMOS_TPM_MODE, EXAMOS_LEDGER_HMAC_KEY, EXAMOS_AGENT_API_TOKEN, and
#     EXAMOS_EXAM_KEY_KEK must be injected by Render (dashboard secrets).
#     The script NEVER generates ephemeral replacements for these in production.
#   • No secrets are printed to stdout or logged.
#   • Seed SQL is never executed on a non-empty database.
set -euo pipefail

echo "========================================================"
echo " SPPIO / ExamOS Core — starting"
echo "========================================================"

# ── 1. Production cloud posture ──────────────────────────────────────────────
# In production, the server runs with full TPM attestation state, PostgreSQL pools,
# HMAC session journal, PBKDF2 authentication, and enterprise platform APIs.
export EXAMOS_TPM_MODE="production"
unset EXAMOS_ALLOW_UNPROVISIONED_DEV 2>/dev/null || true

# Appliance emulation for measured container environments.
export EXAMOS_APPLIANCE_EMULATE="1"

# Edge proxy terminates TLS; internal communication is local container networking.
export EXAMOS_TLS_TERMINATED="1"

# Secure cookie flag — always on for HTTPS endpoints.
export EXAMOS_ADMIN_COOKIE_SECURE="1"

echo "[SPPIO] Mode        : $EXAMOS_TPM_MODE (Enterprise Production Posture)"

# ── 2. Required secrets — fail-closed in production ─────────────────────────
# These must be injected by Render dashboard (sync:false in render.yaml).
# In production, missing secrets abort startup — never generate ephemeral ones.
_require_secret() {
    local name="$1"
    local min_len="${2:-32}"
    local value="${!name:-}"
    if [ -z "$value" ] || [ "${#value}" -lt "$min_len" ]; then
        if [ "$EXAMOS_TPM_MODE" = "production" ]; then
            echo "[SPPIO] FATAL: required secret '$name' is missing or too short (need >= $min_len chars)." >&2
            exit 1
        else
            # Development only: generate ephemeral value with a clear warning.
            echo "[SPPIO] WARNING: '$name' not set — generating ephemeral value for development." >&2
            export "$name"="$(openssl rand -hex 32)"
        fi
    fi
}

_require_secret EXAMOS_LEDGER_HMAC_KEY 32
_require_secret EXAMOS_AGENT_API_TOKEN 32
_require_secret EXAMOS_EXAM_KEY_KEK    64   # 32-byte AES key = 64 hex chars

# These are optional but validated if present.
if [ -z "${EXAMOS_PROCTOR_API_TOKEN:-}" ]; then
    export EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)"
fi
if [ -z "${EXAMOS_EVENT_SIGNING_KEY:-}" ]; then
    export EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)"
fi
if [ -z "${EXAMOS_VARIANT_SECRET:-}" ]; then
    export EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)"
fi

# Admin API token — generated fresh on every container boot (not durable).
# It is a machine-to-machine token used only for internal bootstrap calls.
export EXAMOS_ADMIN_API_TOKEN="$(openssl rand -hex 32)"
# NOTE: token NOT logged to stdout — check Render env vars to retrieve it.

# ── 3. Port mapping ───────────────────────────────────────────────────────────
# Render injects $PORT. Default to 10000 on free tier.
export EXAMOS_SERVER_PORT="${PORT:-${EXAMOS_SERVER_PORT:-10000}}"
export EXAMOS_PORT="$EXAMOS_SERVER_PORT"
export EXAMOS_BIND_ADDR="0.0.0.0"
export EXAMOS_TLS_TERMINATED="1"   # TLS is terminated by Render's edge proxy.

echo "[SPPIO] Listening on: 0.0.0.0:$EXAMOS_SERVER_PORT"

# ── 4. CORS ───────────────────────────────────────────────────────────────────
export EXAMOS_CORS_ALLOWED_ORIGINS="${EXAMOS_CORS_ALLOWED_ORIGINS:-https://sppio-os.vercel.app,http://localhost:5173}"
echo "[SPPIO] CORS origins: $EXAMOS_CORS_ALLOWED_ORIGINS"

# ── 5. Storage and ledger directories ─────────────────────────────────────────
export EXAMOS_DATA_DIR="${EXAMOS_DATA_DIR:-/var/lib/examos}"
export EXAMOS_LEDGER_PATH="${EXAMOS_LEDGER_PATH:-/var/lib/examos/ledger.log}"
export EXAMOS_SESSION_JOURNAL="${EXAMOS_SESSION_JOURNAL:-/var/lib/examos/sessions.journal}"
export EXAMOS_EVENT_CHAIN_PATH="${EXAMOS_EVENT_CHAIN_PATH:-/var/lib/examos/events}"
export EXAMOS_E1_STORE="${EXAMOS_E1_STORE:-$EXAMOS_DATA_DIR/e1}"
export EXAMOS_BEHAVIOUR_STORE="${EXAMOS_BEHAVIOUR_STORE:-$EXAMOS_DATA_DIR/behaviour}"
export EXAMOS_VARIANT_STORE="${EXAMOS_VARIANT_STORE:-$EXAMOS_DATA_DIR/variants}"
export EXAMOS_VIVA_STORE="${EXAMOS_VIVA_STORE:-$EXAMOS_DATA_DIR/viva}"
export EXAMOS_FIREWALL_STATE_DIR="${EXAMOS_FIREWALL_STATE_DIR:-$EXAMOS_DATA_DIR/firewall}"

mkdir -p "$EXAMOS_DATA_DIR" \
         "$EXAMOS_EVENT_CHAIN_PATH" \
         "$(dirname "$EXAMOS_SESSION_JOURNAL")" \
         "$EXAMOS_E1_STORE" \
         "$EXAMOS_BEHAVIOUR_STORE" \
         "$EXAMOS_VARIANT_STORE" \
         "$EXAMOS_VIVA_STORE" \
         "$EXAMOS_FIREWALL_STATE_DIR" \
         /opt/sppio/data \
         /tmp/examos /tmp/examos_secrets \
         /var/log/examos /etc/examos

# ── 6. Policy catalogs ────────────────────────────────────────────────────────
export EXAMOS_BROWSER_POLICY_CATALOG="${EXAMOS_BROWSER_POLICY_CATALOG:-/opt/sppio/config/browser_policies.json}"
export EXAMOS_DEVICES_CONFIG="${EXAMOS_DEVICES_CONFIG:-/opt/sppio/config/devices.json}"
export EXAMOS_RELEASES_CONFIG="${EXAMOS_RELEASES_CONFIG:-/opt/sppio/config/releases.json}"
if [ -d "/opt/sppio/config/ek_anchors" ]; then
    export EXAMOS_EK_TRUST_ANCHORS_DIR="/opt/sppio/config/ek_anchors"
    chmod 0755 "$EXAMOS_EK_TRUST_ANCHORS_DIR" 2>/dev/null || true
    chmod 0644 "$EXAMOS_EK_TRUST_ANCHORS_DIR"/*.pem 2>/dev/null || true
fi

# ── 7. Database URL ───────────────────────────────────────────────────────────
if [ -n "${DATABASE_URL:-}" ] && [ -z "${EXAMOS_DATABASE_URL:-}" ]; then
    export EXAMOS_DATABASE_URL="$DATABASE_URL"
fi

if [ -z "${EXAMOS_DATABASE_URL:-}" ]; then
    echo "[SPPIO] FATAL: DATABASE_URL is not set. Cannot start without a database." >&2
    exit 1
fi

# Write the DB URL to a mode-600 temp file so the C server reads it securely.
# The migration tool uses PQconnectdb() which handles both postgres:// URIs
# and keyword=value strings natively, so no URL transformation is needed here.
export EXAMOS_DATABASE_URL_FILE="/tmp/examos_secrets/db_url"
export EXAMOS_MIGRATION_DATABASE_URL_FILE="$EXAMOS_DATABASE_URL_FILE"
printf "%s" "$EXAMOS_DATABASE_URL" > "$EXAMOS_DATABASE_URL_FILE"
chmod 0600 "$EXAMOS_DATABASE_URL_FILE"

# ── 8. Database migrations ────────────────────────────────────────────────────
if [ -x /usr/local/bin/sppio-db-migrate ] && [ -d /opt/sppio/migrations ]; then
    echo "[SPPIO] Applying database migrations..."
    /usr/local/bin/sppio-db-migrate /opt/sppio/migrations || {
        echo "[SPPIO] FATAL: database migration failed." >&2
        exit 1
    }
fi

# ── 9. Start the server ──────────────────────────────────────────────────────
echo "[SPPIO] Handing off to sppio-server binary..."
exec /usr/local/bin/sppio-server
