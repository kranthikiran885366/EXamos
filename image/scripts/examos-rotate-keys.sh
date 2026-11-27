#!/usr/bin/env bash
# ExamOS — Scheduled Key Rotation for EXAMOS_EXAM_KEY_KEK and EXAMOS_LEDGER_HMAC_KEY
# Preserves the previous key as *_PREV for zero-downtime verification of in-flight
# wrapped exam keys and historical ledger verification, then atomically swaps the
# environment file and reloads examos-server.
set -euo pipefail

ENV_FILE="${EXAMOS_KEY_ENV_FILE:-/etc/examos/keys.env}"
BACKUP_DIR="${EXAMOS_KEY_BACKUP_DIR:-/etc/examos/key-archive}"

umask 077
mkdir -p "$(dirname "$ENV_FILE")" "$BACKUP_DIR"

gen_hex_secret() {
    openssl rand -hex 32
}

OLD_KEK=""
OLD_HMAC=""
if [ -f "$ENV_FILE" ]; then
    OLD_KEK=$(grep -E '^EXAMOS_EXAM_KEY_KEK=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)
    OLD_HMAC=$(grep -E '^EXAMOS_LEDGER_HMAC_KEY=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)
    cp -p "$ENV_FILE" "$BACKUP_DIR/keys.env.$(date -u +%Y%m%dT%H%M%SZ)"
fi

NEW_KEK=$(gen_hex_secret)
NEW_HMAC=$(gen_hex_secret)

TMP_FILE=$(mktemp "${ENV_FILE}.XXXXXX")
trap 'rm -f "$TMP_FILE"' EXIT

{
    echo "# Rotated at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "EXAMOS_EXAM_KEY_KEK=${NEW_KEK}"
    if [ -n "$OLD_KEK" ]; then
        echo "EXAMOS_EXAM_KEY_KEK_PREV=${OLD_KEK}"
    fi
    echo "EXAMOS_LEDGER_HMAC_KEY=${NEW_HMAC}"
    if [ -n "$OLD_HMAC" ]; then
        echo "EXAMOS_LEDGER_HMAC_KEY_PREV=${OLD_HMAC}"
    fi
} > "$TMP_FILE"

chmod 600 "$TMP_FILE"
mv -f "$TMP_FILE" "$ENV_FILE"
trap - EXIT

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet examos-server.service; then
    systemctl reload-or-restart examos-server.service
fi

echo "[ExamOS-KeyRotate] Rotated EXAMOS_EXAM_KEY_KEK and EXAMOS_LEDGER_HMAC_KEY in $ENV_FILE"
