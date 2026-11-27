#!/usr/bin/env bash
# ExamOS / sppio-core — Automated Daily Encrypted PostgreSQL Backup
# Dumps PostgreSQL database with pg_dump (custom format), encrypts with
# AES-256-CBC + PBKDF2 using EXAMOS_BACKUP_PASSPHRASE_FILE, writes SHA-256
# checksum, and prunes backups older than RETENTION_DAYS.
set -euo pipefail

BACKUP_DIR="${EXAMOS_DB_BACKUP_DIR:-/var/backups/examos/postgres}"
RETENTION_DAYS="${EXAMOS_DB_BACKUP_RETENTION_DAYS:-30}"
PASSPHRASE_FILE="${EXAMOS_BACKUP_PASSPHRASE_FILE:-/etc/examos/backup.passphrase}"
DATABASE_URL="${DATABASE_URL:-}"

[ -n "$DATABASE_URL" ] || { echo "[DB-Backup] ERROR: DATABASE_URL is not set" >&2; exit 1; }
[ -r "$PASSPHRASE_FILE" ] || { echo "[DB-Backup] ERROR: Passphrase file unreadable: $PASSPHRASE_FILE" >&2; exit 1; }

umask 077
mkdir -p "$BACKUP_DIR"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TMP_DUMP=$(mktemp "${BACKUP_DIR}/sppio-${STAMP}.dump.XXXXXX")
ENC_FILE="${BACKUP_DIR}/sppio-${STAMP}.dump.enc"
trap 'rm -f "$TMP_DUMP"' EXIT

pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" -f "$TMP_DUMP"
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
    -in "$TMP_DUMP" -out "${ENC_FILE}.tmp" -pass "file:${PASSPHRASE_FILE}"
mv -f "${ENC_FILE}.tmp" "$ENC_FILE"
sha256sum "$ENC_FILE" > "${ENC_FILE}.sha256"
chmod 600 "$ENC_FILE" "${ENC_FILE}.sha256"

find "$BACKUP_DIR" -type f \( -name 'sppio-*.dump.enc' -o -name 'sppio-*.dump.enc.sha256' \) \
    -mtime "+${RETENTION_DAYS}" -delete

echo "[DB-Backup] Encrypted backup complete: $ENC_FILE"
