#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do
    command -v "$tool" >/dev/null || {
        echo "Required tool missing: $tool" >&2
        exit 1
    }
done

PG_BIN="$(pg_config --bindir)"
[[ -x "$PG_BIN/initdb" && -x "$PG_BIN/pg_ctl" ]] || {
    echo "initdb and pg_ctl must be installed." >&2
    exit 1
}

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-tpm-migration-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"
cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=reject \
    --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" \
    -o "-p $PORT -k $TMP_DIR -c listen_addresses=''" \
    -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
export PGOPTIONS='-c client_min_messages=warning'
createdb --maintenance-db=postgres examos_tpm_migration_test
export PGDATABASE=examos_tpm_migration_test

psql -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE device_attestation_keys (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    key_name VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    public_key_pem TEXT NOT NULL
);
SQL

MIGRATION="$ROOT/server/migrations/044_tpm_credential_activation.sql"
psql -X -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
psql -X -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null

marker_count="$(psql -X -At -v ON_ERROR_STOP=1 \
    -c "SELECT COUNT(*) FROM examos_schema_migrations WHERE component='device_fleet' AND version=44")"
[[ "$marker_count" == "1" ]] || {
    echo "TPM activation migration marker was not recorded exactly once." >&2
    exit 1
}

psql -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO device_credential_activations
    (id, device_id, institution_id, ak_name_hex, credential_blob_hex,
     credential_secret_hash, status, expires_at)
VALUES
    ('activation-one', 'device-one', 'institution-one', repeat('0', 68),
     'aabb', repeat('a', 64), 'verifying', 9999999999999);
SQL

if psql -X -v ON_ERROR_STOP=1 -c \
    "INSERT INTO device_credential_activations
     (id,device_id,institution_id,ak_name_hex,credential_blob_hex,credential_secret_hash,status,expires_at)
     VALUES ('activation-two','device-one','institution-one',repeat('0',68),'aabb',repeat('b',64),'pending',9999999999999)" \
    >/dev/null 2>&1; then
    echo "Multiple open activation challenges for one device were accepted." >&2
    exit 1
fi

psql -X -At -v ON_ERROR_STOP=1 -c \
    "SELECT CASE WHEN
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_attestation_keys' AND column_name='ak_template_id')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_credential_activations' AND column_name='activation_error')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='device_credential_activations' AND column_name='activation_response_hex')
     THEN 'ok' ELSE 'bad' END" | grep -qx ok

echo "PASS: TPM activation schema is idempotent and enforces a single open challenge per device"
