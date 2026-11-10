#!/usr/bin/env bash
set -euo pipefail
umask 077

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || {
    echo "[VH-POSTGRES] BLOCKED: set EXAMOS_VH_RUN_DIR to an existing evidence run." >&2
    exit 2
}
[[ "$(id -u)" -ne 0 ]] || {
    echo "[VH-POSTGRES] BLOCKED: run as a non-root user for an isolated rootless PostgreSQL cluster." >&2
    exit 2
}

for tool in openssl python3 make cc psql pg_config; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[VH-POSTGRES] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

INITDB="$(find /usr/lib/postgresql -mindepth 3 -maxdepth 3 -type f -name initdb -print -quit 2>/dev/null || true)"
[[ -n "$INITDB" ]] || {
    echo "[VH-POSTGRES] BLOCKED: no local PostgreSQL initdb binary is installed." >&2
    exit 2
}
PG_BIN="$(dirname "$INITDB")"
for tool in "$PG_BIN/postgres" "$PG_BIN/pg_ctl" "$PG_BIN/createdb"; do
    [[ -x "$tool" ]] || {
        echo "[VH-POSTGRES] BLOCKED: PostgreSQL cluster utility is unavailable: $tool" >&2
        exit 2
    }
done

EVIDENCE="$RUN_DIR/postgres"
mkdir -m 700 -- "$EVIDENCE"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sppio-vh-postgres.XXXXXX")"
PG_STARTED=0
CURRENT_STAGE="PostgreSQL cluster setup"
PG_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
[[ "$PG_PORT" =~ ^[0-9]+$ ]] || {
    echo "[VH-POSTGRES] FAIL: could not allocate a loopback port." >&2
    exit 1
}
DB_PASSWORD="$(openssl rand -hex 32)"
PG_OS_USER="$(id -un)"

cleanup() {
    local rc=$?
    if [[ "$PG_STARTED" -eq 1 ]]; then
        "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m fast -w stop \
            >> "$EVIDENCE/cleanup.log" 2>&1 || rc=1
    fi
    rm -rf -- "$TMP_DIR"
    if [[ "$rc" -ne 0 ]]; then
        printf '[VH-POSTGRES] FAIL during %s (exit %s); inspect the matching file under %s.\n' \
            "$CURRENT_STAGE" "$rc" "$EVIDENCE" >&2
    fi
    return "$rc"
}
trap cleanup EXIT

mkdir -m 700 -- "$TMP_DIR/socket"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
    -subj "/CN=SPPIO Disposable PostgreSQL Test CA/" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$TMP_DIR/ca.key" -out "$TMP_DIR/ca.crt" \
    > "$EVIDENCE/tls-ca-generation.log" 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=127.0.0.1/" \
    -keyout "$TMP_DIR/server.key" -out "$TMP_DIR/server.csr" \
    > "$EVIDENCE/tls-server-generation.log" 2>&1
cat > "$TMP_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF
openssl x509 -req -sha256 -days 2 -in "$TMP_DIR/server.csr" \
    -CA "$TMP_DIR/ca.crt" -CAkey "$TMP_DIR/ca.key" -CAcreateserial \
    -extfile "$TMP_DIR/server.ext" -out "$TMP_DIR/server.crt" \
    > "$EVIDENCE/tls-certificate-signing.log" 2>&1
chmod 600 "$TMP_DIR/server.key"

CURRENT_STAGE="disposable PostgreSQL initialization"
"$INITDB" --no-locale --encoding=UTF8 --auth-local=trust \
    --auth-host=scram-sha-256 -D "$TMP_DIR/data" \
    > "$EVIDENCE/postgres-initdb.log" 2>&1
CURRENT_STAGE="TLS PostgreSQL startup"
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" \
    -o "-h 127.0.0.1 -p $PG_PORT -k $TMP_DIR/socket -c ssl=on -c ssl_cert_file=$TMP_DIR/server.crt -c ssl_key_file=$TMP_DIR/server.key" \
    -l "$EVIDENCE/postgres-server.log" -w start \
    > "$EVIDENCE/postgres-start.log" 2>&1
PG_STARTED=1

CURRENT_STAGE="isolated database and role creation"
cat > "$TMP_DIR/bootstrap.sql" <<SQL
CREATE ROLE examos_vh_app LOGIN PASSWORD '$DB_PASSWORD';
CREATE DATABASE examos_vh OWNER examos_vh_app;
SQL
chmod 600 "$TMP_DIR/bootstrap.sql"
psql -X --no-psqlrc -h "$TMP_DIR/socket" -p "$PG_PORT" -U "$PG_OS_USER" \
    -d postgres -v ON_ERROR_STOP=1 -f "$TMP_DIR/bootstrap.sql" \
    > "$EVIDENCE/postgres-bootstrap.log" 2>&1

CONN_FILE="$TMP_DIR/database-url"
printf 'host=127.0.0.1 port=%s dbname=examos_vh user=examos_vh_app sslmode=verify-full sslrootcert=%s connect_timeout=3\n' \
    "$PG_PORT" "$TMP_DIR/ca.crt" > "$CONN_FILE"
chmod 600 "$CONN_FILE"
PGPASSFILE="$TMP_DIR/pgpass"
printf '127.0.0.1:%s:examos_vh:examos_vh_app:%s\n' "$PG_PORT" "$DB_PASSWORD" > "$PGPASSFILE"
chmod 600 "$PGPASSFILE"
export PGPASSFILE
PSQL_CONN="host=127.0.0.1 port=$PG_PORT dbname=examos_vh user=examos_vh_app sslmode=verify-full sslrootcert=$TMP_DIR/ca.crt connect_timeout=3"
unset DATABASE_URL PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD
unset EXAMOS_DATABASE_URL EXAMOS_MIGRATION_DATABASE_URL_FILE
export EXAMOS_DATABASE_URL_FILE="$CONN_FILE"

CURRENT_STAGE="backend build"
make -C "$WORKSPACE/server" BUILD_DIR="$TMP_DIR/build" all \
    > "$EVIDENCE/backend-build.log" 2>&1
CURRENT_STAGE="backend base-schema bootstrap"
mapfile -d '' -t OBJECTS < <(
    find "$TMP_DIR/build" -type f -name '*.o' ! -path "$TMP_DIR/build/main.o" -print0 | sort -z
)
[[ "${#OBJECTS[@]}" -gt 1 ]] || {
    echo "[VH-POSTGRES] FAIL: backend test object files were not built." >&2
    exit 1
}
PG_INCLUDEDIR="$(pg_config --includedir)"
PG_LIBDIR="$(pg_config --libdir)"
cc -Wall -Wextra -O2 -I"$WORKSPACE/server/include" -I"$WORKSPACE/server/db" \
    -I"$WORKSPACE/server/security" -I"$WORKSPACE/server/audit" \
    -I"$WORKSPACE/server/controllers" -I"$WORKSPACE/common/include" \
    -I"$PG_INCLUDEDIR" -DUSE_OPENSSL_TLS -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong -Dmain=examos_server_main \
    -c "$WORKSPACE/server/main.c" -o "$TMP_DIR/server-main-bootstrap.o" \
    > "$EVIDENCE/schema-bootstrap-main-build.log" 2>&1
cc -Wall -Wextra -I"$WORKSPACE/server/include" -I"$WORKSPACE/server" \
    -I"$PG_INCLUDEDIR" "$WORKSPACE/tests/server/postgres-schema-bootstrap-test.c" \
    "${OBJECTS[@]}" "$TMP_DIR/server-main-bootstrap.o" \
    -L"$PG_LIBDIR" -lssl -lcrypto -lpthread -lpq -lm \
    -o "$TMP_DIR/postgres-schema-bootstrap-test" \
    > "$EVIDENCE/schema-bootstrap-test-build.log" 2>&1
EXAMOS_DATABASE_URL_FILE="$CONN_FILE" "$TMP_DIR/postgres-schema-bootstrap-test" \
    > "$EVIDENCE/backend-schema-bootstrap.log" 2>&1
CURRENT_STAGE="schema migration application"
"$TMP_DIR/build/examos-db-migrate" "$WORKSPACE/server/migrations" \
    > "$EVIDENCE/migrations-first-run.log" 2>&1

checksum_query="SELECT component || '|' || version || '|' || sha256 FROM examos_schema_migration_checksums ORDER BY component,version"
psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    --command="$checksum_query" > "$EVIDENCE/migration-checksums-before.txt"
expected_migration_count="$(find "$WORKSPACE/server/migrations" -maxdepth 1 \
    -type f -name '[0-9][0-9][0-9]_*.sql' -print | wc -l | tr -d '[:space:]')"
migration_count="$(psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align --command='SELECT count(*) FROM examos_schema_migrations')"
[[ "$expected_migration_count" =~ ^[1-9][0-9]*$ ]] || {
    echo "[VH-POSTGRES] FAIL: no numbered SQL migrations were found." >&2
    exit 1
}
[[ "$migration_count" == "$expected_migration_count" ]] || {
    echo "[VH-POSTGRES] FAIL: expected $expected_migration_count applied migrations; got $migration_count." >&2
    exit 1
}
CURRENT_STAGE="migration idempotency"
"$TMP_DIR/build/examos-db-migrate" "$WORKSPACE/server/migrations" \
    > "$EVIDENCE/migrations-idempotent-rerun.log" 2>&1
psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    --command="$checksum_query" > "$EVIDENCE/migration-checksums-after.txt"
cmp "$EVIDENCE/migration-checksums-before.txt" "$EVIDENCE/migration-checksums-after.txt"

cc -Wall -Wextra -I"$WORKSPACE/server/include" -I"$PG_INCLUDEDIR" \
    "$WORKSPACE/tests/server/postgres-auth-e2e-test.c" \
    "${OBJECTS[@]}" "$TMP_DIR/server-main-bootstrap.o" \
    -L"$PG_LIBDIR" -lssl -lcrypto -lpthread -lpq -lm \
    -o "$TMP_DIR/postgres-auth-e2e-test" \
    > "$EVIDENCE/auth-test-build.log" 2>&1
CURRENT_STAGE="authentication create/update/read"
EXAMOS_DATABASE_URL_FILE="$CONN_FILE" "$TMP_DIR/postgres-auth-e2e-test" \
    > "$EVIDENCE/auth-crud-update-read.log" 2>&1

rollback_name="sppio_vh_rollback_probe_$(openssl rand -hex 6)"
set +e
psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=0 > "$EVIDENCE/rollback-test.log" 2>&1 <<SQL
BEGIN;
CREATE TABLE public.$rollback_name (id integer PRIMARY KEY);
INSERT INTO public.$rollback_name VALUES (1);
SELECT 1 / 0;
ROLLBACK;
SQL
rollback_rc=$?
set -e
grep -qi 'division by zero' "$EVIDENCE/rollback-test.log" || {
    echo "[VH-POSTGRES] FAIL: deliberately failing transaction did not reach the expected SQL error." >&2
    exit 1
}
rolled_back="$(psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command="SELECT to_regclass('public.$rollback_name') IS NULL")"
[[ "$rolled_back" == "t" ]] || {
    echo "[VH-POSTGRES] FAIL: failed transaction left its probe table behind." >&2
    exit 1
}
printf 'psql_exit_code=%s\nprobe_table_absent=%s\n' "$rollback_rc" "$rolled_back" \
    > "$EVIDENCE/rollback-verification.txt"

CURRENT_STAGE="PostgreSQL stop and restart"
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m fast -w stop \
    > "$EVIDENCE/postgres-restart-stop.log" 2>&1
PG_STARTED=0
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" \
    -o "-h 127.0.0.1 -p $PG_PORT -k $TMP_DIR/socket -c ssl=on -c ssl_cert_file=$TMP_DIR/server.crt -c ssl_key_file=$TMP_DIR/server.key" \
    -l "$EVIDENCE/postgres-server.log" -w start \
    > "$EVIDENCE/postgres-restart-start.log" 2>&1
PG_STARTED=1
CURRENT_STAGE="authentication persistence after restart"
EXAMOS_DATABASE_URL_FILE="$CONN_FILE" "$TMP_DIR/postgres-auth-e2e-test" \
    --verify-persistence > "$EVIDENCE/auth-persistence-after-restart.log" 2>&1

CURRENT_STAGE="attestation database integration"
cc -Wall -Wextra -I"$PG_INCLUDEDIR" \
    "$WORKSPACE/tests/server/attestation_db_integration_test.c" \
    -L"$PG_LIBDIR" -lssl -lcrypto -lpq \
    -o "$TMP_DIR/attestation-db-integration-test" \
    > "$EVIDENCE/attestation-test-build.log" 2>&1
EXAMOS_DATABASE_URL_FILE="$CONN_FILE" "$TMP_DIR/attestation-db-integration-test" \
    > "$EVIDENCE/attestation-database-integration.log" 2>&1

python3 - "$EVIDENCE" "$migration_count" "$PG_PORT" "$PG_BIN" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

directory = pathlib.Path(sys.argv[1])
record = {
    "schema": "sppio.virtual-hardware.postgres.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "database_target": "disposable local PostgreSQL; loopback only",
    "database_name": "examos_vh",
    "postgresql_bin_directory": sys.argv[4],
    "port": int(sys.argv[3]),
    "migrations_applied": int(sys.argv[2]),
    "backend_base_schema_bootstrap": "PASS",
    "migration_rerun_checksums_unchanged": "PASS",
    "transaction_rollback_after_sql_error": "PASS",
    "schema_migration_rollback": "NOT TESTED: this migration runner has no down-migration operation",
    "auth_create_update_read": "PASS",
    "updated_account_login_after_server_restart": "PASS",
    "attestation_challenge_replay_revocation_and_rollback": "PASS",
    "production_database_touched": False,
    "database_url_or_password_in_report": False,
}
with (directory / "postgres-results.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-POSTGRES] PASS: TLS-only local PostgreSQL, all %s migrations, idempotency, rollback, auth CRUD/update/read, restart persistence, and attestation DB tests.\n' \
    "$migration_count"
