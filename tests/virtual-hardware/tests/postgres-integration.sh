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

for tool in openssl python3 make cc psql pg_config curl swtpm \
            tpm2_startup tpm2_createek tpm2_createak tpm2_readpublic; do
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
SERVER_PID=""
SWTPM_PID=""

cleanup() {
    local rc=$?
    if [[ -n "$SERVER_PID" ]]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$SWTPM_PID" ]]; then
        kill -TERM "$SWTPM_PID" 2>/dev/null || true
        wait "$SWTPM_PID" 2>/dev/null || true
    fi
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
EXAMOS_DATABASE_URL_FILE="$CONN_FILE" "$TMP_DIR/build/examos-server" --bootstrap-schema-only \
    > "$EVIDENCE/backend-schema-bootstrap.log" 2>&1
CURRENT_STAGE="schema migration application"
"$TMP_DIR/build/examos-db-migrate" "$WORKSPACE/server/migrations" \
    > "$EVIDENCE/migrations-first-run.log" 2>&1

checksum_query="SELECT component || '|' || version || '|' || sha256 FROM examos_schema_migration_checksums ORDER BY component,version"
psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
    --command="$checksum_query" > "$EVIDENCE/migration-checksums-before.txt"
expected_migration_count="$(python3 - "$WORKSPACE/server/admin/db_migrate.c" \
    "$WORKSPACE/server/migrations" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
registered = re.findall(r'^\s*\{"([^"]+\.sql)",', source, re.MULTILINE)
if not registered:
    raise SystemExit("No numbered SQL migrations are registered.")
if len(registered) != len(set(registered)):
    raise SystemExit("The migration registry contains duplicate filenames.")
files = sorted(path.name for path in pathlib.Path(sys.argv[2]).glob("*.sql"))
unregistered = sorted(set(files) - set(registered))
missing = sorted(set(registered) - set(files))
if unregistered or missing:
    raise SystemExit(
        f"Migration registry/file mismatch: unregistered={unregistered}, missing={missing}"
    )
print(len(registered))
PY
)"
migration_count="$(psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align --command='SELECT count(*) FROM examos_schema_migrations')"
[[ "$expected_migration_count" =~ ^[1-9][0-9]*$ ]] || {
    echo "[VH-POSTGRES] FAIL: no numbered SQL migrations are registered." >&2
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

CURRENT_STAGE="virtual TPM device enrollment API"
mkdir -m 700 -- "$TMP_DIR/swtpm-state" "$TMP_DIR/server-data" "$TMP_DIR/server-log"
psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    > "$EVIDENCE/device-enrollment-fixture.log" 2>&1 <<'SQL'
INSERT INTO tenants (id, name, code, created_at, created_by, entity_type)
VALUES ('INST-UNIV-01', 'Disposable Virtual TPM Test Institution',
        'VH-TEST-INST', EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000,
        'virtual-hardware-test', 'university');
INSERT INTO device_trust_policies
    (id, institution_id, policy_name, version, require_registration,
     require_admin_approval, require_tpm, require_secure_boot,
     require_approved_release, max_evidence_age_sec, status, approved_by,
     approved_at, activated_at, created_at, updated_at, created_by)
VALUES
    ('vh-test-device-policy', 'INST-UNIV-01', 'Disposable Virtual TPM Test',
     1, TRUE, FALSE, TRUE, TRUE, TRUE, 600, 'active', 'virtual-hardware-test',
     EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000,
     EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000,
     EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000,
     EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000,
     'virtual-hardware-test');
UPDATE examos_admin_users
SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = TRUE
WHERE user_id = 'USR-INST-ADMIN-4';
SQL
[[ "$(psql "$PSQL_CONN" --no-psqlrc --tuples-only --no-align \
    --command="SELECT count(*) FROM examos_admin_users WHERE user_id='USR-INST-ADMIN-4' AND totp_secret='JBSWY3DPEHPK3PXP'")" == "1" ]] || {
    echo "[VH-POSTGRES] FAIL: disposable institution administrator fixture was not provisioned." >&2
    exit 1
}

TPM_SOCKET="$TMP_DIR/device-enrollment-swtpm.sock"
swtpm socket --tpm2 --tpmstate "dir=$TMP_DIR/swtpm-state" \
    --server "type=unixio,path=$TPM_SOCKET" \
    --ctrl "type=unixio,path=$TPM_SOCKET.ctrl" \
    --flags not-need-init,startup-clear \
    > "$EVIDENCE/device-enrollment-swtpm.log" 2>&1 &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:path=$TPM_SOCKET"
for _ in $(seq 1 50); do
    kill -0 "$SWTPM_PID" 2>/dev/null || {
        echo "[VH-POSTGRES] FAIL: disposable swtpm exited during startup." >&2
        exit 1
    }
    [[ -S "$TPM_SOCKET" && -S "$TPM_SOCKET.ctrl" ]] && break
    sleep 0.1
done
[[ -S "$TPM_SOCKET" && -S "$TPM_SOCKET.ctrl" ]] || {
    echo "[VH-POSTGRES] FAIL: disposable swtpm did not create its private sockets." >&2
    exit 1
}
tpm2_startup -c > "$EVIDENCE/device-enrollment-tpm-startup.log" 2>&1
tpm2_createek -c "$TMP_DIR/ek.ctx" -G rsa -R \
    > "$EVIDENCE/device-enrollment-ek-create.log" 2>&1
tpm2_createak -C "$TMP_DIR/ek.ctx" -c "$TMP_DIR/ak.ctx" \
    -G rsa -g sha256 -s rsassa -u "$TMP_DIR/ak.pub" \
    -n "$TMP_DIR/ak.name" -R \
    > "$EVIDENCE/device-enrollment-ak-create.log" 2>&1
tpm2_readpublic -c "$TMP_DIR/ak.ctx" -f pem -o "$TMP_DIR/ak.pem" \
    > "$EVIDENCE/device-enrollment-ak-read.log" 2>&1

DEVICE_ID="sppio-vh-local-device"
python3 - "$TMP_DIR/device-registration.json" "$TMP_DIR/ak.pub" \
    "$TMP_DIR/ak.name" "$TMP_DIR/ak.pem" "$DEVICE_ID" <<'PY'
import json
import pathlib
import sys

target, public_area, name, pem, device_id = sys.argv[1:]
def name_payload(data):
    if len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2:
        return data[2:]
    return data

record = {
    "device_id": device_id,
    "institution_id": "INST-UNIV-01",
    "hostname": "sppio-vh-local-device.test",
    "device_name": "Disposable virtual TPM test device",
    "device_category": "kiosk_appliance",
    "manufacturer": "swtpm virtual test fixture",
    "model": "Software TPM (test only)",
    "cpu_arch": "x86_64",
    "boot_mode": "UEFI-unverified",
    "secure_boot_state": "unknown",
    "tpm_present": True,
    "tpm_version": "2.0",
    "os_release_id": "virtual-test-only",
    "kernel_version": "not-booted",
    "ak_public_key_pem": pathlib.Path(pem).read_text(encoding="ascii"),
    "ak_public_area_hex": pathlib.Path(public_area).read_bytes().hex(),
    "ak_name_hex": name_payload(pathlib.Path(name).read_bytes()).hex(),
}
with pathlib.Path(target).open("x", encoding="utf-8") as stream:
    json.dump(record, stream, separators=(",", ":"))
    stream.write("\n")
PY

API_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
[[ "$API_PORT" =~ ^[0-9]+$ ]] || {
    echo "[VH-POSTGRES] FAIL: could not allocate a loopback API port." >&2
    exit 1
}
export EXAMOS_TPM_MODE=development
export EXAMOS_ALLOW_UNPROVISIONED_DEV=1
export EXAMOS_BIND_ADDR=127.0.0.1
export EXAMOS_SERVER_PORT="$API_PORT"
export EXAMOS_DATABASE_URL_FILE="$CONN_FILE"
export EXAMOS_AGENT_API_TOKEN="$(openssl rand -hex 32)"
export EXAMOS_PROCTOR_API_TOKEN="$(openssl rand -hex 32)"
export EXAMOS_EVENT_SIGNING_KEY="$(openssl rand -hex 32)"
export EXAMOS_VARIANT_SECRET="$(openssl rand -hex 32)"
export EXAMOS_LEDGER_HMAC_KEY="$(openssl rand -hex 32)"
export EXAMOS_LEDGER_PATH="$TMP_DIR/server-log/event-ledger.log"
export EXAMOS_SESSION_JOURNAL="$TMP_DIR/server-log/session-journal.log"
export EXAMOS_EVENT_CHAIN_PATH="$TMP_DIR/server-log/event-chain.log"
export EXAMOS_DATA_DIR="$TMP_DIR/server-data"
export EXAMOS_BROWSER_POLICY_CATALOG="$WORKSPACE/server/config/browser_policies.json"
export EXAMOS_DEVICES_CONFIG="$WORKSPACE/server/config/devices.json"
export EXAMOS_RELEASES_CONFIG="$WORKSPACE/server/config/releases.json"
"$TMP_DIR/build/examos-server" > "$EVIDENCE/device-enrollment-server.log" 2>&1 &
SERVER_PID=$!

server_ready=0
for _ in $(seq 1 50); do
    if curl --silent --show-error --fail \
        "http://127.0.0.1:$API_PORT/api/v1/health" \
        -o "$TMP_DIR/health-response.json" 2>/dev/null; then
        server_ready=1
        break
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.2
done
[[ "$server_ready" -eq 1 ]] || {
    echo "[VH-POSTGRES] FAIL: local development API did not become ready; inspect device-enrollment-server.log." >&2
    exit 1
}

python3 - "$TMP_DIR/api-mfa-code" <<'PY'
import base64
import hashlib
import hmac
import pathlib
import struct
import time

secret = base64.b32decode("JBSWY3DPEHPK3PXP")
counter = int(time.time()) // 30
digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 15
code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1_000_000
pathlib.Path(__import__("sys").argv[1]).write_text(f"{code:06d}", encoding="ascii")
PY
python3 - "$TMP_DIR/api-login.json" "$TMP_DIR/api-mfa-code" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "username": "institution_admin_1",
    "password": "InstitutionAdmin#2026!ExamOS",
    "mfa_code": pathlib.Path(sys.argv[2]).read_text(encoding="ascii").strip(),
}), encoding="utf-8")
PY
login_http="$(curl --silent --show-error --output "$TMP_DIR/api-login-response.json" \
    --write-out '%{http_code}' --request POST \
    --header 'Content-Type: application/json' \
    --data-binary "@$TMP_DIR/api-login.json" \
    "http://127.0.0.1:$API_PORT/api/v1/auth/login")"
[[ "$login_http" == "200" ]] || {
    echo "[VH-POSTGRES] FAIL: local institution-admin API login returned HTTP $login_http." >&2
    exit 1
}
python3 - "$TMP_DIR/api-login-response.json" "$TMP_DIR/api-curl.conf" <<'PY'
import json
import os
import pathlib
import re
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
token = response.get("token", "")
if response.get("status") != "AUTHENTICATED" or not re.fullmatch(r"[0-9a-f]{64}", token):
    raise SystemExit("Local API login did not return an authenticated session.")
path = pathlib.Path(sys.argv[2])
path.write_text(f'header = "Authorization: Bearer {token}"\n', encoding="ascii")
os.chmod(path, 0o600)
PY

registration_http="$(curl --silent --show-error --output "$TMP_DIR/device-registration-response.json" \
    --write-out '%{http_code}' --request POST \
    --config "$TMP_DIR/api-curl.conf" \
    --header 'Content-Type: application/json' \
    --data-binary "@$TMP_DIR/device-registration.json" \
    "http://127.0.0.1:$API_PORT/api/v1/devices/register")"
if [[ "$registration_http" != "201" ]]; then
    cp -- "$TMP_DIR/device-registration-response.json" \
        "$EVIDENCE/device-registration-error-response.json"
    echo "[VH-POSTGRES] FAIL: virtual device registration returned HTTP $registration_http." >&2
    cat "$TMP_DIR/device-registration-response.json" >&2
    exit 1
fi
python3 - "$TMP_DIR/device-registration-response.json" "$DEVICE_ID" <<'PY'
import json
import pathlib
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if response.get("status") != "registered" or response.get("device_id") != sys.argv[2]:
    raise SystemExit("Virtual device registration response did not match the test fixture.")
PY
cp -- "$TMP_DIR/device-registration-response.json" \
    "$EVIDENCE/device-registration-response.json"

device_read_http="$(curl --silent --show-error --output "$TMP_DIR/device-detail-response.json" \
    --write-out '%{http_code}' --config "$TMP_DIR/api-curl.conf" \
    "http://127.0.0.1:$API_PORT/api/v1/devices/$DEVICE_ID")"
[[ "$device_read_http" == "200" ]] || {
    echo "[VH-POSTGRES] FAIL: registered device read-back returned HTTP $device_read_http." >&2
    exit 1
}
python3 - "$TMP_DIR/device-detail-response.json" "$DEVICE_ID" <<'PY'
import json
import pathlib
import sys

device = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["device"]
if (device.get("id") != sys.argv[2] or
        device.get("institution_id") != "INST-UNIV-01" or
        device.get("status") != "registered" or
        device.get("tpm_present") is not True or
        device.get("secure_boot_state") != "unknown"):
    raise SystemExit("Device read-back did not preserve the expected virtual-only state.")
PY
cp -- "$TMP_DIR/device-detail-response.json" \
    "$EVIDENCE/device-detail-response.json"

attestation_challenge_http="$(curl --silent --show-error --output "$TMP_DIR/attestation-challenge-response.json" \
    --write-out '%{http_code}' --request POST \
    --config "$TMP_DIR/api-curl.conf" \
    --header 'Content-Type: application/json' \
    --data-binary '{}' \
    "http://127.0.0.1:$API_PORT/api/v1/devices/$DEVICE_ID/attestation/challenge")"
[[ "$attestation_challenge_http" == "409" ]] || {
    cp -- "$TMP_DIR/attestation-challenge-response.json" \
        "$EVIDENCE/attestation-challenge-unprovisioned-response.json"
    echo "[VH-POSTGRES] FAIL: attestation challenge without an approved registry entry returned HTTP $attestation_challenge_http instead of 409." >&2
    cat "$TMP_DIR/attestation-challenge-response.json" >&2
    exit 1
}

duplicate_http="$(curl --silent --show-error --output "$TMP_DIR/device-duplicate-response.json" \
    --write-out '%{http_code}' --request POST \
    --config "$TMP_DIR/api-curl.conf" \
    --header 'Content-Type: application/json' \
    --data-binary "@$TMP_DIR/device-registration.json" \
    "http://127.0.0.1:$API_PORT/api/v1/devices/register")"
[[ "$duplicate_http" == "409" ]] || {
    echo "[VH-POSTGRES] FAIL: duplicate device registration returned HTTP $duplicate_http instead of 409." >&2
    exit 1
}

python3 - "$TMP_DIR/device-registration.json" "$TMP_DIR/device-invalid-ak.json" <<'PY'
import json
import pathlib
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
source["device_id"] = "sppio-vh-invalid-ak"
area = source["ak_public_area_hex"]
source["ak_public_area_hex"] = ("00" if area[:2] != "00" else "01") + area[2:]
pathlib.Path(sys.argv[2]).write_text(json.dumps(source), encoding="utf-8")
PY
invalid_ak_http="$(curl --silent --show-error --output "$TMP_DIR/device-invalid-ak-response.json" \
    --write-out '%{http_code}' --request POST \
    --config "$TMP_DIR/api-curl.conf" \
    --header 'Content-Type: application/json' \
    --data-binary "@$TMP_DIR/device-invalid-ak.json" \
    "http://127.0.0.1:$API_PORT/api/v1/devices/register")"
[[ "$invalid_ak_http" == "400" ]] || {
    echo "[VH-POSTGRES] FAIL: malformed TPM AK public area returned HTTP $invalid_ak_http instead of 400." >&2
    exit 1
}
invalid_device_count="$(psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command="SELECT count(*) FROM devices WHERE id='sppio-vh-invalid-ak'")"
[[ "$invalid_device_count" == "0" ]] || {
    echo "[VH-POSTGRES] FAIL: rejected virtual device was persisted." >&2
    exit 1
}
device_state="$(psql "$PSQL_CONN" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command="SELECT d.status || '|' || k.status || '|' || k.provenance_status FROM devices d JOIN device_attestation_keys k ON k.device_id=d.id WHERE d.id='$DEVICE_ID'")"
[[ "$device_state" == "registered|active|template_valid" ]] || {
    echo "[VH-POSTGRES] FAIL: persisted device and AK state did not match the registration result." >&2
    exit 1
}

python3 - "$EVIDENCE/device-enrollment-api-results.json" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

record = {
    "schema": "sppio.virtual-hardware.device-enrollment-api.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "api_target": "loopback development server; disposable local PostgreSQL",
    "institution_admin_login": "PASS",
    "software_tpm_ak_created": "PASS",
    "registration": "PASS",
    "device_read_back": "PASS",
    "unregistered_attestation_challenge_rejected": "PASS",
    "duplicate_registration_rejected": "PASS",
    "malformed_ak_public_area_rejected_without_persistence": "PASS",
    "device_status": "registered",
    "ak_status": "active",
    "ak_provenance_status": "template_valid",
    "software_tpm_used": True,
    "physical_tpm_used": False,
    "physical_tpm_verified": False,
    "secure_boot_verified": False,
    "device_attestation_verified": False,
    "production_database_touched": False,
    "trust_anchor_provisioned": False,
}
with pathlib.Path(sys.argv[1]).open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

kill -TERM "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
kill -TERM "$SWTPM_PID"
wait "$SWTPM_PID" 2>/dev/null || true
SWTPM_PID=""
unset TPM2TOOLS_TCTI EXAMOS_TPM_MODE EXAMOS_ALLOW_UNPROVISIONED_DEV

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
    "virtual_device_registration_api": "PASS",
    "virtual_device_attestation_without_approved_registry": "REJECTED",
    "physical_tpm_verified": False,
    "production_database_touched": False,
    "database_url_or_password_in_report": False,
}
with (directory / "postgres-results.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-POSTGRES] PASS: TLS-only local PostgreSQL, all %s registered migrations, idempotency, rollback, auth CRUD/restart persistence, swtpm device registration/read-back, fail-closed challenge, and attestation DB tests.\n' \
    "$migration_count"
