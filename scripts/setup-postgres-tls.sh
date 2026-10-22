#!/usr/bin/env bash
set -euo pipefail

echo "=== Setting up PostgreSQL SSL and ExamOS Database ==="

if [ "$(id -u)" -ne 0 ]; then
  echo "This setup must run as root." >&2
  exit 1
fi

mapfile -t PG_CLUSTER_ROWS < <(
  pg_lsclusters --no-header | awk \
    -v want_version="${EXAMOS_POSTGRES_VERSION:-}" \
    -v want_cluster="${EXAMOS_POSTGRES_CLUSTER:-}" \
    -v want_port="${EXAMOS_POSTGRES_PORT:-}" \
    '$4 != "down" && (!want_version || $1 == want_version) &&
     (!want_cluster || $2 == want_cluster) && (!want_port || $3 == want_port) { print }'
)
if [ "${#PG_CLUSTER_ROWS[@]}" -ne 1 ]; then
  echo "Expected exactly one active PostgreSQL cluster; found ${#PG_CLUSTER_ROWS[@]}. Set EXAMOS_POSTGRES_VERSION, EXAMOS_POSTGRES_CLUSTER, or EXAMOS_POSTGRES_PORT to select one." >&2
  exit 1
fi
read -r PG_VERSION PG_CLUSTER PG_PORT PG_STATUS PG_OWNER PG_DATA PG_LOG <<< "${PG_CLUSTER_ROWS[0]}"
if [ -z "$PG_VERSION" ] || [ -z "$PG_CLUSTER" ] || [ -z "$PG_PORT" ] || [ -z "$PG_DATA" ]; then
  echo "PostgreSQL cluster discovery returned incomplete configuration." >&2
  exit 1
fi
PG_CONFIG_DIR="/etc/postgresql/$PG_VERSION/$PG_CLUSTER"
umask 077
for validity in "${EXAMOS_DB_CA_VALIDITY_DAYS:-397}" "${EXAMOS_DB_CERT_VALIDITY_DAYS:-397}"; do
  [[ "$validity" =~ ^[1-9][0-9]{0,2}$ ]] && (( 10#$validity <= 397 )) || {
    echo "Certificate validity must be between 1 and 397 days." >&2
    exit 1
  }
done
DB_PASSWORD="$(openssl rand -hex 32)"
export -n DB_PASSWORD
install -d -m 0755 /run/examos
rm -f -- /run/examos/db_password
rm -f -- /run/examos/postgres-ready
printf '%s\n' "$DB_PASSWORD" > /run/examos/db_password
chmod 0600 /run/examos/db_password
DB_SETUP_SQL="$(mktemp /run/examos-db-setup.XXXXXX.sql)"
SERVER_REQ="$(mktemp /run/examos-db-server.XXXXXX.req)"
SERVER_EXT="$(mktemp /run/examos-db-server.XXXXXX.cnf)"
HBA_RULES="$(mktemp /run/examos-pg-hba-rules.XXXXXX)"
HBA_TEMP=""
DB_CONFIG_TEMP=""
cleanup() {
  rm -f -- "$DB_SETUP_SQL" "$SERVER_REQ" "$SERVER_EXT" "$HBA_RULES"
  [ -z "$HBA_TEMP" ] || rm -f -- "$HBA_TEMP"
  [ -z "$DB_CONFIG_TEMP" ] || rm -f -- "$DB_CONFIG_TEMP"
  unset DB_PASSWORD
}
trap cleanup EXIT
chmod 0600 "$DB_SETUP_SQL"

mkdir -p /etc/examos/certs /etc/examos/secrets
chmod 0750 /etc/examos
chmod 0700 /etc/examos/certs /etc/examos/secrets

# Generate DB CA if not already present. Never silently reuse an incomplete pair.
if [ -e /etc/examos/certs/db-ca.crt ] || [ -e /etc/examos/certs/db-ca.key ]; then
    if [ ! -s /etc/examos/certs/db-ca.crt ] || [ ! -s /etc/examos/certs/db-ca.key ]; then
      echo "Existing database CA certificate/key pair is incomplete." >&2
      exit 1
    fi
else
    openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -days "${EXAMOS_DB_CA_VALIDITY_DAYS:-397}" -nodes \
      -out /etc/examos/certs/db-ca.crt \
      -keyout /etc/examos/certs/db-ca.key \
      -subj "/CN=127.0.0.1"
fi
chmod 0600 /etc/examos/certs/db-ca.key
chmod 0644 /etc/examos/certs/db-ca.crt

# Generate PostgreSQL Server cert signed by CA
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -out "$SERVER_REQ" \
  -keyout /etc/examos/certs/server.key \
  -subj "/CN=127.0.0.1"

cat > "$SERVER_EXT" <<'EOF'
[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

openssl x509 -req -in "$SERVER_REQ" -days "${EXAMOS_DB_CERT_VALIDITY_DAYS:-397}" \
  -CA /etc/examos/certs/db-ca.crt -CAkey /etc/examos/certs/db-ca.key -CAcreateserial \
  -out /etc/examos/certs/server.crt \
  -extfile "$SERVER_EXT" -extensions v3_req

# Install certs into postgres data directory
cp /etc/examos/certs/server.crt "$PG_DATA/server.crt"
cp /etc/examos/certs/server.key "$PG_DATA/server.key"
cp /etc/examos/certs/db-ca.crt "$PG_DATA/root.crt"
chown postgres:postgres "$PG_DATA/server.crt" "$PG_DATA/server.key" "$PG_DATA/root.crt"
chmod 0600 "$PG_DATA/server.key"
chmod 0644 "$PG_DATA/server.crt" "$PG_DATA/root.crt"
chmod 0644 /etc/examos/certs/db-ca.crt
rm -f -- /etc/examos/certs/server.key

# Configure postgresql.conf
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set listen_addresses "127.0.0.1"
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set ssl on
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set ssl_min_protocol_version "TLSv1.2"
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set ssl_cert_file "$PG_DATA/server.crt"
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set ssl_key_file "$PG_DATA/server.key"
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set ssl_ca_file "$PG_DATA/root.crt"
pg_conftool "$PG_VERSION" "$PG_CLUSTER" set password_encryption "scram-sha-256"

# Configure pg_hba.conf
HBA="$PG_CONFIG_DIR/pg_hba.conf"
[ -f "$HBA" ] && [ ! -L "$HBA" ] || { echo "PostgreSQL host-auth file is missing or unsafe." >&2; exit 1; }
HBA_TEMP="$(mktemp "$PG_CONFIG_DIR/.pg_hba.XXXXXX")"
cat > "$HBA_RULES" <<'HBAEOF'
hostnossl all all 127.0.0.1/32 reject
hostssl examos_db examos 127.0.0.1/32 scram-sha-256
hostssl examos_test_db examos 127.0.0.1/32 scram-sha-256
host all all 127.0.0.1/32 reject
hostnossl all all ::1/128 reject
host all all ::1/128 reject
HBAEOF
if ! head -n 6 "$HBA" | cmp -s - "$HBA_RULES"; then
  cat "$HBA_RULES" "$HBA" > "$HBA_TEMP"
  chown postgres:postgres "$HBA_TEMP"
  chmod 0640 "$HBA_TEMP"
  mv -f -- "$HBA_TEMP" "$HBA"
fi
rm -f -- "$HBA_RULES"

pg_ctlcluster "$PG_VERSION" "$PG_CLUSTER" restart

# Provision user & databases
cat > "$DB_SETUP_SQL" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'examos') THEN
    CREATE ROLE examos LOGIN;
  END IF;
END
\$\$;
ALTER ROLE examos WITH LOGIN PASSWORD '$DB_PASSWORD';
SELECT 'CREATE DATABASE examos_db OWNER examos' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'examos_db') \gexec
SELECT 'CREATE DATABASE examos_test_db OWNER examos' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'examos_test_db') \gexec
ALTER DATABASE examos_db OWNER TO examos;
ALTER DATABASE examos_test_db OWNER TO examos;
SQL
su - postgres -c "psql -X -v ON_ERROR_STOP=1 -d postgres" < "$DB_SETUP_SQL"

# Store connection strings
DB_CONFIG_TEMP="$(mktemp /etc/examos/.db-connection.XXXXXX)"
printf 'host=127.0.0.1 port=%s dbname=examos_db user=examos sslmode=verify-full sslrootcert=/etc/examos/certs/db-ca.crt\n' \
  "$PG_PORT" > "$DB_CONFIG_TEMP"
chown root:root "$DB_CONFIG_TEMP"
chmod 0644 "$DB_CONFIG_TEMP"
mv -f -- "$DB_CONFIG_TEMP" /etc/examos/db-connection.conf
DB_CONFIG_TEMP=""
rm -f -- /etc/examos/secrets/db_url /etc/examos/secrets/test_db_url
unset DB_PASSWORD
printf '%s %s %s\n' "$PG_VERSION" "$PG_CLUSTER" "$PG_PORT" > /run/examos/postgres-ready
chmod 0600 /run/examos/postgres-ready

echo "=== PostgreSQL TLS and Databases Configured; password retained in tmpfs for TPM sealing ==="
