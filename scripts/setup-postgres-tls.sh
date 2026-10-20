#!/usr/bin/env bash
set -euo pipefail

echo "=== Setting up PostgreSQL SSL and ExamOS Database ==="

mkdir -p /etc/examos/certs /etc/examos/secrets
chmod 0750 /etc/examos
chmod 0700 /etc/examos/certs /etc/examos/secrets

# Generate DB CA if not already present
if [ ! -f /etc/examos/certs/db-ca.crt ]; then
    openssl req -new -x509 -days 3650 -nodes \
      -out /etc/examos/certs/db-ca.crt \
      -keyout /etc/examos/certs/db-ca.key \
      -subj "/CN=127.0.0.1"
fi

# Generate PostgreSQL Server cert signed by CA
openssl req -new -nodes \
  -out /tmp/server.req \
  -keyout /etc/examos/certs/server.key \
  -subj "/CN=127.0.0.1"

cat > /tmp/server_ext.cnf <<'EOF'
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

openssl x509 -req -in /tmp/server.req -days 3650 \
  -CA /etc/examos/certs/db-ca.crt -CAkey /etc/examos/certs/db-ca.key -CAcreateserial \
  -out /etc/examos/certs/server.crt \
  -extfile /tmp/server_ext.cnf -extensions v3_req

rm -f /tmp/server.req /tmp/server_ext.cnf

# Install certs into postgres data directory
cp /etc/examos/certs/server.crt /var/lib/postgresql/18/main/server.crt
cp /etc/examos/certs/server.key /var/lib/postgresql/18/main/server.key
cp /etc/examos/certs/db-ca.crt /var/lib/postgresql/18/main/root.crt
chown postgres:postgres /var/lib/postgresql/18/main/server.crt /var/lib/postgresql/18/main/server.key /var/lib/postgresql/18/main/root.crt
chmod 0600 /var/lib/postgresql/18/main/server.key
chmod 0644 /var/lib/postgresql/18/main/server.crt /var/lib/postgresql/18/main/root.crt
chmod 0644 /etc/examos/certs/db-ca.crt

# Configure postgresql.conf
CONF="/etc/postgresql/18/main/postgresql.conf"
sed -i "s/^#listen_addresses = .*/listen_addresses = '127.0.0.1'/" "$CONF"
sed -i "s/^listen_addresses = .*/listen_addresses = '127.0.0.1'/" "$CONF"
sed -i "s/^ssl = .*/ssl = on/" "$CONF"
sed -i "s|^ssl_cert_file = .*|ssl_cert_file = '/var/lib/postgresql/18/main/server.crt'|" "$CONF"
sed -i "s|^ssl_key_file = .*|ssl_key_file = '/var/lib/postgresql/18/main/server.key'|" "$CONF"

grep -q "ssl_ca_file" "$CONF" || echo "ssl_ca_file = '/var/lib/postgresql/18/main/root.crt'" >> "$CONF"

# Configure pg_hba.conf
HBA="/etc/postgresql/18/main/pg_hba.conf"
grep -q "examos_db examos" "$HBA" || {
    echo "hostssl examos_db examos 127.0.0.1/32 scram-sha-256" >> "$HBA"
    echo "hostssl examos_test_db examos 127.0.0.1/32 scram-sha-256" >> "$HBA"
}

/usr/sbin/service postgresql restart

# Provision user & databases
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='examos'\" | grep -q 1 || psql -c \"CREATE USER examos WITH PASSWORD 'ExamOS_Secure_P0stgres_Password_2026';\""
su - postgres -c "psql -c \"ALTER USER examos WITH PASSWORD 'ExamOS_Secure_P0stgres_Password_2026';\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='examos_db'\" | grep -q 1 || psql -c \"CREATE DATABASE examos_db OWNER examos;\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='examos_test_db'\" | grep -q 1 || psql -c \"CREATE DATABASE examos_test_db OWNER examos;\""

# Store connection strings
cat > /etc/examos/secrets/db_url <<'EOF'
host=127.0.0.1 port=5432 dbname=examos_db user=examos password=ExamOS_Secure_P0stgres_Password_2026 sslmode=verify-full sslrootcert=/etc/examos/certs/db-ca.crt
EOF
chmod 0600 /etc/examos/secrets/db_url

cat > /etc/examos/secrets/test_db_url <<'EOF'
host=127.0.0.1 port=5432 dbname=examos_test_db user=examos password=ExamOS_Secure_P0stgres_Password_2026 sslmode=verify-full sslrootcert=/etc/examos/certs/db-ca.crt
EOF
chmod 0600 /etc/examos/secrets/test_db_url

echo "=== PostgreSQL TLS and Databases Configured Successfully ==="
