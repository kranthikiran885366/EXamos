set -eu

mkdir -p "$PGDATA"
cp /run/secrets/postgres_server_certificate /var/run/postgresql/server.crt
cp /run/secrets/postgres_server_private_key /var/run/postgresql/server.key
cp /run/secrets/postgres_app_password /var/run/postgresql/application-password
cp /run/secrets/postgres_root_certificate /var/run/postgresql/root-ca.crt
chown postgres:postgres /var/run/postgresql/server.crt \
  /var/run/postgresql/server.key /var/run/postgresql/application-password \
  /var/run/postgresql/root-ca.crt
chmod 0644 /var/run/postgresql/server.crt
chmod 0600 /var/run/postgresql/server.key
chmod 0400 /var/run/postgresql/application-password
chmod 0644 /var/run/postgresql/root-ca.crt

exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/run/postgresql/server.crt \
  -c ssl_key_file=/var/run/postgresql/server.key \
  -c ssl_min_protocol_version=TLSv1.2 \
  -c password_encryption=scram-sha-256 \
  -c log_connections=on \
  -c log_disconnections=on
