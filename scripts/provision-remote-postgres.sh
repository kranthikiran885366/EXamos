#!/usr/bin/env bash
# Provision an operator-owned PostgreSQL endpoint for a deployed appliance.
# This script never creates a database, account, CA, or credential.
set -euo pipefail
umask 077

fail() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail "Run as root on the target appliance."
[[ $# -eq 0 ]] || fail "Configuration is supplied through EXAMOS_DB_* environment variables."

for name in EXAMOS_DB_HOST EXAMOS_DB_PORT EXAMOS_DB_NAME EXAMOS_DB_USER \
            EXAMOS_DB_CA_FILE EXAMOS_DB_PASSWORD_FILE; do
    [[ -n ${!name:-} ]] || fail "$name must be provided by the deployment operator."
done

[[ $EXAMOS_DB_HOST =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || fail "Database host must be a DNS hostname."
[[ $EXAMOS_DB_HOST != localhost && $EXAMOS_DB_HOST != *.localhost ]] || fail "A remote database hostname is required."
[[ $EXAMOS_DB_PORT =~ ^[0-9]{1,5}$ ]] && (( 10#$EXAMOS_DB_PORT >= 1 && 10#$EXAMOS_DB_PORT <= 65535 )) || fail "Database port is invalid."
[[ $EXAMOS_DB_NAME =~ ^[A-Za-z0-9_]{1,63}$ ]] || fail "Database name has invalid characters."
[[ $EXAMOS_DB_USER =~ ^[A-Za-z0-9_]{1,63}$ ]] || fail "Database user has invalid characters."

[[ ! -L $EXAMOS_DB_CA_FILE && -f $EXAMOS_DB_CA_FILE ]] || fail "Database CA input must be a regular non-symlink file."
[[ ! -L $EXAMOS_DB_PASSWORD_FILE && -f $EXAMOS_DB_PASSWORD_FILE ]] || fail "Database password input must be a regular non-symlink file."
[[ $(stat -c %u -- "$EXAMOS_DB_CA_FILE") == 0 ]] || fail "Database CA file must be root-owned."
[[ $(stat -c %u -- "$EXAMOS_DB_PASSWORD_FILE") == 0 ]] || fail "Database password file must be root-owned."
(( (8#$(stat -c %a -- "$EXAMOS_DB_PASSWORD_FILE") & 0077) == 0 )) || fail "Database password file must be private (mode 0600 or stricter)."
[[ $(stat -c %s -- "$EXAMOS_DB_CA_FILE") -gt 0 && $(stat -c %s -- "$EXAMOS_DB_CA_FILE") -le 1048576 ]] || fail "Database CA file has an invalid size."
[[ $(stat -c %s -- "$EXAMOS_DB_PASSWORD_FILE") -gt 0 && $(stat -c %s -- "$EXAMOS_DB_PASSWORD_FILE") -le 129 ]] || fail "Database password file has an invalid size."
openssl x509 -in "$EXAMOS_DB_CA_FILE" -noout -checkend 0 >/dev/null || fail "Database CA certificate is invalid or expired."
openssl x509 -in "$EXAMOS_DB_CA_FILE" -noout -ext basicConstraints | grep -q 'CA:TRUE' || fail "Supplied certificate is not a CA certificate."

DB_PASSWORD=$(cat -- "$EXAMOS_DB_PASSWORD_FILE")
[[ $DB_PASSWORD =~ ^[A-Za-z0-9_-]{32,128}$ ]] || fail "Database password must be 32–128 base64url characters."
unset EXAMOS_DB_PASSWORD_FILE

install -d -o root -g root -m 0750 /etc/examos /etc/examos/certs /etc/examos/secrets /run/examos
for path in /etc/examos/remote-postgres-enabled /etc/examos/db-connection.conf \
            /etc/examos/certs/db-ca.crt /run/examos/db_password /run/examos/postgres-ready \
            /etc/systemd/system/examos-server.service.d/remote-postgres.conf; do
    [[ ! -e $path && ! -L $path ]] || fail "Existing database provisioning state found at $path; refusing to replace it."
done
if systemctl is-active --quiet examos-server.service; then fail "Stop the ExamOS server before provisioning its database endpoint."; fi

CA_TMP=$(mktemp /etc/examos/certs/.db-ca.XXXXXX)
CONFIG_TMP=$(mktemp /etc/examos/.db-connection.XXXXXX)
PASSWORD_TMP=$(mktemp /run/examos/.db-password.XXXXXX)
MARKER_TMP=$(mktemp /run/examos/.postgres-ready.XXXXXX)
DROPIN_DIR=/etc/systemd/system/examos-server.service.d
DROPIN_TMP=""
PROVISIONED=0
cleanup() {
    rm -f -- "$CA_TMP" "$CONFIG_TMP" "$PASSWORD_TMP" "$MARKER_TMP"
    [[ -z $DROPIN_TMP ]] || rm -f -- "$DROPIN_TMP"
    if [[ $PROVISIONED -eq 0 ]]; then
        rm -f -- /etc/examos/certs/db-ca.crt /etc/examos/db-connection.conf \
            /etc/examos/remote-postgres-enabled /run/examos/db_password \
            /run/examos/postgres-ready "$DROPIN_DIR/remote-postgres.conf"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    unset DB_PASSWORD PGPASSWORD
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

install -o root -g root -m 0644 "$EXAMOS_DB_CA_FILE" "$CA_TMP"
printf 'host=%s port=%s dbname=%s user=%s sslmode=verify-full sslrootcert=/etc/examos/certs/db-ca.crt\n' \
    "$EXAMOS_DB_HOST" "$EXAMOS_DB_PORT" "$EXAMOS_DB_NAME" "$EXAMOS_DB_USER" > "$CONFIG_TMP"
chmod 0644 "$CONFIG_TMP"
printf '%s\n' "$DB_PASSWORD" > "$PASSWORD_TMP"
chmod 0600 "$PASSWORD_TMP"

# Verify DNS, network reachability, hostname identity, TLS trust, credentials,
# target database, and migration privileges before persisting configuration.
export PGPASSWORD="$DB_PASSWORD"
psql "host=$EXAMOS_DB_HOST port=$EXAMOS_DB_PORT dbname=$EXAMOS_DB_NAME user=$EXAMOS_DB_USER sslmode=verify-full sslrootcert=$CA_TMP connect_timeout=5" \
    --no-psqlrc --no-password --set=ON_ERROR_STOP=1 --tuples-only --no-align --quiet \
    --command="SELECT CASE WHEN has_database_privilege(current_user,current_database(),'CONNECT') AND has_schema_privilege(current_user,'public','CREATE') AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND left(c.relname,7)='examos_' AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname=current_user)) THEN 1 ELSE 0 END" |
    grep -qx '1' || fail "Database TLS, CONNECT/CREATE privileges, or ownership of existing ExamOS tables failed."
unset PGPASSWORD

# Commit the verified endpoint and secret inputs as one provisioning operation.
mv -f -- "$CA_TMP" /etc/examos/certs/db-ca.crt
mv -f -- "$CONFIG_TMP" /etc/examos/db-connection.conf
mv -f -- "$PASSWORD_TMP" /run/examos/db_password
printf 'remote-postgresql %s %s %s\n' "$EXAMOS_DB_HOST" "$EXAMOS_DB_PORT" "$EXAMOS_DB_NAME" > "$MARKER_TMP"
chmod 0600 "$MARKER_TMP"
install -d -o root -g root -m 0755 "$DROPIN_DIR"
DROPIN_TMP=$(mktemp "$DROPIN_DIR/.remote-postgres.XXXXXX")
cat > "$DROPIN_TMP" <<'UNIT'
[Unit]
Requires=
Requires=examos-unseal.service
After=
After=network-online.target examos-unseal.service
Wants=network-online.target

[Service]
ConditionPathExists=/etc/examos/remote-postgres-enabled
UNIT
chmod 0644 "$DROPIN_TMP"
mv -f -- "$DROPIN_TMP" "$DROPIN_DIR/remote-postgres.conf"
DROPIN_TMP=""
install -o root -g root -m 0600 /dev/null /etc/examos/remote-postgres-enabled
systemctl daemon-reload
mv -f -- "$MARKER_TMP" /run/examos/postgres-ready
PROVISIONED=1
unset DB_PASSWORD

printf 'Remote PostgreSQL endpoint verified with TLS hostname validation.\n'
printf 'Next: seal /run/examos/db_password together with the deployment secrets using the target TPM.\n'
