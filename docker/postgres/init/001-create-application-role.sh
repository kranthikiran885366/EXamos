set -eu

password_file=/var/run/postgresql/application-password
app_password=$(cat "$password_file")

case "$app_password" in
  *[!A-Fa-f0-9]*)
    printf '%s\n' 'PostgreSQL application password must contain only hexadecimal data.' >&2
    exit 1
    ;;
esac
if [ "${#app_password}" -lt 64 ]; then
    printf '%s\n' 'PostgreSQL application password must contain at least 64 hexadecimal characters.' >&2
    exit 1
fi

PGOPTIONS="-c examos.app_password=$app_password" \
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 <<'SQL'
DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'examos_app') THEN
        CREATE ROLE examos_app LOGIN;
    END IF;
    EXECUTE format(
        'ALTER ROLE examos_app LOGIN PASSWORD %L',
        current_setting('examos.app_password')
    );
END
$role$;
SQL

unset app_password

for migration in /opt/examos/migrations/*.sql; do
  [ -f "$migration" ] || continue
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
    --set=ON_ERROR_STOP=1 \
    --file="$migration"
done
psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 <<'SQL'
REVOKE ALL ON DATABASE examos FROM PUBLIC;
GRANT CONNECT ON DATABASE examos TO examos_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO examos_app;
GRANT SELECT ON examos_schema_migrations TO examos_app;
GRANT SELECT, INSERT ON examos_admin_users TO examos_app;
GRANT UPDATE (last_login_at) ON examos_admin_users TO examos_app;
GRANT SELECT, INSERT, UPDATE ON examos_admin_sessions TO examos_app;
GRANT SELECT, INSERT ON examos_admin_audit TO examos_app;
GRANT USAGE, SELECT ON SEQUENCE examos_admin_audit_audit_id_seq TO examos_app;
SQL
