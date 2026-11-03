\if :{?confirm_purge}
\else
\echo 'Refusing to purge. Run psql with -v confirm_purge=true to confirm.'
\quit
\endif

\if :confirm_purge
\echo 'WARNING: this removes institution data AND all platform admin accounts; re-provision an owner afterward.'
BEGIN;

SELECT current_database() AS database_being_purged;

DO $purge$
DECLARE
    target RECORD;
    row_count BIGINT;
BEGIN
    FOR target IN
        SELECT DISTINCT c.table_schema, c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
        WHERE c.table_schema = 'public'
          AND t.table_type = 'BASE TABLE'
          AND c.column_name IN ('tenant_id', 'institution_id')
    LOOP
        EXECUTE format('SELECT count(*) FROM %I.%I', target.table_schema, target.table_name)
            INTO row_count;
        RAISE NOTICE 'Purging %.% (% rows)', target.table_schema, target.table_name, row_count;
        EXECUTE format('TRUNCATE TABLE %I.%I CASCADE', target.table_schema, target.table_name);
    END LOOP;

    TRUNCATE TABLE public.tenants CASCADE;
    TRUNCATE TABLE public.examos_admin_users CASCADE;
END
$purge$;

COMMIT;

\echo 'All institution-scoped rows and platform administrator accounts were purged.'
\else
\echo 'Refusing to purge. confirm_purge must be true.'
\quit
\endif
