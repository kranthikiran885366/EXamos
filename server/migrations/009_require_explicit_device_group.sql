BEGIN;

-- Device group membership controls policy distribution and must be assigned
-- by enrollment rather than inferred from a shared schema default.
ALTER TABLE examos_devices
    ALTER COLUMN group_name DROP DEFAULT;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 7);

COMMIT;
