BEGIN;

ALTER TABLE device_trust_policies
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(64) NOT NULL DEFAULT '';

INSERT INTO examos_schema_migrations(component, version)
VALUES ('device_fleet', 11)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
