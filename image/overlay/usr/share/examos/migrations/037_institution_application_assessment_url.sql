BEGIN;

ALTER TABLE institution_applications
    ADD COLUMN IF NOT EXISTS target_exam_url TEXT NOT NULL DEFAULT '';

INSERT INTO examos_schema_migrations(component, version)
VALUES ('institutions', 2)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
