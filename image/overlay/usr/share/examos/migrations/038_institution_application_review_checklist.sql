BEGIN;

ALTER TABLE institution_applications
    ADD COLUMN IF NOT EXISTS review_checklist JSONB NOT NULL DEFAULT '{}'::jsonb;

INSERT INTO examos_schema_migrations(component, version)
VALUES ('institutions', 3)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
