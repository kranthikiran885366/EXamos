BEGIN;

ALTER TABLE os_release_manifests
    ALTER COLUMN signature_value DROP NOT NULL;

ALTER TABLE os_release_test_results
    ADD COLUMN IF NOT EXISTS title VARCHAR(120) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS classification VARCHAR(32) NOT NULL DEFAULT 'internal',
    ADD COLUMN IF NOT EXISTS evidence_link TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_digest VARCHAR(80) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_source VARCHAR(32) NOT NULL DEFAULT 'legacy_unverified';

ALTER TABLE os_deployment_groups
    ALTER COLUMN status SET DEFAULT 'planned';

INSERT INTO examos_schema_migrations(component, version)
VALUES ('os_releases', 2)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
