BEGIN;

CREATE TABLE IF NOT EXISTS examos_admin_login_throttle (
    subject_hash char(64) PRIMARY KEY CHECK (subject_hash ~ '^[0-9a-f]{64}$'),
    failed_attempts smallint NOT NULL CHECK (failed_attempts BETWEEN 1 AND 5),
    window_started_at timestamptz NOT NULL,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS examos_admin_login_throttle_cleanup_idx
    ON examos_admin_login_throttle (updated_at);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 7)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
