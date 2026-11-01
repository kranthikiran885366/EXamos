BEGIN;

-- Migration 026: MFA enrollment challenge table.
-- Referenced by auth_controller.c (MFA_SETUP_REQUIRED flow) and
-- auth_mfa_setup / auth_mfa_confirm handlers but never previously created
-- in any migration, causing runtime errors on first-time MFA setup.

CREATE TABLE IF NOT EXISTS examos_admin_mfa_enrollments (
    token_hash  char(64)     PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id     varchar(63)  NOT NULL,
    username    varchar(63)  NOT NULL,
    secret      text         NOT NULL DEFAULT '',
    recovery_hashes text     NOT NULL DEFAULT '',
    attempts    smallint     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at  timestamptz  NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz  NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS examos_admin_mfa_enrollments_user_idx
    ON examos_admin_mfa_enrollments (user_id, expires_at);

-- Periodic cleanup: expired rows are safe to remove after 1 day.
-- (Handled by application; index supports efficient WHERE expires_at < now().)

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 6)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
