BEGIN;

-- Add TOTP secret and enrollment timestamp to admin users
ALTER TABLE examos_admin_users
    ADD COLUMN totp_secret text,
    ADD COLUMN totp_enrolled_at timestamptz;

-- Table for single-use emergency recovery codes (SHA-256 hashed)
CREATE TABLE examos_admin_recovery_codes (
    code_hash char(64) PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    user_id text NOT NULL REFERENCES examos_admin_users(user_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    used boolean NOT NULL DEFAULT false,
    used_at timestamptz
);
CREATE INDEX examos_admin_recovery_codes_user_idx
    ON examos_admin_recovery_codes (user_id)
    WHERE NOT used;

-- Table for secure password reset tokens (SHA-256 hashed)
CREATE TABLE examos_admin_password_resets (
    token_hash char(64) PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id text NOT NULL REFERENCES examos_admin_users(user_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    used boolean NOT NULL DEFAULT false,
    used_at timestamptz,
    CHECK (expires_at > created_at)
);

-- Expand audit event types to cover MFA, password resets, and user lifecycle
ALTER TABLE examos_admin_audit
    DROP CONSTRAINT IF EXISTS examos_admin_audit_event_type_check;

ALTER TABLE examos_admin_audit
    ADD CONSTRAINT examos_admin_audit_event_type_check
    CHECK (event_type IN (
        'ADMIN_SESSION_CREATED',
        'ADMIN_SESSION_REVOKED',
        'ADMIN_LOGIN_FAILED',
        'ADMIN_MFA_ENROLLED',
        'ADMIN_MFA_VERIFIED',
        'ADMIN_MFA_FAILED',
        'ADMIN_RECOVERY_USED',
        'ADMIN_PASSWORD_RESET_REQUESTED',
        'ADMIN_PASSWORD_RESET_COMPLETED',
        'ADMIN_USER_CREATED',
        'ADMIN_USER_UPDATED'
    ));

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 2);

COMMIT;
