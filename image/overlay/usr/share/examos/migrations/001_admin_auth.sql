BEGIN;

CREATE TABLE examos_schema_migrations (
    component text NOT NULL,
    version integer NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (component, version)
);

CREATE TABLE examos_admin_users (
    user_id varchar(63) PRIMARY KEY,
    username varchar(63) NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9._@+-]+$'),
    password_hash varchar(255) NOT NULL,
    full_name varchar(127) NOT NULL DEFAULT '',
    email varchar(127) NOT NULL DEFAULT '',
    institution_id varchar(63),
    role smallint NOT NULL CHECK (role BETWEEN 1 AND 9),
    mfa_enabled boolean NOT NULL DEFAULT false,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_login_at timestamptz
);

CREATE TABLE examos_admin_sessions (
    token_hash char(64) PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    user_id varchar(63) NOT NULL REFERENCES examos_admin_users(user_id) ON DELETE CASCADE,
    role smallint NOT NULL CHECK (role BETWEEN 1 AND 9),
    institution_id text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX examos_admin_sessions_user_active_idx
    ON examos_admin_sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE examos_admin_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    event_type text NOT NULL CHECK (event_type IN
        ('ADMIN_ACCOUNT_CREATED', 'ADMIN_SESSION_CREATED', 'ADMIN_SESSION_REVOKED')),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 1);
COMMIT;
