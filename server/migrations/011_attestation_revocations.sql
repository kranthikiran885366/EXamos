BEGIN;

CREATE TABLE examos_attestation_revocations (
    target_type varchar(16) NOT NULL CHECK (target_type IN ('DEVICE', 'RELEASE')),
    target_id varchar(63) NOT NULL CHECK (target_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    reason varchar(127) NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (target_type, target_id)
);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 9);

COMMIT;
