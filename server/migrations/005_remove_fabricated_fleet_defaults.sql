BEGIN;

ALTER TABLE examos_devices
    ALTER COLUMN hardware_platform SET DEFAULT '',
    ALTER COLUMN os_release SET DEFAULT '',
    ALTER COLUMN compliance_status SET DEFAULT 'NON_COMPLIANT',
    ALTER COLUMN policy_version SET DEFAULT 0,
    ALTER COLUMN update_status SET DEFAULT 'UNKNOWN',
    ALTER COLUMN last_checkin DROP DEFAULT,
    ALTER COLUMN last_checkin DROP NOT NULL;

ALTER TABLE examos_exams
    ALTER COLUMN retention_days DROP DEFAULT;

ALTER TABLE examos_devices
    DROP CONSTRAINT IF EXISTS examos_devices_update_status_check;
ALTER TABLE examos_devices
    ADD CONSTRAINT examos_devices_update_status_check
    CHECK (update_status IN ('UNKNOWN', 'UP_TO_DATE', 'UPDATE_PENDING', 'UPDATING', 'UPDATE_FAILED'));

ALTER TABLE examos_device_heartbeats
    ALTER COLUMN battery_pct DROP DEFAULT,
    ALTER COLUMN battery_charging DROP DEFAULT,
    ALTER COLUMN disk_free_mb DROP DEFAULT,
    ALTER COLUMN mem_used_mb DROP DEFAULT,
    ALTER COLUMN network_state SET DEFAULT 'UNKNOWN',
    ALTER COLUMN policy_version DROP DEFAULT,
    ALTER COLUMN session_state SET DEFAULT 'UNKNOWN';

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 5);

COMMIT;
