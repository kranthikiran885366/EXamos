BEGIN;

-- Require callers to provide business and policy values. Defaults here could
-- silently create an exam with an unintended retention, audience, or policy.
ALTER TABLE examos_institutions
    ALTER COLUMN retention_days DROP DEFAULT;

ALTER TABLE examos_rooms
    ALTER COLUMN capacity DROP DEFAULT,
    ALTER COLUMN supervisor DROP DEFAULT;

ALTER TABLE examos_exams
    ALTER COLUMN timezone DROP DEFAULT,
    ALTER COLUMN state DROP DEFAULT,
    ALTER COLUMN policy_version DROP DEFAULT,
    ALTER COLUMN policy_signature DROP DEFAULT,
    ALTER COLUMN permitted_device_group DROP DEFAULT,
    ALTER COLUMN accommodations_allowed DROP DEFAULT,
    ALTER COLUMN network_offline_allowed DROP DEFAULT,
    ALTER COLUMN browser_policy_json DROP DEFAULT,
    ALTER COLUMN incident_appeal_procedure DROP DEFAULT;

ALTER TABLE examos_exam_policies
    ALTER COLUMN status DROP DEFAULT;

ALTER TABLE examos_exam_roster
    ALTER COLUMN assigned_seat DROP DEFAULT,
    ALTER COLUMN assigned_device_id DROP DEFAULT,
    ALTER COLUMN status DROP DEFAULT,
    ALTER COLUMN accommodation_extra_time_mins DROP DEFAULT;

ALTER TABLE examos_exam_readiness_checks
    ALTER COLUMN network_ok DROP DEFAULT,
    ALTER COLUMN tpm_attested DROP DEFAULT,
    ALTER COLUMN kiosk_policy_ready DROP DEFAULT,
    ALTER COLUMN camera_ready DROP DEFAULT,
    ALTER COLUMN passed DROP DEFAULT,
    ALTER COLUMN details DROP DEFAULT;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('exam_lifecycle', 4);

COMMIT;
