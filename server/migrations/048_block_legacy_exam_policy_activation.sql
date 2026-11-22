BEGIN;

CREATE OR REPLACE FUNCTION guard_legacy_exam_policy_activation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'legacy exam policy history cannot be deleted'
            USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        RAISE EXCEPTION 'legacy exam policy creation is disabled'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.policy_id IS DISTINCT FROM OLD.policy_id
       OR NEW.exam_id IS DISTINCT FROM OLD.exam_id
       OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
       OR NEW.exam_url IS DISTINCT FROM OLD.exam_url
       OR NEW.allowed_origins IS DISTINCT FROM OLD.allowed_origins
       OR NEW.permitted_apps IS DISTINCT FROM OLD.permitted_apps
       OR NEW.signature IS DISTINCT FROM OLD.signature
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'legacy exam policy history is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT (OLD.status IN ('ACTIVE', 'ROLLBACK')
                AND NEW.status = 'SUPERSEDED') THEN
        RAISE EXCEPTION 'legacy exam policy activation or transition is disabled'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS examos_exam_policies_legacy_activation_guard
    ON examos_exam_policies;
CREATE TRIGGER examos_exam_policies_legacy_activation_guard
    BEFORE INSERT OR UPDATE OR DELETE ON examos_exam_policies
    FOR EACH ROW EXECUTE FUNCTION guard_legacy_exam_policy_activation();

REVOKE INSERT, UPDATE, DELETE ON examos_exam_policies FROM PUBLIC;

INSERT INTO examos_schema_migrations(component, version)
VALUES ('exam_policy_trust', 48)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
