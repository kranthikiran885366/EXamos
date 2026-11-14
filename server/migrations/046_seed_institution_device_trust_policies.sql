-- 046_seed_institution_device_trust_policies.sql
-- Ensure all registered tenants have a unique active device trust policy.
-- Guarantees device registration and attestation governance for all onboarded institutions.

BEGIN;

-- 1. Seed active device trust policy for all tenants lacking an active policy
INSERT INTO device_trust_policies (
    id,
    institution_id,
    policy_name,
    version,
    require_registration,
    require_admin_approval,
    require_tpm,
    require_secure_boot,
    require_approved_release,
    max_evidence_age_sec,
    allowed_device_categories,
    status,
    approved_by,
    approved_at,
    activated_at,
    created_at,
    updated_at
)
SELECT
    'dtpol_' || SUBSTRING(t.id FROM 1 FOR 50),
    t.id,
    t.name || ' Standard Device Trust Policy',
    1,
    TRUE,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    600,
    'lab_pc,institution_laptop,personal_laptop,kiosk_appliance',
    'active',
    'usr_system',
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM device_trust_policies p
    WHERE p.institution_id = t.id AND p.status = 'active'
)
ON CONFLICT (id) DO UPDATE SET status = 'active';

-- 2. Record version marker in schema migrations table
INSERT INTO examos_schema_migrations(component, version)
VALUES ('device_fleet', 46)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
