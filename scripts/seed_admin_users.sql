-- Production Platform Admin Provisioning
-- Safe to run multiple times (idempotent).
BEGIN;

-- 1. Ensure default tenant T1 exists in tenants table
INSERT INTO tenants (id, name, code, contact_email, plan, status, created_at)
VALUES ('T1', 'Primary Institution', 'T1', 'admin@examos.local', 'enterprise', 'active', 1700000000)
ON CONFLICT (id) DO NOTHING;

-- 2. Upsert admin and root in public.users table (queried first by auth_controller)
--    PBKDF2-SHA256, 210000 iterations, with separate salt column
--    admin: StrongAdminPassword#2026! (salt: s0_salt_admin_001)
--    root:  Exam0S!Root#2026          (salt: s1_salt_root_001)
INSERT INTO users (id, username, name, role, tenant_id, email, password_hash, salt, totp_secret, status, created_at, mfa_enabled)
VALUES
    ('usr_admin', 'admin', 'Platform Administrator', 'superadmin', 'T1', 'admin@examos.local',
     '0209a1985c6b8ab767712bae8388a67d688f294ea651f074f0e3d84ebed41c1c', 's0_salt_admin_001', NULL, 'active', 1700000000, 0)
ON CONFLICT (username) DO UPDATE SET
    password_hash = '0209a1985c6b8ab767712bae8388a67d688f294ea651f074f0e3d84ebed41c1c',
    salt          = 's0_salt_admin_001',
    mfa_enabled   = 0,
    totp_secret   = NULL,
    status        = 'active';

INSERT INTO users (id, username, name, role, tenant_id, email, password_hash, salt, totp_secret, status, created_at, mfa_enabled)
VALUES
    ('usr_root', 'root', 'Platform Root', 'superadmin', 'T1', 'root@examos.local',
     'b9a4a7087ae5996d60e65156814514b2cb5c1f7221d554720440cca5478d788a', 's1_salt_root_001', NULL, 'active', 1700000000, 0)
ON CONFLICT (username) DO UPDATE SET
    password_hash = 'b9a4a7087ae5996d60e65156814514b2cb5c1f7221d554720440cca5478d788a',
    salt          = 's1_salt_root_001',
    mfa_enabled   = 0,
    totp_secret   = NULL,
    status        = 'active';

UPDATE users SET mfa_enabled = 0, totp_secret = NULL WHERE username IN ('admin', 'root');

-- 3. Upsert admin and root in examos_admin_users table (queried second by auth_controller)
--    PBKDF2-SHA256, 310000 iterations, format "310000:salt_hex:hash_hex"
INSERT INTO examos_admin_users
    (user_id, username, password_hash, full_name, email, role, active, mfa_enabled, totp_secret)
VALUES
    ('usr_admin', 'admin',
     '310000:ee8e19c449b8e1e6e485c672cee05862:aae2df837f94fd673c33afc7692e0221a485fa5cd48c9206f4c4f77193e41289',
     'Platform Administrator', 'admin@examos.local', 1, true, false, NULL)
ON CONFLICT (username) DO UPDATE SET
    password_hash  = EXCLUDED.password_hash,
    user_id        = EXCLUDED.user_id,
    full_name      = EXCLUDED.full_name,
    role           = EXCLUDED.role,
    active         = EXCLUDED.active,
    mfa_enabled    = false,
    totp_secret    = NULL;

INSERT INTO examos_admin_users
    (user_id, username, password_hash, full_name, email, role, active, mfa_enabled, totp_secret)
VALUES
    ('usr_root', 'root',
     '310000:2fefeaff8f5abc45d3f085c5689b7799:58c370141d7bc2e6e8a6ae05654eb801032d80c0843056e16c2f9ba9a20099d0',
     'Platform Root', 'root@examos.local', 1, true, false, NULL)
ON CONFLICT (username) DO UPDATE SET
    password_hash  = EXCLUDED.password_hash,
    user_id        = EXCLUDED.user_id,
    full_name      = EXCLUDED.full_name,
    role           = EXCLUDED.role,
    active         = EXCLUDED.active,
    mfa_enabled    = false,
    totp_secret    = NULL;

UPDATE examos_admin_users
SET mfa_enabled = false, totp_secret = NULL
WHERE username IN ('admin', 'root');

-- 4. Clear all login throttle records so there is no lockout on first login
DELETE FROM examos_admin_login_throttle WHERE 1=1;

-- 5. Ensure default institution
INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days)
VALUES ('inst-default', 'Default Institution', 'DEFAULT', 'admin@examos.local', 365)
ON CONFLICT (institution_id) DO NOTHING;

-- 6. Ensure at least one enrolled kiosk device
INSERT INTO examos_devices (device_id, hostname, group_name, hardware_platform, attestation_status, compliance_status, enrollment_status)
VALUES ('DEV-KIOSK-01', 'DEV-KIOSK-01.kiosk.internal', 'DEFAULT', 'x86_64 / UEFI TPM 2.0', 'TRUSTED', 'COMPLIANT', 'ENROLLED')
ON CONFLICT (device_id) DO NOTHING;

COMMIT;
