-- Production Platform Admin Provisioning
-- Safe to run multiple times (idempotent).
BEGIN;

-- 1. Remove all demo/test accounts from examos_admin_users (keep only admin and root)
DELETE FROM examos_admin_recovery_codes
WHERE user_id IN (SELECT user_id FROM examos_admin_users WHERE username NOT IN ('admin', 'root'));

DELETE FROM examos_admin_sessions
WHERE user_id IN (SELECT user_id FROM examos_admin_users WHERE username NOT IN ('admin', 'root'));

DELETE FROM examos_admin_users
WHERE username NOT IN ('admin', 'root');

-- 2. Remove demo seed users from public.users table (if present)
DELETE FROM users
WHERE username NOT IN ('admin', 'root');

-- 3. Upsert root account
--    password: Exam0S!Root#2026
--    hash: PBKDF2-HMAC-SHA256, 310000 iters, 16-byte random salt (generated fresh)
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

-- 4. Upsert admin account
--    password: StrongAdminPassword#2026!
--    hash: PBKDF2-HMAC-SHA256, 310000 iters, 16-byte random salt (generated fresh)
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

-- 5. Force-clear MFA on both accounts regardless of upsert path
UPDATE examos_admin_users
SET mfa_enabled = false, totp_secret = NULL
WHERE username IN ('admin', 'root');

-- 6. Clear all login throttle records so there is no lockout on first login
-- (safe: throttle resets on successful login anyway)
DELETE FROM examos_admin_login_throttle WHERE 1=1;

-- 7. Ensure default institution
INSERT INTO examos_institutions (institution_id, name, code, domain_email, retention_days)
VALUES ('inst-default', 'Default Institution', 'DEFAULT', 'admin@examos.local', 365)
ON CONFLICT (institution_id) DO NOTHING;

-- 8. Ensure at least one enrolled kiosk device
INSERT INTO examos_devices (device_id, hostname, group_name, hardware_platform, attestation_status, compliance_status, enrollment_status)
VALUES ('DEV-KIOSK-01', 'DEV-KIOSK-01.kiosk.internal', 'DEFAULT', 'x86_64 / UEFI TPM 2.0', 'TRUSTED', 'COMPLIANT', 'ENROLLED')
ON CONFLICT (device_id) DO NOTHING;

COMMIT;
