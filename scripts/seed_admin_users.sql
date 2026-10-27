-- Production Platform Admin Provisioning (Demo Seed Users Removed)
BEGIN;

-- 1. Remove all demo seed accounts from examos_admin_users
DELETE FROM examos_admin_recovery_codes 
WHERE user_id IN (SELECT user_id FROM examos_admin_users WHERE username NOT IN ('admin', 'root'));

DELETE FROM examos_admin_sessions 
WHERE user_id IN (SELECT user_id FROM examos_admin_users WHERE username NOT IN ('admin', 'root'));

DELETE FROM examos_admin_users 
WHERE username NOT IN ('admin', 'root');

-- 2. Remove all demo seed users from public.users table (if present)
DELETE FROM users 
WHERE username NOT IN ('admin', 'root');

-- 3. Ensure primary platform owners exist
INSERT INTO examos_admin_users (user_id, username, password_hash, full_name, email, role, active, mfa_enabled)
VALUES ('usr_root', 'root', '310000:c9151a5993da820c9094590bed69a7fe:f4358c93143b2cafd99d47fb30ccefadf0398cae6c4c0cd9264cca45505d3ef3', 'Platform Root', 'root@examos.local', 1, true, false)
ON CONFLICT (username) DO UPDATE 
SET password_hash = '310000:c9151a5993da820c9094590bed69a7fe:f4358c93143b2cafd99d47fb30ccefadf0398cae6c4c0cd9264cca45505d3ef3',
    user_id = 'usr_root',
    full_name = 'Platform Root',
    role = 1,
    active = true,
    mfa_enabled = false;

INSERT INTO examos_admin_users (user_id, username, password_hash, full_name, email, role, active, mfa_enabled)
VALUES ('usr_admin', 'admin', '310000:d52abc412bf0f6f47a17e8fbaa240292:931722f49f380ffc3f4401e072fdbf88c997a1e6ea1b0dff146bc56e35f933b7', 'Platform Administrator', 'admin@examos.local', 1, true, false)
ON CONFLICT (username) DO UPDATE 
SET password_hash = '310000:d52abc412bf0f6f47a17e8fbaa240292:931722f49f380ffc3f4401e072fdbf88c997a1e6ea1b0dff146bc56e35f933b7',
    user_id = 'usr_admin',
    full_name = 'Platform Administrator',
    role = 1,
    active = true;

COMMIT;
