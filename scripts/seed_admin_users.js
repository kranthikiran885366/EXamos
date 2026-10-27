const crypto = require('crypto');
const fs = require('fs');

function makeHash(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  return `310000:${salt.toString('hex')}:${hash.toString('hex')}`;
}

const primaryAdmins = [
  { id: 'usr_root', user: 'root', name: 'Platform Root', email: 'root@examos.local', role: 1, pw: 'Exam0S!Root#2026' },
  { id: 'usr_admin', user: 'admin', name: 'Platform Administrator', email: 'admin@examos.local', role: 1, pw: 'StrongAdminPassword#2026!' },
];

let sql = `-- Production Platform Admin Provisioning (Demo Seed Users Removed)
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
`;

for (const u of primaryAdmins) {
  const h = makeHash(u.pw);
  sql += `INSERT INTO examos_admin_users (user_id, username, password_hash, full_name, email, role, active, mfa_enabled)
VALUES ('${u.id}', '${u.user}', '${h}', '${u.name}', '${u.email}', ${u.role}, true, false)
ON CONFLICT (username) DO UPDATE 
SET password_hash = '${h}',
    user_id = '${u.id}',
    full_name = '${u.name}',
    role = ${u.role},
    active = true;

`;
}

sql += `COMMIT;
`;

fs.writeFileSync('scripts/seed_admin_users.sql', sql);
console.log('Generated clean scripts/seed_admin_users.sql (all demo users removed)');
