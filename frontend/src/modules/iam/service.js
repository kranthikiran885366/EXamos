import { get, put } from '../../core/db/db';
import { pbkdf2, randomId } from '../../core/security/crypto';
import { newSecret } from '../../core/security/totp';
import { clean } from '../../core/security/sanitize';
import { ROLES } from '../../core/security/rbac';
import { need, fail, log } from '../../core/services/common';

export const pwIssues = (p) => {
  const r = [];
  if (p.length < 12) r.push('12+ characters');
  if (!/[a-z]/.test(p) || !/[A-Z]/.test(p)) r.push('upper and lower case');
  if (!/\d/.test(p)) r.push('a digit');
  if (!/[^A-Za-z0-9]/.test(p)) r.push('a symbol');
  return r;
};
export const makeUser = async ({ username, name, role, password }) => {
  const salt = randomId(12), totp = newSecret();
  const nm = clean(name, 60);
  return { id: username, name: nm, initials: nm.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase(), role, title: ROLES[role].label, status: 'active', salt, pwHash: await pbkdf2(password, salt), totp, createdAt: Date.now(), lastLogin: null };
};
export async function createUser(a, { username, name, role, password }) {
  need(a, 'user.manage');
  const id = clean(username, 32).toLowerCase();
  if (!/^[a-z][a-z0-9._-]{2,31}$/.test(id)) fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  if (clean(name, 60).length < 2) fail('Enter the full name.');
  if (await get('users', id)) fail('Username already exists.');
  if (!Object.hasOwn(ROLES, role)) fail('Pick a role.');
  if (role === 'superadmin' && a.role !== 'superadmin') fail('Only a super admin can create a super admin.');
  const bad = pwIssues(password || ''); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  const u = await makeUser({ username: id, name, role, password });
  await put('users', u); await log(a, 'USER_CREATED', `${id} role=${role}`);
  return `User ${id} created. Authenticator key (shown once): ${u.totp}`;
}
export async function setUserStatus(a, u, status, reason) {
  need(a, 'user.manage');
  if (u.id === a.id) fail('You cannot change your own account status.');
  await put('users', { ...u, status }); await log(a, 'USER_' + status.toUpperCase(), `${u.id}: ${reason}`);
  return `${u.id} is now ${status}.`;
}
export async function setUserRole(a, u, role, reason) {
  need(a, 'user.manage');
  if (u.id === a.id) fail('You cannot change your own role (no self-escalation).');
  if (!Object.hasOwn(ROLES, role)) fail('Pick a role.');
  if ((role === 'superadmin' || u.role === 'superadmin') && a.role !== 'superadmin') fail('Only a super admin can grant or remove super admin.');
  await put('users', { ...u, role, title: ROLES[role].label }); await log(a, 'USER_ROLE_CHANGED', `${u.id}: ${u.role} -> ${role}: ${reason}`);
  return `${u.id} is now ${ROLES[role].label}.`;
}
export async function resetPassword(a, u, password) {
  need(a, 'user.manage');
  const bad = pwIssues(password || ''); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  const salt = randomId(12);
  await put('users', { ...u, salt, pwHash: await pbkdf2(password, salt) }); await log(a, 'USER_PASSWORD_RESET', u.id);
  return `Password reset for ${u.id}.`;
}
