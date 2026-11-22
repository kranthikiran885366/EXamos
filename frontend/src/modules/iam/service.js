// ExamOS Console — IAM service (backend-only, zero local storage).
//
// Every user-management operation is executed against the real ExamOS C server.
// Credentials, password hashes, TOTP secrets, and user records stay on the server.
import { BACKEND_ADMIN_ROLES, ROLES } from '../../core/security/rbac';
import { need, fail } from '../../core/services/common';
import { create as requestApproval } from '../../core/services/approvals';
import * as Api from '../../core/api/services';

export const pwIssues = (p) => {
  const s = String(p || '');
  const r = [];
  if (s.length < 12)                        r.push('12+ characters');
  if (!/[a-z]/.test(s) || !/[A-Z]/.test(s)) r.push('upper and lower case');
  if (!/\d/.test(s))                        r.push('a digit');
  if (!/[^A-Za-z0-9]/.test(s))             r.push('a symbol');
  return r;
};

// Create user on the real backend.
export async function createUser(a, { username, name, role, password, email = '', institutionId }) {
  need(a, 'user.manage');
  const id = String(username || '').toLowerCase().trim();
  if (!/^[a-z][a-z0-9._-]{2,31}$/.test(id))
    fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  if (!name || String(name).trim().length < 2)
    fail('Enter the full name.');
  if (!BACKEND_ADMIN_ROLES.includes(role))
    fail('Pick a valid role.');
  if (role === 'superadmin' && a.role !== 'superadmin')
    fail('Only a super admin can create a super admin.');
  const bad = pwIssues(password);
  if (bad.length) fail('Password needs ' + bad.join(', ') + '.');

  return Api.createUser({
    username:     id,
    fullName:     String(name).trim(),
    email:        email || `${id}@examos.local`,
    password,
    institutionId: institutionId || a.tenantId || '',
    role,
  });
}

// Change user status on the backend.
export async function setUserStatus(a, userId, status, reason) {
  need(a, 'user.manage');
  if (typeof Api.setUserStatus !== 'function')
    fail('setUserStatus is not available on the backend service.');
  return Api.setUserStatus(userId, status, reason);
}

// Change user role on the backend.
export async function setUserRole(a, userId, role, reason) {
  need(a, 'user.manage');
  if (!BACKEND_ADMIN_ROLES.includes(role)) fail('Pick a backend-supported administrative role.');
  if (role === 'superadmin' && a.role !== 'superadmin')
    fail('Only a super admin can grant super admin.');
  if (ROLES[role].rank >= 60 && a.role !== 'superadmin') {
    if (ROLES[role].rank >= (ROLES[a.role]?.rank ?? 0))
      fail('You cannot grant a role at or above your own privilege.');
    const why = String(reason || '').trim();
    if (why.length < 8) fail('Provide a reason of at least 8 characters.');
    const request = await requestApproval(a, {
      kind: 'role-change',
      label: `${userId} → ${role}`,
      targetId: userId,
      tenantId: a.tenantId,
      reason: why,
      data: { role },
    });
    return `Approval requested (${request.id}). A platform super admin must approve it.`;
  }
  if (typeof Api.setUserRole !== 'function')
    fail('setUserRole is not available on the backend service.');
  return Api.setUserRole(userId, role, reason);
}

// Reset password on the backend.
export async function resetPassword(a, userId, password) {
  need(a, 'user.manage');
  const bad = pwIssues(password);
  if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  if (typeof Api.resetUserPassword !== 'function')
    fail('resetUserPassword is not available on the backend service.');
  return Api.resetUserPassword(userId, password);
}
