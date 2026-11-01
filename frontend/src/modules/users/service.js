// ExamOS Console — User management service (backend-only, zero local storage).
//
// Every operation calls the real ExamOS C server through Api.*.
// No password hashes, TOTP secrets, salts, or user records are stored
// in IndexedDB, localStorage, or sessionStorage. The server is the only
// source of truth for identity, credentials, and roles.
import { clean } from '../../core/security/sanitize';
import { ROLES, roleInfo, roleLabel, permissionsOf, registerRoles } from '../../core/security/rbac';
import { need, fail, log, assertScope, requireReason, id, isEmail } from '../../core/services/common';
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

const usernameOk  = (u) => /^[a-z][a-z0-9._-]{2,31}$/.test(u);
export const initialsOf = (name) =>
  clean(name, 60).split(/\s+/).filter(Boolean).map((w) => w[0]).join('').slice(0, 2).toUpperCase();

// ─── Guard helpers ────────────────────────────────────────────────────────────

function guardTarget(a, u) {
  if (!u) fail('User not found.');
  if (!['superadmin', 'ops_admin'].includes(a.role) && u.tenantId !== a.tenantId)
    fail('That user belongs to another institution.');
  if (!['superadmin', 'ops_admin'].includes(a.role) &&
      (roleInfo(u.role)?.rank ?? 0) >= (roleInfo(a.role)?.rank ?? 0))
    fail('You cannot manage an account with equal or higher privilege.');
}

// ─── User CRUD — all backend ──────────────────────────────────────────────────

export async function createUser(a, { username, name, role, password, tenantId, email = '' }) {
  need(a, 'user.manage');
  const uid = clean(username, 32).toLowerCase();
  if (!usernameOk(uid))
    fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  if (clean(name, 60).length < 2)
    fail('Enter the full name.');
  if (email && !isEmail(email))
    fail('Enter a valid email address.');
  if (!roleInfo(role))
    fail('Pick a role.');
  if (role === 'system' && a.role !== 'superadmin')
    fail('Service identities can only be created by a platform super admin.');
  if ((roleInfo(role)?.rank ?? 0) >= (roleInfo(a.role)?.rank ?? 0) && a.role !== 'superadmin')
    fail('You cannot create an account with equal or higher privilege.');
  if (a.role !== 'superadmin') { tenantId = a.tenantId; if (!tenantId) fail('Your account has no institution scope.'); }
  const bad = pwIssues(password); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');

  // Create on the C server — credentials never touch the browser.
  const result = await Api.createUser({
    username:     uid,
    fullName:     clean(name, 60),
    email:        email ? clean(email, 120).toLowerCase() : `${uid}@examos.local`,
    password,
    institutionId: tenantId || '',
    role,
  });

  await log(a, 'USER_CREATED', `${uid} role=${role} tenant=${tenantId || 'global'}`);
  return result;
}

export async function updateUser(a, u, patch) {
  need(a, 'user.manage'); guardTarget(a, u);
  const nm = patch.name !== undefined ? clean(patch.name, 60) : u.name;
  if (nm.length < 2) fail('Enter the full name.');
  if (patch.email && !isEmail(patch.email)) fail('Enter a valid email address.');
  if (patch.tenantId !== undefined && a.role !== 'superadmin')
    fail('Only a platform super admin can move an account between institutions.');

  const result = await Api.updateUser(u.id, {
    full_name:    nm,
    email:        patch.email ? clean(patch.email, 120).toLowerCase() : undefined,
    institution_id: patch.tenantId,
  });
  await log(a, 'USER_UPDATED', u.id);
  return result || 'Profile updated.';
}

export async function setUserStatus(a, u, status, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.id === a.id) fail('You cannot change your own account status.');
  if (!['active', 'suspended', 'deactivated', 'locked'].includes(status)) fail('Unknown status.');
  const r = requireReason(reason, 8);

  await Api.setUserStatus(u.id, status, r);
  await log(a, 'USER_' + status.toUpperCase(), `${u.id}: ${r}`);
  return `${u.id} is now ${status}.`;
}

export async function unlockUser(a, u, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.status !== 'locked') fail('Account is not locked.');
  const r = requireReason(reason, 8);
  await Api.setUserStatus(u.id, 'active', r);
  await log(a, 'USER_UNLOCKED', `${u.id}: ${r}`);
  return `${u.id} unlocked.`;
}

export async function setUserRole(a, u, role, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.id === a.id) fail('You cannot change your own role (no self-escalation).');
  if (!roleInfo(role)) fail('Pick a role.');
  const r      = requireReason(reason, 8);
  const tRank  = roleInfo(role)?.rank   ?? 0;
  const myRank = roleInfo(a.role)?.rank ?? 0;
  if (role === 'superadmin'   && a.role !== 'superadmin') fail('Only a super admin can grant super admin.');
  if (u.role === 'superadmin' && a.role !== 'superadmin') fail('Only a super admin can change a super admin.');
  if (tRank >= myRank && a.role !== 'superadmin') fail('You cannot grant a role at or above your own privilege.');

  // Sensitive role changes require a second approver unless performed by super admin.
  if (a.role !== 'superadmin' && tRank >= 60) {
    const ap = await requestApproval(a, {
      kind: 'role-change', label: `${u.id} → ${roleLabel(role)}`,
      targetId: u.id, tenantId: u.tenantId, reason: r, data: { role },
    });
    return `Approval requested (${ap.id}). A different privileged user must confirm this role change.`;
  }

  await Api.setUserRole(u.id, role, r);
  await log(a, 'USER_ROLE_CHANGED', `${u.id}: ${u.role} -> ${role}: ${r}`);
  return `${u.id} is now ${roleLabel(role)}.`;
}

export async function resetPassword(a, u, password, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  const bad = pwIssues(password); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  await Api.resetUserPassword(u.id, password);
  await log(a, 'USER_PASSWORD_RESET', `${u.id}: ${clean(reason || '', 100)}`);
  return `Password reset for ${u.id}.`;
}

// ─── Session revocation — backend ─────────────────────────────────────────────

export async function revokeUserSessions(userId, why = 'administrative action') {
  try {
    const res = await Api.revokeUserSessions?.(userId, why);
    return res?.count ?? 0;
  } catch { return 0; }
}

// ─── Invitations — backend ────────────────────────────────────────────────────

export async function invite(a, { name, email, role, tenantId, expiresInDays = 7 }) {
  need(a, 'user.manage');
  if (clean(name, 60).length < 2) fail('Enter the full name.');
  if (!isEmail(email)) fail('Enter a valid email address.');
  if (!roleInfo(role) || role === 'system') fail('Pick a human role.');
  if (a.role !== 'superadmin') tenantId = a.tenantId;
  if (!tenantId) fail('Choose an institution.');
  if (!['superadmin', 'ops_admin'].includes(a.role) && tenantId !== a.tenantId)
    fail('You can only invite staff to your institution.');
  if ((roleInfo(role)?.rank ?? 0) >= (roleInfo(a.role)?.rank ?? 0) && a.role !== 'superadmin')
    fail('You cannot invite a role at or above your own privilege.');

  const result = await Api.inviteUser?.({ name, email, role, tenantId, expiresInDays });
  await log(a, 'INVITATION_CREATED', `${email} role=${role}`);
  return result;
}

export async function acceptInvitation(token, { username, password }) {
  const uid = clean(username, 32).toLowerCase();
  if (!usernameOk(uid)) fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  const bad = pwIssues(password); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  return Api.acceptInvitation?.({ token, username: uid, password });
}

// ─── Custom roles — backend ───────────────────────────────────────────────────

export async function createRole(a, { id: rid, label, desc, perms }) {
  need(a, 'role.manage');
  const key = clean(rid, 40).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  if (!/^[a-z][a-z0-9-]{2,39}$/.test(key)) fail('Role key: 3–40 lowercase letters, digits or -.');
  if (clean(label, 60).length < 3) fail('Role name needs 3+ characters.');
  const list = Array.isArray(perms) ? perms.filter((p) => typeof p === 'string') : [];
  if (!list.length) fail('Select at least one permission.');

  const result = await Api.createRole?.({ key, label: clean(label, 60), desc: clean(desc || '', 200), perms: [...new Set(list)] });
  registerRoles(await Api.listRoles?.() || []);
  await log(a, 'ROLE_CREATED', `${key} perms=${list.length}`);
  return result;
}

export async function updateRole(a, role, patch) {
  need(a, 'role.manage');
  if (!role.custom) fail('Predefined roles cannot be edited. Create a custom role instead.');
  const next = {
    label: patch.label !== undefined ? clean(patch.label, 60) : role.label,
    desc:  patch.desc  !== undefined ? clean(patch.desc,  200) : role.desc,
    perms: patch.perms ? [...new Set(patch.perms)] : role.perms,
  };
  if (!next.perms.length) fail('A role needs at least one permission.');
  await Api.updateRole?.(role.id, next);
  registerRoles(await Api.listRoles?.() || []);
  await log(a, 'ROLE_UPDATED', `${role.id} perms=${next.perms.length}`);
  return 'Role updated.';
}

export async function deleteRole(a, role) {
  need(a, 'role.manage');
  if (!role.custom) fail('Predefined roles cannot be deleted.');
  await Api.deleteRole?.(role.id);
  registerRoles((await Api.listRoles?.() || []).filter((r) => !r.deleted));
  await log(a, 'ROLE_DELETED', role.id);
  return 'Role deleted.';
}

export const effectivePermissions = (u) => ({
  role:  u.role,
  label: roleLabel(u.role),
  perms: permissionsOf(u.role),
});
