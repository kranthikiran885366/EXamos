import { all, get, put } from '../../core/db/db';
import { pbkdf2, randomId, sha256, safeEqual } from '../../core/security/crypto';
import { newSecret } from '../../core/security/totp';
import { clean } from '../../core/security/sanitize';
import { ROLES, roleInfo, roleLabel, permissionsOf, registerRoles } from '../../core/security/rbac';
import { need, fail, log, assertScope, requireReason, id, isEmail } from '../../core/services/common';
import { create as requestApproval } from '../../core/services/approvals';
import * as Api from '../../core/api/services';

export const pwIssues = (p) => {
  const r = [];
  if (String(p).length < 12) r.push('12+ characters');
  if (!/[a-z]/.test(p) || !/[A-Z]/.test(p)) r.push('upper and lower case');
  if (!/\d/.test(p)) r.push('a digit');
  if (!/[^A-Za-z0-9]/.test(p)) r.push('a symbol');
  return r;
};
const usernameOk = (u) => /^[a-z][a-z0-9._-]{2,31}$/.test(u);
const normCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
export const initialsOf = (name) => clean(name, 60).split(/\s+/).filter(Boolean).map((w) => w[0]).join('').slice(0, 2).toUpperCase();

export async function makeUser({ username, name, role, password, tenantId = null, email = '', candidateId = null, mfaEnabled = true }) {
  const salt = randomId(12), totp = newSecret();
  const nm = clean(name, 60);
  return {
    id: username, name: nm, initials: initialsOf(nm), role, title: roleLabel(role), status: 'active',
    tenantId, email: clean(email, 120).toLowerCase(), candidateId, mfaEnabled,
    salt, pwHash: await pbkdf2(password, salt), totp, recoveryCodes: [],
    createdAt: Date.now(), lastLogin: null, passwordChangedAt: Date.now(),
  };
}

function guardTarget(a, u) {
  if (!u) fail('User not found.');
  if (!['superadmin', 'ops_admin'].includes(a.role) && u.tenantId !== a.tenantId) fail('That user belongs to another institution.');
  if (!['superadmin', 'ops_admin'].includes(a.role) && roleInfo(u.role)?.rank >= roleInfo(a.role)?.rank) fail('You cannot manage an account with equal or higher privilege.');
}

export async function createUser(a, { username, name, role, password, tenantId, email = '', mfaEnabled = true }) {
  need(a, 'user.manage');
  const uid = clean(username, 32).toLowerCase();
  if (!usernameOk(uid)) fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  if (clean(name, 60).length < 2) fail('Enter the full name.');
  if (email && !isEmail(email)) fail('Enter a valid email address.');
  if (await get('users', uid)) fail('Username already exists.');
  if (!roleInfo(role)) fail('Pick a role.');
  if (role === 'system' && a.role !== 'superadmin') fail('Service identities can only be created by a platform super admin.');
  if (roleInfo(role).rank >= roleInfo(a.role).rank && a.role !== 'superadmin') fail('You cannot create an account with equal or higher privilege.');
  if (a.role !== 'superadmin') { tenantId = a.tenantId; if (!tenantId) fail('Your account has no institution scope.'); }
  const bad = pwIssues(password || ''); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  const u = await makeUser({ username: uid, name, role, password, tenantId, email, mfaEnabled });
  const recovery = Array.from({ length: 8 }, () => normCode(randomId(5)).slice(0, 8).replace(/(.{4})/, '$1-'));
  u.recoveryCodes = await Promise.all(recovery.map((c) => sha256(normCode(c))));
  try {
    await Api.createUser({
      username: uid,
      fullName: name,
      email: email || `${uid}@examos.local`,
      password,
      institutionId: tenantId || '',
      role,
    });
  } catch (err) {
    console.warn('Backend user registration fallback:', err.message);
  }
  await put('users', u);
  await log(a, 'USER_CREATED', `${uid} role=${role} tenant=${tenantId || 'global'}`);
  return { user: u, totp: u.totp, recovery };
}

export async function updateUser(a, u, patch) {
  need(a, 'user.manage'); guardTarget(a, u);
  const nm = patch.name !== undefined ? clean(patch.name, 60) : u.name;
  if (nm.length < 2) fail('Enter the full name.');
  if (patch.email && !isEmail(patch.email)) fail('Enter a valid email address.');
  const next = { ...u, name: nm, initials: initialsOf(nm), email: patch.email !== undefined ? clean(patch.email, 120).toLowerCase() : u.email };
  if (patch.tenantId !== undefined) {
    if (a.role !== 'superadmin') fail('Only a platform super admin can move an account between institutions.');
    next.tenantId = patch.tenantId || null;
  }
  await put('users', next); await log(a, 'USER_UPDATED', `${u.id}`);
  return 'Profile updated.';
}

export async function setUserStatus(a, u, status, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.id === a.id) fail('You cannot change your own account status.');
  if (!['active', 'suspended', 'deactivated', 'locked'].includes(status)) fail('Unknown status.');
  const r = requireReason(reason, 8);
  await put('users', { ...u, status, statusReason: r, statusAt: Date.now(), statusBy: a.id });
  if (status !== 'active') await revokeUserSessions(u.id, `account ${status}`);
  await log(a, 'USER_' + status.toUpperCase(), `${u.id}: ${r}`);
  return `${u.id} is now ${status}. Active sessions were revoked.`;
}

export async function unlockUser(a, u, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.status !== 'locked') fail('Account is not locked.');
  const r = requireReason(reason, 8);
  await put('users', { ...u, status: 'active', statusReason: r, statusAt: Date.now(), statusBy: a.id });
  await log(a, 'USER_UNLOCKED', `${u.id}: ${r}`);
  return `${u.id} unlocked.`;
}

async function applyRole(a, u, role, reason) {
  await put('users', { ...u, role, title: roleLabel(role), roleChangedAt: Date.now(), roleChangedBy: a.id });
  await log(a, 'USER_ROLE_CHANGED', `${u.id}: ${u.role} -> ${role}: ${reason}`);
  return `${u.id} is now ${roleLabel(role)}.`;
}

export async function setUserRole(a, u, role, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  if (u.id === a.id) fail('You cannot change your own role (no self-escalation).');
  if (!roleInfo(role)) fail('Pick a role.');
  const r = requireReason(reason, 8);
  const targetRank = roleInfo(role).rank || 0, myRank = roleInfo(a.role).rank || 0;
  if (role === 'superadmin' && a.role !== 'superadmin') fail('Only a super admin can grant super admin.');
  if (u.role === 'superadmin' && a.role !== 'superadmin') fail('Only a super admin can change a super admin.');
  if (targetRank >= myRank && a.role !== 'superadmin') fail('You cannot grant a role at or above your own privilege.');
  // Sensitive role changes need a second person unless a super admin performs them.
  if (a.role !== 'superadmin' && targetRank >= 60) {
    const ap = await requestApproval(a, { kind: 'role-change', label: `${u.id} → ${roleLabel(role)}`, targetId: u.id, tenantId: u.tenantId, reason: r, data: { role } });
    return `Approval requested (${ap.id}). A different privileged user must confirm this role change.`;
  }
  const msg = await applyRole(a, u, role, r);
  await revokeUserSessions(u.id, 'role changed');
  return msg;
}

export async function applyRoleApproval(ap, approver) {
  const u = await get('users', ap.targetId);
  if (!u) fail('The target user no longer exists.');
  const role = ap.data?.role;
  if (!roleInfo(role)) fail('The role in this request is no longer valid.');
  if ((roleInfo(role).rank || 0) >= (roleInfo(approver.role).rank || 0) && approver.role !== 'superadmin') fail('Approver lacks the privilege for this assignment.');
  await put('users', { ...u, role, title: roleLabel(role), roleChangedAt: Date.now(), roleChangedBy: approver.id });
  await revokeUserSessions(u.id, 'role changed by approval');
  await log(approver, 'USER_ROLE_CHANGED', `${u.id} -> ${role} (approval ${ap.id})`);
  return `${u.id} is now ${roleLabel(role)}.`;
}

export async function resetPassword(a, u, password, reason) {
  need(a, 'user.manage'); guardTarget(a, u);
  const bad = pwIssues(password || ''); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  const salt = randomId(12);
  await put('users', { ...u, salt, pwHash: await pbkdf2(password, salt), passwordChangedAt: Date.now(), passwordResetBy: a.id });
  await revokeUserSessions(u.id, 'password reset');
  await log(a, 'USER_PASSWORD_RESET', `${u.id}: ${clean(reason, 100)}`);
  return `Password reset for ${u.id}. Existing sessions were revoked.`;
}

export async function revokeUserSessions(userId, why = 'administrative action') {
  const list = (await all('authSessions')).filter((s) => s.userId === userId && s.status === 'active');
  for (const s of list) await put('authSessions', { ...s, status: 'revoked', current: false, endedAt: Date.now(), reason: why });
  return list.length;
}

/* ---------------- Invitations ---------------- */
export async function invite(a, { name, email, role, tenantId, expiresInDays = 7 }) {
  need(a, 'user.manage');
  if (clean(name, 60).length < 2) fail('Enter the full name.');
  if (!isEmail(email)) fail('Enter a valid email address.');
  if (!roleInfo(role) || role === 'system') fail('Pick a human role.');
  if (a.role !== 'superadmin') tenantId = a.tenantId;
  if (!tenantId) fail('Choose an institution.');
  if (!['superadmin', 'ops_admin'].includes(a.role) && tenantId !== a.tenantId) fail('You can only invite staff to your institution.');
  if ((roleInfo(role).rank || 0) >= (roleInfo(a.role).rank || 0) && a.role !== 'superadmin') fail('You cannot invite a role at or above your own privilege.');
  const existing = (await all('users')).find((u) => u.email === clean(email, 120).toLowerCase());
  if (existing) fail('A user with this email already exists.');
  if ((await all('invitations')).some((i) => i.status === 'pending' && i.email === clean(email, 120).toLowerCase())) fail('An invitation is already pending for this email.');
  const token = randomId(18);
  const inv = {
    id: id('inv'), name: clean(name, 60), email: clean(email, 120).toLowerCase(), role, tenantId,
    tokenHash: await sha256(token), invitedBy: a.id, createdAt: Date.now(),
    expiresAt: Date.now() + Math.max(1, Math.min(30, Number(expiresInDays) || 7)) * 864e5, status: 'pending',
  };
  await put('invitations', inv);
  await log(a, 'INVITATION_CREATED', `${inv.email} role=${role}`);
  return { invitation: inv, token, link: `${location.origin}/invite/${token}` };
}

export async function resendInvitation(a, inv, expiresInDays = 7) {
  need(a, 'user.manage');
  if (inv.status !== 'pending') fail('Only pending invitations can be resent.');
  await assertInviteScope(a, inv);
  const token = randomId(18);
  const next = { ...inv, tokenHash: await sha256(token), expiresAt: Date.now() + Math.max(1, Number(expiresInDays) || 7) * 864e5, sentAt: Date.now() };
  await put('invitations', next); await log(a, 'INVITATION_RESENT', inv.email);
  return { invitation: next, token, link: `${location.origin}/invite/${token}` };
}

async function assertInviteScope(a, inv) {
  if (!['superadmin', 'ops_admin'].includes(a.role) && inv.tenantId !== a.tenantId) fail('That invitation belongs to another institution.');
}

export async function expireInvitation(a, inv, reason) {
  need(a, 'user.manage'); await assertInviteScope(a, inv);
  if (inv.status !== 'pending') fail('Only pending invitations can be expired.');
  const r = requireReason(reason, 8);
  await put('invitations', { ...inv, status: 'expired', expiredBy: a.id, expiredAt: Date.now(), note: r });
  await log(a, 'INVITATION_EXPIRED', inv.email);
  return 'Invitation expired.';
}

export async function acceptInvitation(token, { username, password }) {
  const h = await sha256(String(token || ''));
  const inv = (await all('invitations')).find((x) => x.tokenHash === h && x.status === 'pending');
  if (!inv) fail('This invitation is invalid or has already been used.');
  if (Date.now() > inv.expiresAt) {
    await put('invitations', { ...inv, status: 'expired' });
    fail('This invitation has expired. Ask an administrator to resend it.');
  }
  const uid = clean(username, 32).toLowerCase();
  if (!usernameOk(uid)) fail('Username: 3–32 characters, start with a letter; letters, digits . _ - only.');
  if (await get('users', uid)) fail('Username already exists.');
  const bad = pwIssues(password || ''); if (bad.length) fail('Password needs ' + bad.join(', ') + '.');
  const u = await makeUser({ username: uid, name: inv.name, role: inv.role, password, tenantId: inv.tenantId, email: inv.email });
  const recovery = Array.from({ length: 8 }, () => normCode(randomId(5)).slice(0, 8).replace(/(.{4})/, '$1-'));
  u.recoveryCodes = await Promise.all(recovery.map((c) => sha256(normCode(c))));
  await put('users', u);
  await put('invitations', { ...inv, status: 'accepted', acceptedAt: Date.now(), acceptedUser: uid });
  await log({ id: uid }, 'INVITATION_ACCEPTED', inv.email);
  return { user: u, totp: u.totp, recovery };
}

/* ---------------- Custom roles ---------------- */
export async function createRole(a, { id: rid, label, desc, perms }) {
  need(a, 'role.manage');
  const key = clean(rid, 40).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  if (!/^[a-z][a-z0-9-]{2,39}$/.test(key)) fail('Role key: 3–40 lowercase letters, digits or -.');
  if (ROLES[key] || (await all('roles')).some((r) => r.id === key)) fail('A role with this key already exists.');
  if (clean(label, 60).length < 3) fail('Role name needs 3+ characters.');
  const list = Array.isArray(perms) ? perms.filter((p) => typeof p === 'string') : [];
  if (!list.length) fail('Select at least one permission.');
  const role = { id: key, label: clean(label, 60), desc: clean(desc, 200), perms: [...new Set(list)], custom: true, createdAt: Date.now(), createdBy: a.id };
  await put('roles', role);
  registerRoles(await all('roles'));
  await log(a, 'ROLE_CREATED', `${key} perms=${role.perms.length}`);
  return role;
}
export async function updateRole(a, role, patch) {
  need(a, 'role.manage');
  if (!role.custom) fail('Predefined roles cannot be edited. Create a custom role instead.');
  const next = { ...role, label: patch.label !== undefined ? clean(patch.label, 60) : role.label, desc: patch.desc !== undefined ? clean(patch.desc, 200) : role.desc, perms: patch.perms ? [...new Set(patch.perms)] : role.perms };
  if (!next.perms.length) fail('A role needs at least one permission.');
  await put('roles', next); registerRoles(await all('roles'));
  await log(a, 'ROLE_UPDATED', `${role.id} perms=${next.perms.length}`);
  return 'Role updated. Affected users see the change on their next request.';
}
export async function deleteRole(a, role) {
  need(a, 'role.manage');
  if (!role.custom) fail('Predefined roles cannot be deleted.');
  if ((await all('users')).some((u) => u.role === role.id)) fail('Role is still assigned to users.');
  await put('roles', { ...role, deleted: true }); registerRoles((await all('roles')).filter((r) => !r.deleted));
  await log(a, 'ROLE_DELETED', role.id);
  return 'Role deleted.';
}
export const effectivePermissions = (u) => ({ role: u.role, label: roleLabel(u.role), perms: permissionsOf(u.role) });
