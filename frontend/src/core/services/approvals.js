import { all, get, put } from '../db/db';
import { clean } from '../security/sanitize';
import { id, need, fail, log, assertScope, requireReason } from './common';

export const KINDS = {
  'role-change': 'Role assignment',
  'release-approve': 'Release approval',
  'policy-rollback': 'Policy rollback',
  'config-change': 'Configuration change',
  'device-reauth': 'Device reauthorisation',
  'exam-approve': 'Exam approval',
  'billing-change': 'Subscription change',
  'privacy-deletion': 'Data deletion request',
};
export const OPEN = ['pending'];

export async function create(a, { kind, label, targetId, tenantId, reason, data = {} }) {
  need(a, 'approval.view');
  if (!KINDS[kind]) fail('Unknown approval type.');
  const r = requireReason(reason, 8);
  const list = await all('approvals');
  if (list.some((x) => x.status === 'pending' && x.kind === kind && x.targetId === targetId)) fail('An identical request is already pending.');
  const ap = { id: id('apr'), kind, label: clean(label, 140), targetId, tenantId: tenantId || a.tenantId || null, requestedBy: a.id, reason: r, data, status: 'pending', createdAt: Date.now() };
  await put('approvals', ap); await log(a, 'APPROVAL_REQUESTED', `${kind}: ${ap.label}`);
  return ap;
}

export async function decide(a, ap, approve, note = '') {
  need(a, 'approval.decide');
  if (ap.status !== 'pending') fail('This request has already been decided.');
  if (ap.requestedBy === a.id) fail('You cannot decide your own request (two-person rule).');
  if (ap.tenantId && ap.tenantId !== a.tenantId && a.role !== 'superadmin') fail('This request belongs to another institution.');
  const n = clean(note, 300);
  if (!approve && n.length < 5) fail('Give a short rejection note (5+ characters).');
  let applied = null;
  if (approve) {
    try { applied = await apply(ap, a); }
    catch (e) {
      await put('approvals', { ...ap, status: 'failed', decidedBy: a.id, decidedAt: Date.now(), note: n, error: e.message });
      await log(a, 'APPROVAL_FAILED', `${ap.kind}: ${e.message}`);
      fail(`Approved, but applying it failed: ${e.message}`);
    }
  }
  const out = { ...ap, status: approve ? 'approved' : 'rejected', decidedBy: a.id, decidedAt: Date.now(), note: n, result: applied || null };
  await put('approvals', out);
  await log(a, 'APPROVAL_' + (approve ? 'APPROVED' : 'REJECTED'), `${ap.kind}: ${ap.label}`);
  return out;
}

async function apply(ap, a) {
  switch (ap.kind) {
    case 'role-change': return (await import('../../modules/users/service')).applyRoleApproval(ap, a);
    case 'release-approve': return (await import('../../modules/releases/service')).applyReleaseApproval(ap, a);
    case 'policy-rollback': return (await import('../../modules/policies/service')).applyRollbackApproval(ap, a);
    case 'config-change': return (await import('../../modules/settings/service')).applyConfigApproval(ap, a);
    case 'device-reauth': return (await import('../../modules/devices/service')).applyDeviceReauth(ap, a);
    case 'billing-change': return (await import('../../modules/billing/service')).applyBillingChange(ap, a);
    case 'privacy-deletion': return (await import('../../modules/privacy/service')).applyPrivacyDeletion(ap, a);
    default: return 'Recorded (no automated action for this type).';
  }
}

export async function pendingFor(tenantId) {
  const rows = (await all('approvals')).filter((x) => x.status === 'pending');
  return tenantId ? rows.filter((x) => !x.tenantId || x.tenantId === tenantId) : rows;
}

export async function cancel(a, ap, reason) {
  if (ap.requestedBy !== a.id && a.role !== 'superadmin') fail('Only the requester can withdraw this request.');
  if (ap.status !== 'pending') fail('Only pending requests can be withdrawn.');
  const r = requireReason(reason, 5);
  await put('approvals', { ...ap, status: 'withdrawn', decidedBy: a.id, decidedAt: Date.now(), note: r });
  await log(a, 'APPROVAL_WITHDRAWN', `${ap.kind}: ${r}`);
  return 'Request withdrawn.';
}
export const apAge = (ap) => Date.now() - ap.createdAt;
export async function getApproval(id) { return get('approvals', id); }
