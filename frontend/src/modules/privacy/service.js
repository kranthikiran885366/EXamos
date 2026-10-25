import { all, get, put, del, delMany } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason, day } from '../../core/services/common';
import { can } from '../../core/security/rbac';
import { create as requestApproval } from '../../core/services/approvals';

export const REQUEST_TYPES = [
  { v: 'access', l: 'Access / copy of data' }, { v: 'erasure', l: 'Erasure (right to be forgotten)' },
  { v: 'rectification', l: 'Correct inaccurate data' }, { v: 'portability', l: 'Portable export' },
  { v: 'restriction', l: 'Restrict processing' }, { v: 'objection', l: 'Object to processing' },
];
export const SUBJECT_TYPES = [
  { v: 'candidate', l: 'Candidate' }, { v: 'user', l: 'Staff account' }, { v: 'device', l: 'Device' }, { v: 'other', l: 'Other data subject' },
];
export const REQUEST_STATUSES = ['received', 'identity-pending', 'in-review', 'approved', 'rejected', 'fulfilled', 'closed'];
export const DATA_TYPES = [
  { v: 'candidates', l: 'Candidate records' }, { v: 'sessions', l: 'Exam sessions & answers' },
  { v: 'notifications', l: 'Notifications' }, { v: 'support', l: 'Support conversations' },
  { v: 'evidence', l: 'Evidence vault records' }, { v: 'audit', l: 'Audit trail (immutable)' },
  { v: 'attestations', l: 'Attestation quotes' }, { v: 'securityEvents', l: 'Security events' },
];
export const RETENTION_ACTIONS = ['delete', 'anonymize', 'archive'];

export const DATA_MAP = [
  { category: 'Identity', fields: 'Name, roll number, email, account identifier', purpose: 'Candidate identification and exam eligibility', basis: 'Contract / legitimate interest', retention: 'Candidate retention policy' },
  { category: 'Exam delivery', fields: 'Exam assignment, seat, session answers, score, receipt', purpose: 'Deliver and evidence the examination', basis: 'Contract', retention: 'Exam records retention' },
  { category: 'Device trust', fields: 'Device serial, TPM quote, PCR values, compatibility results', purpose: 'Verify the device is trusted before an exam', basis: 'Legitimate interest / security', retention: 'Attestation retention' },
  { category: 'Security', fields: 'Security events, incidents, audit trail', purpose: 'Detect, investigate and evidence misuse', basis: 'Legal obligation / legitimate interest', retention: 'Audit retention (immutable)' },
  { category: 'Support', fields: 'Request text, messages, diagnostics snapshot', purpose: 'Resolve support issues', basis: 'Legitimate interest', retention: 'Support retention' },
  { category: 'Billing', fields: 'Plan, invoices, payment status', purpose: 'Bill for the service', basis: 'Contract / legal obligation', retention: 'Financial records retention' },
];

export async function createPrivacyRequest(a, { tenantId, type, subjectType, subjectId = '', subjectName = '', details = '', dueDays = 30 }) {
  if (!REQUEST_TYPES.some((t) => t.v === type)) fail('Pick a request type.');
  if (!SUBJECT_TYPES.some((t) => t.v === subjectType)) fail('Pick a data subject type.');
  if (tenantId) assertScope(a, tenantId);
  if (!can(a.role, 'privacy.manage') && subjectId !== a.id) fail('You can only raise a request about your own data.');
  if (clean(subjectName, 80).length < 2) fail('Record the data subject name.');
  if (clean(details, 2000).length < 10) fail('Describe the request in 10+ characters.');
  const now = Date.now();
  const r = {
    id: id('dsr'), tenantId: tenantId || a.tenantId || null, type, subjectType,
    subjectId: clean(subjectId, 60), subjectName: clean(subjectName, 80), details: clean(details, 2000),
    status: 'received', receivedAt: now, dueAt: now + Math.max(1, Math.min(90, Number(dueDays) || 30)) * day,
    identityVerified: false, assignedTo: null, notes: [], createdBy: a.id, history: [{ at: now, by: a.id, action: 'Request received' }],
  };
  await put('privacy', r);
  await log(a, 'PRIVACY_REQUEST_CREATED', `${type} · ${r.subjectName}`);
  return r;
}

export async function verifySubject(a, r, note = '') {
  need(a, 'privacy.manage'); if (r.tenantId) assertScope(a, r.tenantId);
  await put('privacy', { ...r, identityVerified: true, status: r.status === 'received' ? 'in-review' : r.status, identityVerifiedBy: a.id, identityVerifiedAt: Date.now(), identityNote: clean(note, 200), history: [...(r.history || []), { at: Date.now(), by: a.id, action: 'Identity verified' }] });
  await log(a, 'PRIVACY_IDENTITY_VERIFIED', r.subjectName);
  return 'Identity verified. The request can now be processed.';
}

export async function assignPrivacy(a, r, assignee) {
  need(a, 'privacy.manage'); if (r.tenantId) assertScope(a, r.tenantId);
  const u = await get('users', assignee); if (!u) fail('Pick a user.');
  await put('privacy', { ...r, assignedTo: assignee, status: 'in-review', history: [...(r.history || []), { at: Date.now(), by: a.id, action: `Assigned to ${assignee}` }] });
  await log(a, 'PRIVACY_ASSIGNED', `${r.subjectName} -> ${assignee}`);
  return 'Request assigned.';
}

export async function setPrivacyStatus(a, r, status, note = '') {
  need(a, 'privacy.manage'); if (r.tenantId) assertScope(a, r.tenantId);
  if (!REQUEST_STATUSES.includes(status)) fail('Unknown request status.');
  if (['approved', 'rejected', 'fulfilled'].includes(status) && !r.identityVerified) fail('Verify the data subject identity first.');
  if (status === 'rejected') requireReason(note, 10);
  const next = { ...r, status, decisionNote: clean(note, 500), history: [...(r.history || []), { at: Date.now(), by: a.id, action: `Status → ${status}`, note: clean(note, 300) }] };
  if (['fulfilled', 'closed'].includes(status)) next.completedAt = Date.now();
  await put('privacy', next);
  await log(a, 'PRIVACY_' + status.toUpperCase().replace(/-/g, '_'), r.subjectName);
  return `Request marked ${status}.`;
}

export async function requestErasure(a, r, reason) {
  need(a, 'privacy.manage'); if (r.tenantId) assertScope(a, r.tenantId);
  if (!r.identityVerified) fail('Verify the data subject identity first.');
  if (!['erasure', 'rectification', 'restriction'].includes(r.type)) fail('This request type does not require an approval-gated action.');
  const ap = await requestApproval(a, { kind: 'privacy-deletion', label: `${r.type} · ${r.subjectName}`, targetId: r.id, tenantId: r.tenantId, reason, data: { type: r.type, subjectType: r.subjectType, subjectId: r.subjectId } });
  await put('privacy', { ...r, approvalId: ap.id, history: [...(r.history || []), { at: Date.now(), by: a.id, action: `Approval requested (${ap.id})` }] });
  return `Approval requested (${ap.id}). A second privileged user must approve the data action.`;
}

/** Handler used by the shared approvals service. */
export async function applyPrivacyDeletion(ap, approver) {
  const r = await get('privacy', ap.targetId); if (!r) fail('The privacy request no longer exists.');
  if (r.tenantId) assertScope(approver, r.tenantId);
  let result = 'Recorded.';
  if (r.type === 'erasure' && r.subjectType === 'candidate' && r.subjectId) {
    const c = await get('candidates', r.subjectId);
    if (!c) fail('Candidate record not found.');
    const open = (await all('sessions')).some((s) => s.candidateId === c.id && s.status === 'in_progress');
    if (open) fail('An exam session is in progress for this candidate.');
    await put('candidates', { ...c, name: 'Erased subject', email: `erased+${c.id}@invalid.local`, identity: 'exempt', erasedAt: Date.now(), erasedBy: approver.id, examId: null, centerId: null, seat: null });
    result = 'Candidate identity fields erased and assignments cleared.';
  } else if (r.type === 'erasure' && r.subjectType === 'user' && r.subjectId) {
    const u = await get('users', r.subjectId);
    if (!u) fail('User record not found.');
    if (u.id === approver.id) fail('You cannot erase your own account.');
    await put('users', { ...u, name: 'Erased subject', email: '', status: 'deactivated', erasedAt: Date.now(), erasedBy: approver.id });
    const { revokeUserSessions } = await import('../users/service');
    await revokeUserSessions(u.id, 'privacy erasure');
    result = 'User account anonymised and deactivated; sessions revoked.';
  } else if (r.type === 'restriction') {
    await put('privacy', { ...r, restriction: true });
    result = 'Processing restriction recorded.';
  }
  await put('privacy', { ...r, status: 'fulfilled', completedAt: Date.now(), approvalId: ap.id, history: [...(r.history || []), { at: Date.now(), by: approver.id, action: 'Data action applied by approval' }] });
  await log(approver, 'PRIVACY_ACTION_APPLIED', `${r.type} ${r.subjectName} via ${ap.id}`);
  return result;
}

/* ---------------- Retention ---------------- */
export async function saveRetention(a, { id: pid, tenantId, dataType, retentionDays, action = 'delete', legalBasis = '', status = 'active' }) {
  need(a, 'privacy.manage'); assertScope(a, tenantId);
  if (!DATA_TYPES.some((d) => d.v === dataType)) fail('Pick a data type.');
  if (!RETENTION_ACTIONS.includes(action)) fail('Pick a retention action.');
  if (dataType === 'audit') fail('The audit trail is immutable and cannot be deleted by retention.');
  const days = Number(retentionDays);
  if (!(days >= 30 && days <= 3650)) fail('Retention must be 30–3,650 days.');
  const existing = pid ? await get('retention', pid) : null;
  const rec = {
    id: existing?.id || id('ret'), tenantId, dataType, retentionDays: days, action,
    legalBasis: clean(legalBasis, 200), status, lastRunAt: existing?.lastRunAt || null,
    nextRunAt: Date.now() + days * day, updatedAt: Date.now(), updatedBy: a.id,
  };
  await put('retention', rec);
  await log(a, 'RETENTION_POLICY_SAVED', `${dataType} ${days}d ${action}`);
  return 'Retention policy saved.';
}

export async function runRetention(a, policy, dryRun = true) {
  need(a, 'privacy.manage'); assertScope(a, policy.tenantId);
  if (policy.dataType === 'audit') fail('The audit trail is immutable.');
  const cutoff = Date.now() - policy.retentionDays * day;
  const rows = (await all(policy.dataType)).filter((x) => x.tenantId === policy.tenantId && (x.createdAt || x.at || x.issuedAt || 0) < cutoff);
  if (dryRun) {
    await log(a, 'RETENTION_DRY_RUN', `${policy.dataType} would affect ${rows.length}`);
    return `${rows.length} record(s) would be affected by ${policy.action}. Nothing was changed.`;
  }
  if (policy.action === 'delete') {
    await delMany(policy.dataType, rows.map((r) => r.id));
  } else if (policy.action === 'anonymize') {
    for (const r of rows) {
      if (policy.dataType === 'candidates') await put('candidates', { ...r, name: 'Retained subject', email: `retained+${r.id}@invalid.local` });
      else if (policy.dataType === 'support') await put('support', { ...r, subject: 'Retained request', description: 'Content removed by retention policy', messages: [] });
      else await put(policy.dataType, { ...r, anonymized: true, anonymizedAt: Date.now() });
    }
  } else {
    for (const r of rows) await put(policy.dataType, { ...r, archived: true, archivedAt: Date.now() });
  }
  await put('retention', { ...policy, lastRunAt: Date.now(), nextRunAt: Date.now() + policy.retentionDays * day, lastCount: rows.length });
  await log(a, 'RETENTION_RUN', `${policy.dataType} ${policy.action} count=${rows.length}`);
  return `${rows.length} record(s) processed (${policy.action}).`;
}

export async function deleteRetention(a, p, reason) {
  need(a, 'privacy.manage'); assertScope(a, p.tenantId);
  const r = requireReason(reason, 8);
  await put('retention', { ...p, status: 'retired', retiredAt: Date.now(), retiredBy: a.id, retireReason: r });
  await log(a, 'RETENTION_RETIRED', `${p.dataType}: ${r}`);
  return 'Retention policy retired.';
}

export function privacyStats(requests, retention) {
  const now = Date.now();
  return {
    total: requests.length, open: requests.filter((r) => !['fulfilled', 'closed', 'rejected'].includes(r.status)).length,
    overdue: requests.filter((r) => !['fulfilled', 'closed', 'rejected'].includes(r.status) && r.dueAt < now).length,
    erasure: requests.filter((r) => r.type === 'erasure').length,
    fulfilled: requests.filter((r) => r.status === 'fulfilled').length,
    policies: retention.filter((p) => p.status === 'active').length,
    nextRun: retention.filter((p) => p.status === 'active').sort((a, b) => (a.nextRunAt || 0) - (b.nextRunAt || 0))[0]?.nextRunAt || null,
  };
}

export async function dataSubjectExport(a, r) {
  need(a, 'privacy.manage'); if (r.tenantId) assertScope(a, r.tenantId);
  const out = { request: { id: r.id, type: r.type, subject: r.subjectName, receivedAt: r.receivedAt }, generatedAt: Date.now(), data: {} };
  if (r.subjectType === 'candidate' && r.subjectId) {
    out.data.candidate = await get('candidates', r.subjectId);
    out.data.sessions = (await all('sessions')).filter((s) => s.candidateId === r.subjectId);
  } else if (r.subjectType === 'user' && r.subjectId) {
    out.data.user = await get('users', r.subjectId);
    out.data.sessions = (await all('authSessions')).filter((s) => s.userId === r.subjectId);
  }
  await log(a, 'PRIVACY_EXPORT', r.subjectName);
  return out;
}

export async function purgeNotification(a, n) {
  need(a, 'privacy.manage');
  await del('notifications', n.id);
  await log(a, 'NOTIFICATION_PURGED', n.title);
  return 'Notification purged.';
}
