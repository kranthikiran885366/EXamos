import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope } from '../../core/services/common';

export const CHANNELS = [
  { v: 'in-app', l: 'In-app inbox' }, { v: 'email', l: 'Email' }, { v: 'both', l: 'In-app + email' },
];
export const TONES = [
  { v: 'info', l: 'Information' }, { v: 'success', l: 'Success' }, { v: 'warn', l: 'Warning' }, { v: 'danger', l: 'Critical' },
];
export const AUDIENCES = [
  { v: 'all', l: 'Everyone in the institution' }, { v: 'students', l: 'Students / candidates' },
  { v: 'staff', l: 'Staff' }, { v: 'admins', l: 'Administrators' }, { v: 'role', l: 'A specific role' },
];
export const TEMPLATES = [
  { key: 'exam-reminder', label: 'Exam reminder', title: 'Your exam starts soon', body: 'Check your device and identity documents before the briefing.' },
  { key: 'schedule-change', label: 'Schedule change', title: 'Exam schedule updated', body: 'The exam window has changed. Review the new schedule in your assignments.' },
  { key: 'policy-update', label: 'Policy update', title: 'Security policy updated', body: 'A new policy version will be applied to your device before the next session.' },
  { key: 'maintenance', label: 'Maintenance notice', title: 'Planned maintenance', body: 'The console will be read-only during the maintenance window.' },
  { key: 'submission', label: 'Submission receipt', title: 'Submission received', body: 'Your submission receipt is available in History & receipts.' },
  { key: 'support', label: 'Support update', title: 'Your support request was updated', body: 'Open the request to read the latest response.' },
];

export async function broadcast({ tenantId, userId = null, role = null, title, body = '', link = '', tone = 'info', channel = 'in-app', kind = 'system', createdBy = 'system' }) {
  if (!clean(title, 140)) throw new Error('Notification title is required.');
  const n = {
    id: id('ntf'), tenantId: tenantId || null, userId, role, title: clean(title, 140), body: clean(body, 600),
    link: clean(link, 300), tone: TONES.some((t) => t.v === tone) ? tone : 'info',
    channel, kind: clean(kind, 30), readBy: [], archivedBy: [], createdAt: Date.now(), createdBy,
  };
  await put('notifications', n);
  return n;
}

export async function sendNotification(a, input) {
  need(a, 'notify.manage');
  const tenantId = input.tenantId || a.tenantId || null;
  if (tenantId) assertScope(a, tenantId);
  if (!AUDIENCES.some((x) => x.v === input.audience)) fail('Pick an audience.');
  if (input.audience === 'role' && !input.role) fail('Pick the target role.');
  const scheduledAt = input.scheduledAt ? Date.parse(input.scheduledAt) : null;
  const targets = [];
  if (input.audience === 'all' || input.audience === 'students' || input.audience === 'staff' || input.audience === 'admins') {
    const users = await all('users');
    const pool = users.filter((u) => (!tenantId || u.tenantId === tenantId) && u.status === 'active');
    if (input.audience === 'students') targets.push(...pool.filter((u) => u.role === 'student').map((u) => u.id));
    else if (input.audience === 'staff') targets.push(...pool.filter((u) => u.role !== 'student').map((u) => u.id));
    else if (input.audience === 'admins') targets.push(...pool.filter((u) => ['superadmin', 'inst_admin', 'exam_controller', 'it_admin', 'ops_admin'].includes(u.role)).map((u) => u.id));
    else targets.push(...pool.map((u) => u.id));
  }
  const base = {
    tenantId, role: input.audience === 'role' ? input.role : null, title: input.title, body: input.body,
    link: input.link, tone: input.tone, channel: input.channel, kind: 'broadcast', createdBy: a.id,
  };
  if (scheduledAt && scheduledAt > Date.now()) {
    const rec = { id: id('ntf'), ...base, title: clean(input.title, 140), body: clean(input.body, 600), userId: null, status: 'scheduled', scheduledAt, readBy: [], archivedBy: [], createdAt: Date.now() };
    await put('notifications', rec);
    await log(a, 'NOTIFICATION_SCHEDULED', `${rec.title} at ${new Date(scheduledAt).toISOString()}`);
    return `Scheduled for ${new Date(scheduledAt).toLocaleString('en-IN')}.`;
  }
  if (input.audience === 'role') {
    await broadcast({ ...base, userId: null });
  } else if (targets.length) {
    for (const uid of targets) await broadcast({ ...base, userId: uid });
  } else {
    await broadcast({ ...base, userId: null });
  }
  await log(a, 'NOTIFICATION_SENT', `${clean(input.title, 80)} audience=${input.audience}`);
  return `Notification sent to ${targets.length || 'the selected audience'}.`;
}

export async function markRead(userId, n) {
  if (!n) return;
  if ((n.readBy || []).includes(userId)) return;
  await put('notifications', { ...n, readBy: [...(n.readBy || []), userId] });
}
export async function markAllRead(userId, list) {
  for (const n of list) if (!(n.readBy || []).includes(userId)) await put('notifications', { ...n, readBy: [...(n.readBy || []), userId] });
}
export async function archive(userId, n) {
  await put('notifications', { ...n, archivedBy: [...(n.archivedBy || []), userId] });
}
export async function unarchive(userId, n) {
  await put('notifications', { ...n, archivedBy: (n.archivedBy || []).filter((x) => x !== userId) });
}
export async function remove(a, n) {
  need(a, 'notify.manage');
  await put('notifications', { ...n, deleted: true, deletedBy: a.id, deletedAt: Date.now() });
  await log(a, 'NOTIFICATION_DELETED', n.title);
  return 'Notification removed from the inbox.';
}

export function visibleTo(user, list) {
  return list.filter((n) => !n.deleted && (!n.tenantId || !user.tenantId || n.tenantId === user.tenantId || ['superadmin', 'auditor', 'release_engineer'].includes(user.role))
    && (!n.userId || n.userId === user.id) && (!n.role || n.role === user.role) && !(n.archivedBy || []).includes(user.id)
    && (!n.scheduledAt || n.scheduledAt <= Date.now() || n.status !== 'scheduled'));
}
export const unreadFor = (user, list) => visibleTo(user, list).filter((n) => !(n.readBy || []).includes(user.id)).length;
export const notifStats = (list, userId) => ({
  total: list.length,
  unread: list.filter((n) => !(n.readBy || []).includes(userId)).length,
  scheduled: list.filter((n) => n.status === 'scheduled').length,
  critical: list.filter((n) => n.tone === 'danger').length,
  archived: list.filter((n) => (n.archivedBy || []).includes(userId)).length,
});
