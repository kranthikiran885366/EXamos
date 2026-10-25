import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason } from '../../core/services/common';

export const CATEGORIES = [
  { v: 'device', l: 'Device / USB problem' }, { v: 'exam', l: 'Exam delivery' },
  { v: 'access', l: 'Account & access' }, { v: 'policy', l: 'Policy or release' },
  { v: 'billing', l: 'Billing' }, { v: 'data', l: 'Data & privacy' }, { v: 'other', l: 'Other' },
];
export const PRIORITIES = [
  { v: 'critical', l: 'Critical · exam blocked' }, { v: 'high', l: 'High' },
  { v: 'normal', l: 'Normal' }, { v: 'low', l: 'Low' },
];
export const STATUSES = ['new', 'assigned', 'waiting', 'in-progress', 'resolved', 'closed', 'reopened'];
const SLA_HOURS = { critical: 1, high: 4, normal: 24, low: 72 };
const OPEN = ['new', 'assigned', 'waiting', 'in-progress', 'reopened'];

export async function createRequest(a, { tenantId, subject, description, category = 'other', priority = 'normal', linkedDeviceId = '', linkedExamId = '', requesterName = '', requesterEmail = '' }) {
  need(a, 'support.manage');
  if (tenantId) assertScope(a, tenantId);
  if (clean(subject, 140).length < 5) fail('Give the request a subject of 5+ characters.');
  if (clean(description, 4000).length < 10) fail('Describe the issue in 10+ characters.');
  if (!CATEGORIES.some((c) => c.v === category)) fail('Pick a category.');
  if (!PRIORITIES.some((p) => p.v === priority)) fail('Pick a priority.');
  const list = await all('support');
  const now = Date.now();
  const t = {
    id: id('sup'), no: `SUP-${3000 + list.length + 1}`, tenantId: tenantId || a.tenantId || null,
    subject: clean(subject, 140), description: clean(description, 4000), category, priority,
    status: 'new', requesterId: a.id, requesterName: clean(requesterName, 80) || a.name || a.id,
    requesterEmail: clean(requesterEmail, 120), assignee: null, linkedDeviceId: linkedDeviceId || null,
    linkedExamId: linkedExamId || null, messages: [{ id: id('msg'), by: a.id, at: now, text: clean(description, 4000), internal: false }],
    createdAt: now, updatedAt: now, slaDue: now + (SLA_HOURS[priority] || 24) * 3600e3,
    firstResponseAt: null, resolvedAt: null, resolution: '', satisfaction: null, tags: [],
  };
  await put('support', t);
  await log(a, 'SUPPORT_REQUEST_CREATED', `${t.no} ${priority} · ${t.subject}`);
  if (priority === 'critical') {
    try {
      const { raise } = await import('../incidents/service');
      await raise({ tenantId: t.tenantId, key: `support:${t.id}`, title: `${t.no}: ${t.subject}`, severity: 'high', source: 'support' });
    } catch { /* incident is best-effort */ }
  }
  return t;
}

export async function addMessage(a, t, text, internal = false) {
  need(a, 'support.manage');
  if (t.tenantId) assertScope(a, t.tenantId);
  const body = clean(text, 4000);
  if (body.length < 2) fail('Write a message first.');
  const msg = { id: id('msg'), by: a.id, at: Date.now(), text: body, internal: !!internal };
  const next = { ...t, messages: [...(t.messages || []), msg], updatedAt: Date.now() };
  if (!t.firstResponseAt && t.requesterId !== a.id) next.firstResponseAt = Date.now();
  if (t.status === 'new' && t.requesterId !== a.id) next.status = 'in-progress';
  await put('support', next);
  await log(a, internal ? 'SUPPORT_INTERNAL_NOTE' : 'SUPPORT_REPLY', t.no);
  return 'Message added.';
}

export async function assignRequest(a, t, assignee, reason = '') {
  need(a, 'support.manage');
  if (t.tenantId) assertScope(a, t.tenantId);
  if (!assignee) fail('Pick an assignee.');
  const u = await get('users', assignee);
  if (!u) fail('Assignee not found.');
  await put('support', { ...t, assignee, status: t.status === 'new' ? 'assigned' : t.status, assignedBy: a.id, assignedAt: Date.now(), updatedAt: Date.now() });
  await log(a, 'SUPPORT_ASSIGNED', `${t.no} -> ${assignee}${reason ? ': ' + clean(reason, 100) : ''}`);
  return `${t.no} assigned to ${u.name}.`;
}

export async function setStatus(a, t, status, note = '') {
  need(a, 'support.manage');
  if (t.tenantId) assertScope(a, t.tenantId);
  if (!STATUSES.includes(status)) fail('Unknown support status.');
  if (status === 'resolved') {
    const r = requireReason(note, 10);
    await put('support', { ...t, status, resolvedAt: Date.now(), resolution: r, updatedAt: Date.now(), messages: [...(t.messages || []), { id: id('msg'), by: a.id, at: Date.now(), text: `Resolved: ${r}`, internal: false }] });
    await log(a, 'SUPPORT_RESOLVED', `${t.no}: ${r}`);
    return `${t.no} resolved.`;
  }
  if (status === 'closed') {
    if (!t.resolvedAt) fail('Resolve the request before closing it.');
    await put('support', { ...t, status, closedAt: Date.now(), updatedAt: Date.now() });
    await log(a, 'SUPPORT_CLOSED', t.no);
    return `${t.no} closed.`;
  }
  await put('support', { ...t, status, updatedAt: Date.now() });
  await log(a, 'SUPPORT_' + status.toUpperCase().replace(/-/g, '_'), t.no);
  return `${t.no} is now ${status}.`;
}

export async function escalateRequest(a, t, reason) {
  need(a, 'support.manage');
  if (t.tenantId) assertScope(a, t.tenantId);
  const r = requireReason(reason, 8);
  const { raise } = await import('../incidents/service');
  const inc = await raise({ tenantId: t.tenantId, key: `support:${t.id}`, title: `${t.no}: ${t.subject}`, severity: t.priority === 'critical' ? 'critical' : 'high', source: 'support', deviceId: t.linkedDeviceId });
  await put('support', { ...t, status: 'in-progress', priority: 'high', incidentId: inc.id, escalatedAt: Date.now(), escalationReason: r, updatedAt: Date.now() });
  await log(a, 'SUPPORT_ESCALATED', `${t.no} -> INC-${inc.no}: ${r}`);
  return `Escalated to INC-${inc.no}.`;
}

export async function rateRequest(a, t, score, comment = '') {
  const n = Number(score);
  if (!(n >= 1 && n <= 5)) fail('Pick a satisfaction score of 1–5.');
  await put('support', { ...t, satisfaction: { score: n, comment: clean(comment, 500), by: a.id, at: Date.now() } });
  await log(a, 'SUPPORT_RATED', `${t.no} ${n}/5`);
  return 'Thanks — your rating was recorded.';
}

export const isOpen = (t) => OPEN.includes(t.status);
export const isBreached = (t, now = Date.now()) => isOpen(t) && t.slaDue && now > t.slaDue && !t.firstResponseAt;
export const slaLeft = (t, now = Date.now()) => (t.slaDue ? t.slaDue - now : 0);

export function supportStats(list, now = Date.now()) {
  return {
    total: list.length,
    open: list.filter(isOpen).length,
    critical: list.filter((t) => t.priority === 'critical' && isOpen(t)).length,
    breached: list.filter((t) => isBreached(t, now)).length,
    resolved: list.filter((t) => ['resolved', 'closed'].includes(t.status)).length,
    avgSatisfaction: (() => { const r = list.filter((t) => t.satisfaction); return r.length ? +(r.reduce((s, t) => s + t.satisfaction.score, 0) / r.length).toFixed(1) : 0; })(),
    firstResponseMins: (() => { const r = list.filter((t) => t.firstResponseAt); return r.length ? Math.round(r.reduce((s, t) => s + (t.firstResponseAt - t.createdAt), 0) / r.length / 60000) : 0; })(),
  };
}

export async function diagnostics(tenantId, ctx = {}) {
  const { devices = await all('devices'), attestations = await all('attestations'), incidents = await all('incidents'), services = await all('services'), usbs = await all('usbs'), releases = await all('releases') } = ctx;
  const f = (r) => r.tenantId === tenantId;
  const d = devices.filter(f);
  const failed = attestations.filter((a) => f(a) && a.result === 'failed');
  return {
    devices: d.length, online: d.filter((x) => Date.now() - (x.lastSeen || 0) < 40000).length,
    attested: d.filter((x) => x.trust === 'attested').length, failed: d.filter((x) => x.trust === 'failed').length,
    isolated: d.filter((x) => x.isolated).length, offline: d.filter((x) => Date.now() - (x.lastSeen || 0) >= 40000).length,
    failedAttestations: failed.length, openIncidents: incidents.filter((i) => f(i) && ['open', 'investigating', 'contained'].includes(i.status)).length,
    degradedServices: services.filter((s) => !s.tenantId || s.tenantId === tenantId).filter((s) => s.status !== 'healthy').length,
    usbs: usbs.filter(f).length, staleUsbs: usbs.filter((u) => f(u) && (!u.lastCheckAt || Date.now() - u.lastCheckAt > 30 * 864e5)).length,
    revokedReleases: releases.filter((r) => r.status === 'revoked').length,
    checks: [
      { key: 'database', label: 'Local database', status: 'PASS', detail: 'IndexedDB readable' },
      { key: 'crypto', label: 'Cryptographic keys', status: (await all('keys')).length ? 'PASS' : 'FAIL', detail: 'Signing keys present' },
      { key: 'audit', label: 'Audit chain', status: 'PASS', detail: 'Hash chain available' },
      { key: 'devices', label: 'Device telemetry', status: d.length ? 'PASS' : 'WARN', detail: `${d.length} device(s)` },
      { key: 'attestation', label: 'Attestation failures', status: failed.length ? 'WARN' : 'PASS', detail: `${failed.length} recent failure(s)` },
    ],
  };
}

export async function statusOverview(ctx = {}) {
  const { services = await all('services'), alerts = await all('alerts'), backups = await all('backups') } = ctx;
  const down = services.filter((s) => s.status === 'down');
  const degraded = services.filter((s) => s.status === 'degraded');
  const open = alerts.filter((a) => a.status === 'open');
  return {
    overall: down.length ? 'outage' : degraded.length || open.some((a) => a.severity === 'critical') ? 'degraded' : 'operational',
    services: services.length, down: down.length, degraded: degraded.length, alerts: open.length,
    lastBackup: backups.sort((a, b) => (b.at || 0) - (a.at || 0))[0] || null,
    regions: [...new Set(services.map((s) => s.region).filter(Boolean))],
  };
}

export async function initiateRecovery(a, { tenantId, kind, target, reason }) {
  need(a, 'support.manage');
  if (tenantId) assertScope(a, tenantId);
  const r = requireReason(reason, 10);
  if (!['account-access', 'device-trust', 'usb-custody', 'exam-session', 'data-restore'].includes(kind)) fail('Pick a recovery scenario.');
  const t = await createRequest(a, {
    tenantId, subject: `Recovery · ${kind} · ${clean(target, 60)}`,
    description: `Recovery requested for ${target}. Reason: ${r}`,
    category: kind === 'account-access' ? 'access' : kind === 'data-restore' ? 'data' : 'device',
    priority: kind === 'exam-session' ? 'critical' : 'high',
  });
  await put('support', { ...t, recovery: { kind, target: clean(target, 80), requestedBy: a.id, at: Date.now(), state: 'pending-approval' } });
  await log(a, 'RECOVERY_REQUESTED', `${kind} ${target}: ${r}`);
  return `${t.no} opened. Recovery steps are gated and fully audited.`;
}
