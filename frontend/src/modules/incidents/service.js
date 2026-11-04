import { all, put } from '../../core/db/db';
import { record } from '../../core/security/auditChain';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log } from '../../core/services/common';
import * as Api from '../../core/api/services';

const OPEN = ['open', 'investigating', 'contained'];
export const FLOW = { open: ['investigating'], investigating: ['contained', 'resolved'], contained: ['resolved'], resolved: ['closed', 'investigating'], closed: [], false_positive: [] };

export async function listIncidents(tenantId) {
  return (await all('incidents')).filter((i) => !tenantId || i.tenantId === tenantId);
}

export async function raise({ tenantId, key, title, severity = 'medium', source, deviceId = null }) {
  const list = await all('incidents');
  const ex = list.find((i) => i.key === key && OPEN.includes(i.status)); if (ex) return ex;
  const inc = {
    id: id('inc'), tenantId, key, title, severity, source, deviceId, kind: 'alert', status: 'open',
    owner: null, notes: [], createdAt: Date.now(),
  };
  await put('incidents', inc);
  await record('system', 'INCIDENT_RAISED', `${inc.id} ${title}`);
  return inc;
}

export async function move(a, i, to) {
  need(a, 'incident.manage');
  if (!FLOW[i.status]?.includes(to)) fail(`Cannot go from ${i.status} to ${to}.`);
  if (to === 'resolved' && !i.notes.length) fail('Add an investigation note before resolving.');
  await put('incidents', { ...i, status: to, owner: i.owner || a.id });
  await log(a, 'INCIDENT_' + to.toUpperCase(), `INC-${i.no}`);
  return `INC-${i.no} is now ${to}.`;
}

export async function addNote(a, i, text) {
  need(a, 'incident.manage'); text = clean(text, 400); if (text.length < 5) fail('Note is too short.');
  await put('incidents', { ...i, notes: [...i.notes, { by: a.id, at: Date.now(), text }] });
  await log(a, 'INCIDENT_NOTE', `INC-${i.no}`);
}

export async function assign(a, i, owner) {
  need(a, 'incident.manage');
  await put('incidents', { ...i, owner });
  await log(a, 'INCIDENT_ASSIGNED', `INC-${i.no} -> ${owner}`);
}

export async function falsePositive(a, i, why) {
  need(a, 'incident.manage'); if (!OPEN.includes(i.status)) fail('Only open incidents can be dismissed.');
  if ((why || '').length < 10) fail('Justify the false-positive call in 10+ characters.');
  await put('incidents', { ...i, status: 'false_positive', notes: [...i.notes, { by: a.id, at: Date.now(), text: 'False positive: ' + clean(why, 300) }] });
  await log(a, 'INCIDENT_FALSE_POSITIVE', `INC-${i.no}: ${why}`);
}

export async function promote(a, i) {
  need(a, 'incident.manage'); if (i.kind === 'finding') fail('Already a reviewed finding.'); if (!i.notes.length) fail('Add a review note before promoting.');
  await put('incidents', { ...i, kind: 'finding', reviewedBy: a.id });
  await log(a, 'INCIDENT_PROMOTED', `INC-${i.no}`);
}
