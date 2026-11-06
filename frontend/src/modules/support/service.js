// SPPIO / ExamOS Support module — frontend service layer.
//
// The backend (server/controllers/support_controller.c, backed by the
// migration 032 tables) is the source of truth. This module only calls the
// server over the authenticated API client; it does NOT enforce authorization,
// generate ids, compute SLA deadlines, or fabricate diagnostics in the browser.
// Display-only helpers (isOpen/isBreached/slaText/supportStats) operate on
// server-provided records.

import { api } from '../../core/api/client';

const BASE = '/api/v1/support';

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
const OPEN = ['new', 'assigned', 'waiting', 'in-progress', 'reopened'];

/* ------------------------------------------------------------------ reads */

export async function listRequests() {
  const { data } = await api.get(`${BASE}/requests`, { actor: 'console', sign: false });
  return Array.isArray(data) ? data : [];
}

export async function getRequest(id) {
  const { data } = await api.get(`${BASE}/requests/${encodeURIComponent(id)}`, { actor: 'console', sign: false });
  return data;
}

export async function getStats() {
  const { data } = await api.get(`${BASE}/stats`, { actor: 'console', sign: false });
  return data || {};
}

export async function listRecovery() {
  const { data } = await api.get(`${BASE}/recovery`, { actor: 'console', sign: false });
  return Array.isArray(data) ? data : [];
}

/* Real, server-computed diagnostics (no client-side fabrication). */
export async function diagnostics() {
  const { data } = await api.get(`${BASE}/diagnostics`, { actor: 'console', sign: false });
  return data || { checks: [], database: false, read_only: true };
}

/* Real service-status overview (uptime is honestly "insufficient-data"). */
export async function statusOverview() {
  const { data } = await api.get(`${BASE}/status`, { actor: 'console', sign: false });
  return data || { overall: 'unknown', services: 0, down: 0, degraded: 0, alerts: 0 };
}

/* ------------------------------------------------------------------ writes */

export async function createRequest(_user, payload) {
  const { data } = await api.post(`${BASE}/requests`, {
    tenantId: payload.tenantId || null,
    subject: payload.subject,
    description: payload.description,
    category: payload.category || 'other',
    priority: payload.priority || 'normal',
    linkedDeviceId: payload.linkedDeviceId || '',
    linkedExamId: payload.linkedExamId || '',
    requesterName: payload.requesterName || '',
  }, { actor: 'console', sign: true });
  return data;
}

export async function addMessage(_user, t, text, internal = false) {
  await api.post(`${BASE}/requests/${encodeURIComponent(t.id)}/comments`, { text, internal: !!internal },
    { actor: 'console', sign: true });
  return 'Message added.';
}

export async function assignRequest(_user, t, assignee, reason = '') {
  await api.post(`${BASE}/requests/${encodeURIComponent(t.id)}/assign`, { assignee, reason },
    { actor: 'console', sign: true });
  return `${t.no} assigned.`;
}

export async function setStatus(_user, t, status, note = '') {
  await api.post(`${BASE}/requests/${encodeURIComponent(t.id)}/status`, { status, note },
    { actor: 'console', sign: true });
  return `${t.no} is now ${status}.`;
}

export async function escalateRequest(_user, t, reason) {
  const { data } = await api.post(`${BASE}/requests/${encodeURIComponent(t.id)}/escalate`, { reason },
    { actor: 'console', sign: true });
  return `Escalated to ${data?.incidentId || 'incident'}.`;
}

export async function rateRequest(_user, t, score) {
  await api.post(`${BASE}/requests/${encodeURIComponent(t.id)}/rate`, { score: Number(score) },
    { actor: 'console', sign: true });
  return 'Thanks — your rating was recorded.';
}

export async function initiateRecovery(_user, payload) {
  const { data } = await api.post(`${BASE}/recovery`, {
    tenantId: payload.tenantId || null,
    kind: payload.kind,
    target: payload.target,
    reason: payload.reason,
  }, { actor: 'console', sign: true });
  return `${data?.ticketNo || 'Case'} opened. Recovery is gated behind approval and fully audited.`;
}

/* ------------------------------------------------------------------ display helpers (operate on server records) */

export const isOpen = (t) => OPEN.includes(t.status);
export const isBreached = (t, now = Date.now()) => isOpen(t) && t.slaDue && now > t.slaDue && !t.firstResponseAt;
export const slaLeft = (t, now = Date.now()) => (t.slaDue ? t.slaDue - now : 0);

export function supportStats(list, now = Date.now()) {
  const rated = list.filter((t) => t.satisfactionScore);
  const responded = list.filter((t) => t.firstResponseAt);
  return {
    total: list.length,
    open: list.filter(isOpen).length,
    critical: list.filter((t) => t.priority === 'critical' && isOpen(t)).length,
    breached: list.filter((t) => isBreached(t, now)).length,
    resolved: list.filter((t) => ['resolved', 'closed'].includes(t.status)).length,
    avgSatisfaction: rated.length ? +(rated.reduce((s, t) => s + t.satisfactionScore, 0) / rated.length).toFixed(1) : 0,
    firstResponseMins: responded.length ? Math.round(responded.reduce((s, t) => s + (t.firstResponseAt - t.createdAt), 0) / responded.length / 60000) : 0,
  };
}
