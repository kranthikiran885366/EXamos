// Device module facade. Device lifecycle lives in the fleet service; attestation lives in tpm.
export * from '../fleet/service';
export { attest as attestDevice } from '../tpm/service';
import { all, get } from '../../core/db/db';
import { attest } from '../tpm/service';
import { fail } from '../../core/services/common';

export async function attestDeviceFor(a, deviceId) {
  return attest(a, deviceId);
}

export async function deviceDetail(deviceId, ctx = {}) {
  const { attestations = await all('attestations'), compat = await all('compat'), incidents = await all('incidents'), policies = await all('policies'), releases = await all('releases'), centers = await all('centers'), sessions = await all('sessions') } = ctx;
  const d = await get('devices', deviceId);
  if (!d) fail('Device not found.');
  return {
    device: d, center: centers.find((c) => c.id === d.centerId) || null,
    policy: policies.find((p) => p.id === d.policyId) || null,
    release: releases.find((r) => r.id === d.releaseId) || null,
    attestations: attestations.filter((x) => x.deviceId === d.id).sort((a, b) => b.issuedAt - a.issuedAt),
    compat: compat.filter((x) => x.deviceId === d.id).sort((a, b) => b.runAt - a.runAt),
    incidents: incidents.filter((x) => x.deviceId === d.id).sort((a, b) => b.createdAt - a.createdAt),
    sessions: sessions.filter((x) => x.deviceId === d.id).sort((a, b) => b.startedAt - a.startedAt),
  };
}

export function timelineFor(detail) {
  const out = [];
  for (const a of detail.attestations) out.push({ id: a.id, title: 'Legacy attestation record (unverified)', meta: new Date(a.verifiedAt || a.issuedAt).toLocaleString('en-IN'), body: a.reason || '', tone: '' });
  for (const c of detail.compat) out.push({ id: c.id, title: `Compatibility ${c.overall}`, meta: new Date(c.runAt).toLocaleString('en-IN'), body: `${c.checks.filter((x) => x.effective === 'PASS').length}/${c.checks.length} checks passed` });
  for (const i of detail.incidents) out.push({ id: i.id, title: `INC-${i.no} · ${i.title}`, meta: new Date(i.createdAt).toLocaleString('en-IN'), body: i.status, tone: i.severity === 'critical' ? 'r' : '' });
  for (const s of detail.sessions) out.push({ id: s.id, title: `Exam session ${s.status}`, meta: new Date(s.startedAt).toLocaleString('en-IN'), body: s.receipt || '' });
  return out.sort((a, b) => (Date.parse(b.meta) || 0) - (Date.parse(a.meta) || 0));
}

export const deviceLabel = (d) => d ? `${d.hostname} · ${d.seat}` : '—';
