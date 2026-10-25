import { all, get, put } from '../../core/db/db';
import { sha256, canon } from '../../core/security/crypto';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason, pct } from '../../core/services/common';
import { verifyChain } from '../../core/security/auditChain';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const EVENT_TYPES = [
  'attestation-failure', 'boot-integrity', 'policy-violation', 'usb-incident', 'network-block',
  'identity-failure', 'session-anomaly', 'release-integrity', 'access-anomaly', 'device-isolation',
];
export const VULN_STATUSES = ['open', 'triaged', 'mitigating', 'fixed', 'accepted', 'false-positive'];
export const EVIDENCE_KINDS = ['attestation-report', 'release-validation', 'incident-report', 'penetration-test', 'audit-export', 'configuration-baseline', 'other'];
export const EVIDENCE_CLASS = ['internal', 'confidential', 'restricted', 'auditor-only'];

export async function logSecurityEvent(actor, { tenantId, type, severity = 'medium', title, detail = '', deviceId = null, source = 'console' }) {
  if (!tenantId) fail('A security event needs an institution.');
  if (!EVENT_TYPES.includes(type)) fail('Unknown security event type.');
  if (!SEVERITIES.includes(severity)) fail('Unknown severity.');
  const ev = {
    id: id('sec'), tenantId, type, severity, title: clean(title, 140), detail: clean(detail, 500),
    deviceId, source: clean(source, 40), status: 'open', at: Date.now(), actor: actor?.id || 'system',
  };
  await put('securityEvents', ev);
  if (actor?.id) await log(actor, 'SECURITY_EVENT', `${type} · ${ev.title}`);
  return ev;
}

export async function acknowledgeEvent(a, e, note = '') {
  need(a, 'security.manage'); assertScope(a, e.tenantId);
  if (e.status !== 'open') fail('Only open events can be acknowledged.');
  await put('securityEvents', { ...e, status: 'acknowledged', ackBy: a.id, ackAt: Date.now(), note: clean(note, 300) });
  await log(a, 'SECURITY_EVENT_ACK', e.title);
  return 'Event acknowledged.';
}

export async function resolveEvent(a, e, reason) {
  need(a, 'security.manage'); assertScope(a, e.tenantId);
  const r = requireReason(reason, 8);
  if (['resolved', 'closed'].includes(e.status)) fail('This event is already closed.');
  await put('securityEvents', { ...e, status: 'resolved', resolvedBy: a.id, resolvedAt: Date.now(), resolution: r });
  await log(a, 'SECURITY_EVENT_RESOLVED', `${e.title}: ${r}`);
  return 'Event resolved and recorded.';
}

export async function escalateEvent(a, e, reason) {
  need(a, 'security.manage'); assertScope(a, e.tenantId);
  const r = requireReason(reason, 8);
  const { raise } = await import('../incidents/service');
  const inc = await raise({ tenantId: e.tenantId, key: `sec:${e.id}`, title: e.title, severity: e.severity, source: 'security-console', deviceId: e.deviceId });
  await put('securityEvents', { ...e, status: 'escalated', incidentId: inc.id, escalatedBy: a.id, escalatedAt: Date.now(), escalationReason: r });
  await log(a, 'SECURITY_EVENT_ESCALATED', `${e.title} -> INC-${inc.no}: ${r}`);
  return `Escalated to INC-${inc.no}.`;
}

/* ---------------- Vulnerabilities ---------------- */
export async function createVulnerability(a, { tenantId, cve, component, title, severity = 'medium', cvss = 5, affected = '', fixedIn = '', source = 'manual', owner = '' }) {
  need(a, 'security.manage'); assertScope(a, tenantId);
  const c = clean(cve, 30).toUpperCase();
  if (c && !/^CVE-\d{4}-\d{4,}$/.test(c)) fail('CVE id looks like CVE-2024-12345.');
  if (clean(component, 60).length < 2) fail('Name the affected component.');
  if (clean(title, 120).length < 5) fail('Describe the vulnerability in 5+ characters.');
  if (!SEVERITIES.includes(severity)) fail('Pick a severity.');
  const score = Number(cvss);
  if (!(score >= 0 && score <= 10)) fail('CVSS must be 0–10.');
  if ((await all('vulnerabilities')).some((v) => v.tenantId === tenantId && v.cve === c && v.component === component && v.status !== 'fixed')) fail('That finding is already open for this component.');
  const v = {
    id: id('vul'), tenantId, cve: c, component: clean(component, 60), title: clean(title, 120),
    severity, cvss: score, affected: clean(affected, 120), fixedIn: clean(fixedIn, 40),
    source: clean(source, 40), owner: clean(owner, 40), status: 'open', createdAt: Date.now(), createdBy: a.id, history: [],
  };
  await put('vulnerabilities', v);
  await log(a, 'VULNERABILITY_CREATED', `${c || v.component} ${severity}`);
  return v;
}

export async function updateVulnerability(a, v, patch, reason = '') {
  need(a, 'security.manage'); assertScope(a, v.tenantId);
  const next = { ...v };
  if (patch.status !== undefined) {
    if (!VULN_STATUSES.includes(patch.status)) fail('Unknown vulnerability status.');
    if (['accepted', 'false-positive'].includes(patch.status)) next.acceptReason = requireReason(reason, 10);
    if (patch.status === 'fixed') next.fixedAt = Date.now();
    next.status = patch.status;
  }
  for (const k of ['owner', 'fixedIn', 'affected', 'title']) if (patch[k] !== undefined) next[k] = clean(patch[k], 120);
  if (patch.cvss !== undefined) { const n = Number(patch.cvss); if (!(n >= 0 && n <= 10)) fail('CVSS must be 0–10.'); next.cvss = n; }
  if (patch.severity !== undefined) { if (!SEVERITIES.includes(patch.severity)) fail('Pick a severity.'); next.severity = patch.severity; }
  next.history = [...(v.history || []), { at: Date.now(), by: a.id, from: v.status, to: next.status, note: clean(reason, 200) }];
  await put('vulnerabilities', next);
  await log(a, 'VULNERABILITY_UPDATED', `${v.cve || v.component} -> ${next.status}`);
  return 'Vulnerability updated.';
}

export async function syncVulnerabilities(a, tenantId) {
  need(a, 'security.manage'); assertScope(a, tenantId);
  const rels = (await all('releases')).filter((r) => !r.tenantId || r.tenantId === tenantId);
  const existing = await all('vulnerabilities');
  let added = 0;
  for (const r of rels) for (const f of r.findings || []) {
    const cve = f.cve;
    if (existing.some((v) => v.tenantId === tenantId && v.cve === cve && v.component === f.component)) continue;
    await put('vulnerabilities', {
      id: id('vul'), tenantId, cve, component: f.component, title: `${f.component} vulnerable in ${r.version}`,
      severity: f.sev, cvss: f.sev === 'critical' ? 9.8 : f.sev === 'high' ? 8.1 : f.sev === 'medium' ? 5.5 : 3.1,
      affected: r.version, fixedIn: '', source: 'sbom-scan', owner: '', status: 'open', createdAt: Date.now(), createdBy: a.id, history: [],
    });
    added++;
  }
  await log(a, 'VULNERABILITY_SYNC', `tenant=${tenantId} added=${added}`);
  return `${added} finding(s) imported from release SBOMs.`;
}

/* ---------------- Evidence vault ---------------- */
export async function addEvidence(a, { tenantId, title, kind = 'other', classification = 'internal', content = '', link = '', releaseId = '', incidentId = '', tags = [] }) {
  need(a, 'evidence.manage'); assertScope(a, tenantId);
  if (clean(title, 120).length < 4) fail('Give the evidence a descriptive title.');
  if (!EVIDENCE_KINDS.includes(kind)) fail('Pick an evidence type.');
  if (!EVIDENCE_CLASS.includes(classification)) fail('Pick a classification.');
  const body = clean(content, 200000);
  const hash = await sha256(canon({ title: clean(title, 120), kind, body, link: clean(link, 300), releaseId, incidentId }));
  const ev = {
    id: id('evd'), tenantId, title: clean(title, 120), kind, classification, body, link: clean(link, 300),
    releaseId: releaseId || null, incidentId: incidentId || null, tags: (Array.isArray(tags) ? tags : String(tags || '').split(/[\s,]+/)).map((t) => clean(t, 30)).filter(Boolean),
    hash, size: new Blob([body]).size, status: 'sealed', createdBy: a.id, createdAt: Date.now(), verifiedAt: Date.now(), verification: 'sealed',
  };
  await put('evidence', ev);
  await log(a, 'EVIDENCE_SEALED', `${ev.title} sha256=${hash.slice(0, 12)}`);
  return `Evidence sealed · SHA-256 ${hash.slice(0, 16)}…`;
}

export async function verifyEvidenceRecord(e) {
  const body = clean(e.body || '', 200000);
  const hash = await sha256(canon({ title: e.title, kind: e.kind, body, link: e.link, releaseId: e.releaseId, incidentId: e.incidentId }));
  const ok = hash === e.hash;
  await put('evidence', { ...e, verification: ok ? 'verified' : 'tampered', verifiedAt: Date.now() });
  return { ok, hash, expected: e.hash };
}

export async function verifyAllEvidence(a, tenantId) {
  need(a, 'evidence.view'); assertScope(a, tenantId);
  const list = (await all('evidence')).filter((e) => e.tenantId === tenantId);
  let bad = 0;
  for (const e of list) { const r = await verifyEvidenceRecord(e); if (!r.ok) bad++; }
  await log(a, 'EVIDENCE_VERIFIED_ALL', `tenant=${tenantId} count=${list.length} bad=${bad}`);
  return bad ? `${bad} evidence record(s) failed verification.` : `${list.length} evidence record(s) verified.`;
}

export async function deleteEvidence(a, e, reason) {
  need(a, 'evidence.manage'); assertScope(a, e.tenantId);
  const r = requireReason(reason, 10);
  if (e.releaseId) fail('Evidence attached to a release cannot be deleted; supersede it with a new record.');
  await put('evidence', { ...e, status: 'retained', deletedAt: Date.now(), deletedBy: a.id, deleteReason: r });
  await log(a, 'EVIDENCE_RETIRED', `${e.title}: ${r}`);
  return 'Evidence retired from the active vault. The audit record remains.';
}

/* ---------------- Derived posture ---------------- */
export function latestAttestations(atts, deviceId) {
  return atts.filter((x) => x.deviceId === deviceId && x.quote).sort((x, y) => y.issuedAt - x.issuedAt)[0] || null;
}

export async function bootIntegrity(tenantId, ctx = {}) {
  const { devices = await all('devices'), attestations = await all('attestations'), releases = await all('releases'), policies = await all('policies') } = ctx;
  return devices.filter((d) => d.tenantId === tenantId).map((d) => {
    const last = latestAttestations(attestations, d.id);
    const rel = releases.find((r) => r.id === d.releaseId);
    const pol = policies.find((p) => p.id === d.policyId);
    const secureBoot = d.hardware?.secureBoot;
    const tpm = d.hardware?.tpm2;
    const status = d.tampered ? 'tampered' : !last ? 'unknown' : last.result === 'attested' ? (rel?.status === 'revoked' ? 'release-revoked' : 'intact') : 'failed';
    return {
      ...d, lastAttestation: last, release: rel, policy: pol, secureBoot, tpm,
      bootStatus: status, measuredAt: last?.verifiedAt || null,
      pcr: last?.quote?.body?.pcr || null, nonce: last?.nonce || null,
    };
  });
}

export async function securityOverview(tenantId, ctx = {}) {
  const { devices = await all('devices'), incidents = await all('incidents'), events = await all('securityEvents'), vulnerabilities = await all('vulnerabilities'), evidence = await all('evidence'), attestations = await all('attestations'), releases = await all('releases'), policies = await all('policies') } = ctx;
  const f = (r) => r.tenantId === tenantId;
  const d = devices.filter(f), inc = incidents.filter(f), ev = events.filter(f), vul = vulnerabilities.filter(f), e = evidence.filter(f);
  const attested = d.filter((x) => x.trust === 'attested').length;
  const openVul = vul.filter((v) => !['fixed', 'false-positive'].includes(v.status));
  const critical = openVul.filter((v) => v.severity === 'critical').length;
  const openEvents = ev.filter((x) => ['open', 'acknowledged', 'escalated'].includes(x.status)).length;
  const chain = await verifyChain();
  const boot = d.filter((x) => !x.tampered && latestAttestations(attestations, x.id)?.result === 'attested').length;
  const score = Math.max(0, Math.min(100, Math.round(
    (d.length ? (attested / d.length) * 35 : 20) +
    (d.length ? (boot / d.length) * 25 : 15) +
    (openVul.length ? Math.max(0, 20 - critical * 8) : 20) +
    (chain.ok ? 10 : 0) +
    (openEvents ? Math.max(0, 10 - openEvents * 2) : 10),
  )));
  return {
    devices: d.length, attested, bootIntact: boot, failed: d.filter((x) => x.trust === 'failed').length,
    isolated: d.filter((x) => x.isolated).length, openIncidents: inc.filter((i) => ['open', 'investigating', 'contained'].includes(i.status)).length,
    criticalIncidents: inc.filter((i) => i.severity === 'critical' && ['open', 'investigating', 'contained'].includes(i.status)).length,
    openEvents, criticalVulns: critical, openVulns: openVul.length, evidence: e.length,
    evidenceTampered: e.filter((x) => x.verification === 'tampered').length, chainOk: chain.ok, chainCount: chain.count,
    attestedPct: pct(attested, d.length), bootPct: pct(boot, d.length), score,
    releases: releases.length, revokedReleases: releases.filter((r) => r.status === 'revoked').length,
    publishedPolicies: policies.filter((p) => f(p) && p.status === 'published').length,
  };
}

export const evidenceStats = (list) => ({
  total: list.length,
  sealed: list.filter((e) => e.status === 'sealed').length,
  verified: list.filter((e) => e.verification === 'verified').length,
  tampered: list.filter((e) => e.verification === 'tampered').length,
  restricted: list.filter((e) => ['restricted', 'auditor-only'].includes(e.classification)).length,
});

export const vulnStats = (list) => ({
  total: list.length,
  open: list.filter((v) => v.status === 'open').length,
  critical: list.filter((v) => v.severity === 'critical' && !['fixed', 'false-positive'].includes(v.status)).length,
  high: list.filter((v) => v.severity === 'high' && !['fixed', 'false-positive'].includes(v.status)).length,
  fixed: list.filter((v) => v.status === 'fixed').length,
  accepted: list.filter((v) => v.status === 'accepted').length,
  meanCvss: list.length ? +(list.reduce((s, v) => s + (v.cvss || 0), 0) / list.length).toFixed(1) : 0,
});
