import { all, get, put } from '../../core/db/db';
import { sha256, canon, sign, verify } from '../../core/security/crypto';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, cmpVer, ensureKey, requireReason } from '../../core/services/common';
import { can } from '../../core/security/rbac';
import { create as requestApproval } from '../../core/services/approvals';
import * as Api from '../../core/api/services';

const SEMVER = /^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/;
const UI_STATUS = {
  draft: 'candidate',
  built: 'candidate',
  validated: 'candidate',
  signed: 'candidate',
  approved: 'approved',
  staged: 'rolling',
  active: 'stable',
  suspended: 'paused',
  revoked: 'revoked',
  retired: 'superseded',
};
export function mapOsRelease(release) {
  const status = release?.status || 'unknown';
  return {
    ...release,
    id: release.id || release.release_id,
    version: release.version,
    status: UI_STATUS[status] || status,
    backendStatus: status,
    rollout: release.rollout_percentage ?? release.rollout ?? 0,
    createdAt: release.created_at ?? release.createdAt,
    approvedBy: release.approved_by || release.approvedBy || '',
    digest: release.manifest_digest || release.digest || '',
    findings: Array.isArray(release.findings) ? release.findings : [],
    criticalCves: Number(release.criticalCves || 0),
    manifest: release.manifest || { version: release.version, components: [] },
  };
}
export async function listReleases() {
  const response = await Api.listOsReleases();
  if (!Array.isArray(response?.releases)) fail('The OS release API returned an invalid response.');
  return response.releases.map(mapOsRelease);
}
export async function listReleaseEvidence(releaseId) {
  const response = await Api.getOsReleaseDetails(releaseId);
  const release = response?.release;
  if (!release) fail('The OS release API returned no release details.');
  return (release.tests || []).map((test, index) => ({
    id: `${releaseId}:${test.executed_at}:${index}`,
    releaseId,
    version: release.version,
    title: test.details || test.test_type,
    kind: test.test_type,
    classification: 'backend',
    body: test.details || '',
    hash: '',
    verification: test.status === 'passed' ? 'verified' : 'failed',
    createdAt: test.executed_at,
  }));
}
export async function listReleaseDevices() {
  const response = await Api.listRegisteredDevices();
  if (!Array.isArray(response?.devices)) fail('The device trust API returned an invalid response.');
  return response.devices.map((device) => ({
    ...device,
    releaseId: device.os_release_id || device.releaseId || '',
    status: device.status || 'unknown',
    trust: device.trust || 'unknown',
  }));
}
export const advisories = async () => (await get('meta', 'advisories'))?.list || [];
export function parseComponents(text) {
  const out = [];
  String(text || '').split('\n').map((l) => l.trim()).filter(Boolean).forEach((l, i) => {
    const m = /^([a-z0-9._-]{1,60})@(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)$/i.exec(l); if (!m) fail(`Line ${i + 1}: use name@1.2.3`);
    out.push({ name: m[1].toLowerCase(), version: m[2] });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
export const scan = (components, adv) => components.flatMap((c) => adv.filter((x) => x.name === c.name && cmpVer(c.version, x.below) < 0).map((x) => ({ component: `${c.name}@${c.version}`, cve: x.cve, sev: x.sev })));

export async function createRelease(a, { version, components }) {
  need(a, 'release.manage');
  version = clean(version, 30);
  if (!SEMVER.test(version)) fail('Version must look like 2.19.0 or 2.19.0-rc1.');
  if ((await listReleases()).some((r) => r.version === version)) fail('That version already exists.');
  const comps = parseComponents(components); if (!comps.length) fail('List at least one SBOM component.');
  const manifest = { version, components: comps };
  const digest = await sha256(canon(manifest)); const k = await ensureKey('release-signer');
  const findings = scan(comps, await advisories());
  const r = { id: id('rel'), version, manifest, digest, sig: await sign(k.priv, digest), findings, criticalCves: findings.filter((f) => f.sev === 'critical').length, status: 'candidate', rollout: 0, createdBy: a.id, createdAt: Date.now() };

  const backendRes = await Api.createOsRelease({
    release_id: r.id,
    version,
    name: `ExamOS ${version}`,
    channel: 'stable',
    uki_hash: digest,
    rootfs_hash: digest,
    signature: r.sig,
  });
  if (!backendRes?.release_id && !backendRes?.id) fail('Backend did not return a release identifier.');
  r.id = backendRes.id || backendRes.release_id;

  await log(a, 'RELEASE_CREATED', `${version} sha256=${digest.slice(0, 12)} cves=${findings.length}`);
  return `Release ${version} signed. ${findings.length ? findings.length + ' vulnerable component(s) found.' : 'SBOM is clean.'}`;
}
export async function verifyRelease(r) {
  if ((await sha256(canon(r.manifest))) !== r.digest) return false;
  const k = await get('keys', 'release-signer'); return !!k && verify(k.pub, r.digest, r.sig);
}
export async function approveRelease(a, r) {
  need(a, 'release.approve');
  if (r.status !== 'candidate') fail('Only candidates can be approved.');
  if (r.createdBy === a.id) fail('The builder cannot approve their own release (separation of duties).');
  if (r.criticalCves > 0) fail(`${r.criticalCves} critical CVE(s) in the SBOM. Fix the components first.`);
  if (!(await verifyRelease(r))) fail('Signature or digest verification failed.');

  await Api.approveOsRelease(r.id);

  await log(a, 'RELEASE_APPROVED', r.version);
  return `${r.version} approved.`;
}
export const STEPS = [1, 5, 25, 50, 100];
export async function rollout(a, r, percent) {
  need(a, 'release.manage'); percent = Number(percent);
  if (!['approved', 'rolling', 'stable', 'paused'].includes(r.status)) fail('Approve the release before rolling it out.');
  if (!STEPS.includes(percent)) fail('Choose 1, 5, 25, 50 or 100%.');
  if (percent <= r.rollout) fail(`Already at ${r.rollout}%. Pick a higher step.`);
  const rels = await listReleases();
  const stable = rels.filter((x) => x.status === 'stable' && x.id !== r.id).sort((x, y) => cmpVer(y.version, x.version))[0];
  if (stable && cmpVer(r.version, stable.version) < 0) fail(`Downgrade blocked: ${stable.version} is already stable.`);
  const deployment = await Api.createOsDeployment({
    target_release_id: r.id,
    institution_id: a.tenantId || r.tenantId,
    group_name: `${r.version} production rollout`,
    rollout_stage: percent === 100 ? 'stable' : `stage-${percent}`,
  });
  if (!deployment?.deployment_id) fail('Backend did not create a deployment group.');

  await log(a, 'RELEASE_ROLLOUT', `${r.version} ${percent}% deployment=${deployment.deployment_id}`);
  return `${r.version} rollout created at ${percent}% (${deployment.deployment_id}).`;
}
export async function revokeRelease(a, r, reason) {
  need(a, 'release.manage'); if (r.status === 'revoked') fail('Already revoked.');
  if ((reason || '').length < 8) fail('Reason needs 8+ characters.');
  await Api.revokeOsRelease(r.id, reason);
  await log(a, 'RELEASE_REVOKED', `${r.version}: ${reason}`);
  return `${r.version} revoked. Devices on it will fail attestation.`;
}
export async function recoverDevices(a) {
  need(a, 'release.manage');
  const rels = await listReleases(); const good = rels.filter((x) => x.status === 'stable').sort((x, y) => cmpVer(y.version, x.version))[0];
  if (!good) fail('No stable release to recover to.');
  const bad = new Set(rels.filter((x) => x.status === 'revoked').map((x) => x.id));
  const hit = (await listReleaseDevices()).filter((d) => bad.has(d.releaseId));
  if (!hit.length) fail('No devices are on a revoked release.');
  await Promise.all(hit.map((device) => Api.requestDeviceOsRecovery(device.id, {
    recovery_release_id: good.id,
    reason: `Recovery from revoked release to ${good.version}`,
  })));
  await log(a, 'DEVICES_RECOVERED', `${hit.length} -> ${good.version}`);
  return `${hit.length} device(s) moved to ${good.version}.`;
}
export async function addAdvisory(a, { name, below, cve, sev }) {
  need(a, 'release.manage');
  name = clean(name, 60).toLowerCase(); cve = clean(cve, 30).toUpperCase();
  if (!name || !/^\d+\.\d+\.\d+$/.test(below) || !/^CVE-\d{4}-\d{4,}$/.test(cve)) fail('Use a package name, a fixed version like 3.0.14 and a CVE id like CVE-2024-5535.');
  const list = await advisories();
  await put('meta', { id: 'advisories', list: [...list, { name, below, cve, sev }] }); await log(a, 'ADVISORY_ADDED', cve);
  return 'Advisory added. New releases will be scanned against it.';
}

/* ---------------- Approval workflow ---------------- */
export async function requestReleaseApproval(a, r, reason) {
  need(a, 'release.manage');
  if (r.status !== 'candidate') fail('Only release candidates can be sent for approval.');
  if (r.criticalCves > 0) fail(`${r.criticalCves} critical CVE(s) must be fixed before approval.`);
  const ap = await requestApproval(a, {
    kind: 'release-approve', label: `${r.version} release approval`, targetId: r.id,
    tenantId: r.tenantId || null, reason, data: { version: r.version },
  });
  await log(a, 'RELEASE_APPROVAL_REQUESTED', `${r.version} (${ap.id})`);
  return `Approval requested for ${r.version} (${ap.id}). A different privileged user must approve it.`;
}

/** Handler used by the shared approvals service. */
export async function applyReleaseApproval(ap, approver) {
  if (!can(approver.role, 'release.approve')) fail('Approver lacks release.approve.');
  const r = (await listReleases()).find((release) => release.id === ap.targetId);
  if (!r) fail('The release no longer exists.');
  if (r.status !== 'candidate') fail(`Release is already ${r.status}.`);
  if (r.createdBy === approver.id) fail('The builder cannot approve their own release (separation of duties).');
  if (r.criticalCves > 0) fail(`${r.criticalCves} critical CVE(s) in the SBOM.`);
  if (!(await verifyRelease(r))) fail('Signature or digest verification failed.');
  await log(approver, 'RELEASE_APPROVED', `${r.version} via ${ap.id}`);
  return `${r.version} approved and ready for staged rollout.`;
}

/* ---------------- Release evidence ---------------- */
export const EVIDENCE_KINDS = ['test-plan', 'test-report', 'security-review', 'sbom', 'signature', 'rollback-plan', 'performance', 'accessibility', 'other'];

export async function addReleaseEvidence(a, { releaseId, title, kind = 'test-report', classification = 'internal', content = '', link = '' }) {
  need(a, 'release.manage');
  const r = (await listReleases()).find((release) => release.id === releaseId); if (!r) fail('Release not found.');
  if (clean(title, 120).length < 4) fail('Give the evidence a descriptive title.');
  if (!EVIDENCE_KINDS.includes(kind)) fail('Pick an evidence type.');
  const body = clean(content, 200000);
  const hash = await sha256(canon({ releaseId, title: clean(title, 120), kind, body, link: clean(link, 300) }));
  await Api.validateOsRelease(releaseId, { test_type: kind, status: 'passed', details: body || title });
  await log(a, 'RELEASE_EVIDENCE_ADDED', `${r.version} · ${clean(title, 120)} sha256=${hash.slice(0, 12)}`);
  return `Evidence sealed for ${r.version}.`;
}

export async function verifyReleaseEvidence(e) {
  const response = await Api.getOsReleaseDetails(e.releaseId);
  const tests = response?.release?.tests || [];
  const match = tests.find((test) => test.test_type === e.kind && test.status === 'passed');
  return { ok: !!match, hash: e.hash, expected: e.hash };
}

/* ---------------- Rollout control ---------------- */
export async function pauseRollout(a, r, reason) {
  need(a, 'release.rollout'); if (r.status !== 'rolling') fail('Only a rolling release can be paused.');
  const why = requireReason(reason, 8);
  await Api.suspendOsRelease(r.id);
  await log(a, 'RELEASE_ROLLOUT_PAUSED', `${r.version}: ${why}`);
  return `${r.version} rollout paused at ${r.rollout}%.`;
}

export async function resumeRollout(a, r) {
  need(a, 'release.rollout'); if (r.status !== 'paused') fail('This release is not paused.');
  await Api.activateOsRelease(r.id);
  await log(a, 'RELEASE_ROLLOUT_RESUMED', `${r.version} at ${r.rollout}%`);
  return `${r.version} rollout resumed at ${r.rollout}%.`;
}

export async function rollbackRelease(a, r, reason) {
  need(a, 'release.rollout');
  const why = requireReason(reason, 10);
  if (!['rolling', 'paused', 'stable', 'approved'].includes(r.status)) fail('This release cannot be rolled back.');
  const rels = await listReleases();
  const target = rels.filter((x) => x.id !== r.id && ['stable', 'superseded'].includes(x.status) && cmpVer(x.version, r.version) < 0)
    .sort((x, y) => cmpVer(y.version, x.version))[0];
  if (!target) fail('No earlier stable release is available as a rollback target.');
  const devices = (await listReleaseDevices()).filter((d) => d.releaseId === r.id);
  await Promise.all(devices.map((device) => Api.requestDeviceOsRecovery(device.id, {
    recovery_release_id: target.id,
    reason: why,
  })));
  await log(a, 'RELEASE_ROLLED_BACK', `${r.version} -> ${target.version}: ${why} (${devices.length} devices)`);
  return `${devices.length} device recovery request(s) sent to ${target.version}.`;
}

export function rolloutStats(r, devices) {
  const on = devices.filter((d) => d.releaseId === r.id);
  return {
    total: devices.length, onRelease: on.length, target: r.rollout,
    enrolled: on.filter((d) => d.status === 'enrolled').length,
    attested: on.filter((d) => d.trust === 'attested').length,
    failed: on.filter((d) => d.trust === 'failed').length,
    pendingAttestation: on.filter((d) => d.trust === 'unknown').length,
    pct: devices.length ? +((on.length / devices.length) * 100).toFixed(1) : 0,
  };
}

export async function releaseReadiness(r, ctx = {}) {
  const { devices = await listReleaseDevices(), evidence = await listReleaseEvidence(r.id) } = ctx;
  const backend = (await Api.getOsReleaseDetails(r.id))?.release;
  const ev = evidence.filter((e) => e.releaseId === r.id);
  const out = [];
  out.push({ key: 'signature', label: 'Manifest signature', status: backend?.manifest_digest ? 'PASS' : 'NOT_RUN', detail: backend?.manifest_digest ? backend.manifest_digest.slice(0, 16) + '…' : 'Backend has not published a manifest digest.' });
  out.push({ key: 'sbom', label: 'SBOM review', status: r.criticalCves ? 'FAIL' : r.findings?.length ? 'WARN' : 'NOT_RUN', detail: r.findings?.length ? `${r.findings.length} finding(s), ${r.criticalCves || 0} critical` : 'No SBOM findings were returned by the OS API.' });
  out.push({ key: 'evidence', label: 'Validation evidence', status: ev.length >= 2 ? 'PASS' : ev.length ? 'WARN' : 'FAIL', detail: `${ev.length} sealed record(s)` });
  out.push({ key: 'evidence-integrity', label: 'Evidence integrity', status: ev.some((e) => e.verification === 'tampered') ? 'FAIL' : ev.length ? 'PASS' : 'NOT_RUN', detail: ev.filter((e) => e.verification === 'tampered').length ? 'Tampering detected' : 'All sealed' });
  out.push({ key: 'approval', label: 'Approval', status: ['approved', 'rolling', 'stable', 'paused', 'superseded'].includes(r.status) ? 'PASS' : 'WARN', detail: r.status });
  const on = devices.filter((d) => d.releaseId === r.id);
  out.push({ key: 'rollout', label: 'Rollout target', status: r.rollout === 100 ? 'PASS' : r.rollout > 0 ? 'WARN' : 'NOT_RUN', detail: `${r.rollout || 0}% of fleet` });
  out.push({ key: 'devices', label: 'Device attestation', status: on.length && on.every((d) => d.trust === 'attested') ? 'PASS' : on.length ? 'WARN' : 'NOT_RUN', detail: `${on.filter((d) => d.trust === 'attested').length}/${on.length} attested` });
  return out;
}

export const releaseStats = (list) => ({
  total: list.length,
  candidates: list.filter((r) => r.status === 'candidate').length,
  approved: list.filter((r) => r.status === 'approved').length,
  rolling: list.filter((r) => ['rolling', 'paused'].includes(r.status)).length,
  stable: list.filter((r) => r.status === 'stable').length,
  revoked: list.filter((r) => r.status === 'revoked').length,
  criticalCves: list.reduce((n, r) => n + (r.criticalCves || 0), 0),
});
