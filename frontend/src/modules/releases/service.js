import { clean } from '../../core/security/sanitize';
import { need, fail, cmpVer, requireReason } from '../../core/services/common';
import * as Api from '../../core/api/services';
import { create as createApprovalRequest } from '../../core/services/approvals';

const SEMVER = /^\d+\.\d+\.\d+(-[a-z0-9.]+)?$/;
const UI_STATUS = {
  draft: 'draft',
  built: 'draft',
  validated: 'draft',
  signed: 'unverified',
  approved: 'approved',
  staged: 'rolling',
  active: 'stable',
  suspended: 'paused',
  revoked: 'revoked',
  retired: 'superseded',
};
export function mapOsRelease(release) {
  const backendStatus = release?.status || 'unknown';
  const manifestVerified = release?.manifest_verified === true;
  let status = UI_STATUS[backendStatus] || backendStatus;
  if (backendStatus === 'signed' && manifestVerified) status = 'candidate';
  if (!manifestVerified && ['approved', 'staged', 'active', 'suspended'].includes(backendStatus)) {
    status = 'unverified';
  }
  return {
    ...release,
    id: release.id || release.release_id,
    version: release.version,
    status,
    backendStatus,
    manifestVerified,
    rollout: release.rollout_percentage ?? release.rollout ?? 0,
    createdAt: release.created_at ?? release.createdAt,
    createdBy: release.created_by ?? release.createdBy ?? '',
    approvedBy: release.approved_by || release.approvedBy || '',
    approvedAt: release.approved_at ?? release.approvedAt,
    digest: release.manifest_digest || release.digest || '',
    findings: Array.isArray(release.findings) ? release.findings : null,
    criticalCves: release.criticalCves === null || release.criticalCves === undefined
      ? null
      : Number.isFinite(Number(release.criticalCves)) ? Number(release.criticalCves) : null,
    manifest: release.manifest || {},
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
  return (release.tests || []).map((test) => ({
    id: test.id,
    releaseId,
    version: release.version,
    title: test.title || test.test_type,
    kind: test.test_type,
    classification: test.classification || 'legacy_unverified',
    link: test.link || '',
    hash: test.evidence_digest || '',
    status: test.evidence_source === 'user_submitted' ? 'submitted' : 'unverified',
    verification: test.evidence_source === 'user_submitted'
      ? (test.integrity_valid ? 'digest-matched' : 'integrity-mismatch')
      : 'unverified',
    integrityValid: test.integrity_valid === true,
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
    backendTrustOutcome: device.backendTrustOutcome || device.backend_trust_outcome || null,
  }));
}
export const advisories = async () => fail('Advisories must come from a trusted backend vulnerability feed.');
export function parseComponents(text) {
  const out = [];
  String(text || '').split('\n').map((l) => l.trim()).filter(Boolean).forEach((l, i) => {
    const m = /^([a-z0-9._-]{1,60})@(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)$/i.exec(l); if (!m) fail(`Line ${i + 1}: use name@1.2.3`);
    out.push({ name: m[1].toLowerCase(), version: m[2] });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
export async function createRelease(a, { version, components }) {
  need(a, 'release.manage');
  version = clean(version, 30);
  if (!SEMVER.test(version)) fail('Version must look like 2.19.0 or 2.19.0-rc1.');
  if ((await listReleases()).some((r) => r.version === version)) fail('That version already exists.');
  const comps = parseComponents(components); if (!comps.length) fail('List at least one SBOM component.');
  const manifest = { version, components: comps };
  const backendRes = await Api.createOsRelease({
    release_id: `ExamOS ${version}`,
    version,
    manifest_json: JSON.stringify(manifest),
  });
  if (!backendRes?.id || backendRes?.lifecycle_status !== 'draft' || backendRes?.manifest_verified !== false) {
    fail('Backend did not confirm an unsigned, persisted release draft.');
  }
  return `Draft ${version} persisted. It is not signed, vulnerability-scanned, or eligible for rollout.`;
}
export async function verifyRelease(r) {
  const response = await Api.getOsReleaseDetails(r.id);
  return response?.release?.manifest_verified === true &&
    typeof response.release.manifest_signature === 'string' &&
    response.release.manifest_signature.length > 0;
}
export async function approveRelease(a, r, reason) {
  need(a, 'release.approve');
  if (r.status !== 'candidate') fail('Only candidates can be approved.');
  if (r.createdBy === a.id) fail('The builder cannot approve their own release (separation of duties).');
  if (!(await verifyRelease(r))) fail('Backend has not verified a trusted manifest signature.');
  const justification = requireReason(reason, 8);
  const request = await createApprovalRequest(a, {
    kind: 'release-approve',
    label: `Approve release ${r.version}`,
    targetId: r.id,
    tenantId: a.tenantId || r.tenantId,
    reason: justification,
    data: { releaseId: r.id, manifestDigest: r.digest },
  });
  return `Approval request ${request.id} submitted. The release was not approved or published.`;
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

  return `Deployment plan ${deployment.deployment_id} persisted. No devices were assigned or dispatched.`;
}
export async function revokeRelease(a, r, reason) {
  need(a, 'release.manage'); if (r.status === 'revoked') fail('Already revoked.');
  if ((reason || '').length < 8) fail('Reason needs 8+ characters.');
  await Api.revokeOsRelease(r.id, reason);
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
  return `${hit.length} device recovery request(s) submitted for ${good.version}; device completion is not yet verified.`;
}
export async function addAdvisory(a, { name, below, cve, sev }) {
  need(a, 'release.manage');
  void name; void below; void cve; void sev;
  fail('Advisory management is unavailable until a trusted backend vulnerability feed is configured.');
}

/* ---------------- Release evidence ---------------- */
export const EVIDENCE_KINDS = ['test-plan', 'test-report', 'security-review', 'sbom', 'signature', 'rollback-plan', 'performance', 'accessibility', 'other'];

export async function addReleaseEvidence(a, { releaseId, title, kind = 'test-report', classification = 'internal', content = '', link = '' }) {
  need(a, 'release.manage');
  const r = (await listReleases()).find((release) => release.id === releaseId); if (!r) fail('Release not found.');
  if (clean(title, 120).length < 4) fail('Give the evidence a descriptive title.');
  if (!EVIDENCE_KINDS.includes(kind)) fail('Pick an evidence type.');
  const body = clean(content, 4000);
  const response = await Api.validateOsRelease(releaseId, {
    test_type: kind,
    title: clean(title, 120),
    classification,
    details: body,
    link: clean(link, 300),
  });
  if (response?.status !== 'submitted' || !response.evidence_id) fail('Backend did not confirm evidence persistence.');
  return `Evidence submitted for ${r.version}. It is not a passed validation result.`;
}

export async function verifyReleaseEvidence(e) {
  const response = await Api.getOsReleaseDetails(e.releaseId);
  const tests = response?.release?.tests || [];
  const match = tests.find((test) => test.id === e.id);
  return { ok: match?.integrity_valid === true, hash: match?.evidence_digest || '', expected: e.hash };
}

/* ---------------- Rollout control ---------------- */
export async function pauseRollout(a, r, reason) {
  need(a, 'release.rollout');
  void r; void reason;
  fail('Rollout groups do not yet support pause controls; release state was not changed.');
}

export async function resumeRollout(a, r) {
  need(a, 'release.rollout');
  void r;
  fail('Rollout groups do not yet support resume controls; release state was not changed.');
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
  return `${devices.length} device recovery request(s) submitted for ${target.version}; completion requires device acknowledgements.`;
}

export async function listReleaseDeployments() {
  const response = await Api.listOsDeploymentGroups();
  if (!Array.isArray(response?.deployments)) fail('The deployment API returned an invalid response.');
  return response.deployments;
}

export function rolloutStats(r, devices) {
  const on = devices.filter((d) => d.releaseId === r.id);
  return {
    total: devices.length, onRelease: on.length, target: r.rollout,
    enrolled: on.filter((d) => d.status === 'enrolled').length,
    attested: on.filter((d) => d.backendTrustOutcome === 'ALLOW').length,
    failed: on.filter((d) => d.backendTrustOutcome === 'DENY').length,
    pendingAttestation: on.filter((d) => d.backendTrustOutcome !== 'ALLOW').length,
    pct: devices.length ? +((on.length / devices.length) * 100).toFixed(1) : 0,
  };
}

export async function releaseReadiness(r, ctx = {}) {
  const { devices = await listReleaseDevices(), evidence = await listReleaseEvidence(r.id) } = ctx;
  const backend = (await Api.getOsReleaseDetails(r.id))?.release;
  const ev = evidence.filter((e) => e.releaseId === r.id);
  const digestMatches = ev.filter((e) => e.verification === 'digest-matched').length;
  const digestMismatches = ev.filter((e) => e.verification === 'integrity-mismatch').length;
  const out = [];
  out.push({
    key: 'signature',
    label: 'Manifest signature',
    status: backend?.manifest_verified === true ? 'PASS' : 'NOT_RUN',
    detail: backend?.manifest_verified === true
      ? backend.manifest_digest
      : 'No trusted signing service has verified this manifest.',
  });
  out.push({ key: 'sbom', label: 'SBOM review', status: 'NOT_RUN', detail: 'No backend vulnerability scan result is available.' });
  out.push({
    key: 'evidence',
    label: 'Validation evidence',
    status: ev.length ? 'WARN' : 'NOT_RUN',
    detail: `${ev.length} user-submitted record(s); these are not test results.`,
  });
  out.push({
    key: 'evidence-integrity',
    label: 'Evidence digest',
    status: digestMismatches ? 'FAIL' : digestMatches ? 'WARN' : 'NOT_RUN',
    detail: digestMatches || digestMismatches
      ? `${digestMatches} matching and ${digestMismatches} mismatching submitted record digest(s).`
      : 'No submitted evidence digest is available to check.',
  });
  out.push({
    key: 'approval',
    label: 'Approval',
    status: backend?.manifest_verified === true &&
      ['approved', 'staged', 'active', 'suspended'].includes(r.backendStatus) ? 'PASS' : 'WARN',
    detail: r.backendStatus,
  });
  const on = devices.filter((d) => d.releaseId === r.id);
  out.push({
    key: 'rollout',
    label: 'Device rollout',
    status: 'NOT_RUN',
    detail: `${on.length} device(s) report this release; no deployment dispatch or assignment is recorded.`,
  });
  out.push({ key: 'devices', label: 'Device attestation', status: on.length && on.every((d) => d.backendTrustOutcome === 'ALLOW') ? 'PASS' : on.length ? 'WARN' : 'NOT_RUN', detail: `${on.filter((d) => d.backendTrustOutcome === 'ALLOW').length}/${on.length} server-verified` });
  return out;
}

export const releaseStats = (list) => ({
  total: list.length,
  candidates: list.filter((r) => r.status === 'candidate').length,
  approved: list.filter((r) => r.status === 'approved').length,
  rolling: list.filter((r) => ['rolling', 'paused'].includes(r.status)).length,
  stable: list.filter((r) => r.status === 'stable').length,
  revoked: list.filter((r) => r.status === 'revoked').length,
  criticalCves: list.some((r) => r.criticalCves === null)
    || list.length === 0 ? null
    : list.reduce((n, r) => n + (r.criticalCves || 0), 0),
});
