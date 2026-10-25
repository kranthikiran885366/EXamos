import { all, get, put, putMany } from '../../core/db/db';
import { genKeyPair } from '../../core/security/crypto';
import { id, need, fail, log, cmpVer, seatLabel, assertScope, requireReason } from '../../core/services/common';
import { latestPublished } from '../policies/service';
import { create as requestApproval } from '../../core/services/approvals';
import { clean } from '../../core/security/sanitize';

export const reachable = (d, t = Date.now()) => t - (d.lastSeen || 0) < 40000;
export function compliant(d, policies, releases, t = Date.now()) {
  const rel = releases.find((r) => r.id === d.releaseId); const pol = policies.find((p) => p.id === d.policyId);
  return d.status === 'enrolled' && !d.isolated && reachable(d, t) && d.trust === 'attested' && !!rel && rel.status !== 'revoked' && !!pol && pol.status === 'published';
}

const PROFILES = {
  'standard-uefi': { uefi: true, usbBoot: true, secureBoot: true, tpm2: true, ramGb: 8, storageGb: 128, wifi: true, display: '1920x1080', battery: true },
  'secure-lab': { uefi: true, usbBoot: true, secureBoot: true, tpm2: true, ramGb: 16, storageGb: 256, wifi: true, display: '1920x1080', battery: false },
  'legacy-bios': { uefi: false, usbBoot: true, secureBoot: false, tpm2: false, ramGb: 4, storageGb: 64, wifi: true, display: '1366x768', battery: true },
};
export const COMPAT_PROFILES = Object.keys(PROFILES).map((k) => ({ v: k, l: k.replace(/-/g, ' ') }));
export const CHECKS = [
  { key: 'uefi', label: 'UEFI boot capability', group: 'Firmware', mandatory: true },
  { key: 'usbBoot', label: 'USB boot support and boot-entry detection', group: 'Firmware', mandatory: true },
  { key: 'secureBoot', label: 'Secure Boot state and trust chain', group: 'Firmware', mandatory: true },
  { key: 'tpm2', label: 'TPM 2.0 presence and readiness', group: 'Firmware', mandatory: true },
  { key: 'ramGb', label: 'Memory capacity (8 GB+)', group: 'Hardware', mandatory: true },
  { key: 'storageGb', label: 'Free storage (64 GB+)', group: 'Hardware', mandatory: true },
  { key: 'cpu', label: 'CPU architecture and instructions (x86-64)', group: 'Hardware', mandatory: true },
  { key: 'wifi', label: 'Wi-Fi / Ethernet adapter and driver', group: 'Network', mandatory: true },
  { key: 'network', label: 'Connectivity to approved exam origin', group: 'Network', mandatory: true },
  { key: 'time', label: 'Time synchronisation and certificate validation', group: 'Network', mandatory: true },
  { key: 'display', label: 'Display resolution (1366×768+)', group: 'Peripherals', mandatory: true },
  { key: 'keyboard', label: 'Keyboard and pointer input', group: 'Peripherals', mandatory: true },
  { key: 'battery', label: 'Battery / power state', group: 'Peripherals', mandatory: false },
  { key: 'sleep', label: 'Sleep / resume behaviour', group: 'Peripherals', mandatory: false },
  { key: 'camera', label: 'Camera (only when exam requires it)', group: 'Peripherals', mandatory: false },
  { key: 'microphone', label: 'Microphone (only when exam requires it)', group: 'Peripherals', mandatory: false },
  { key: 'accessibility', label: 'Approved accessibility hardware', group: 'Peripherals', mandatory: false },
];
const checkStatus = (key, profile, device) => {
  if (device.status !== 'enrolled') return { status: 'BLOCKED', reason: `Device is ${device.status}` };
  if (device.compatFail?.includes(key)) return { status: 'FAIL', reason: 'Hardware check failed on the last run' };
  if (device.compatUnknown?.includes(key)) return { status: 'UNKNOWN', reason: 'The agent could not read this property' };
  if (key === 'cpu') return { status: 'PASS', reason: 'x86-64 with SSE4.2' };
  if (key === 'network' || key === 'time') return { status: device.isolated ? 'FAIL' : 'PASS', reason: device.isolated ? 'Device isolated by policy' : 'Reachable and certificate valid' };
  if (key === 'keyboard') return { status: 'PASS', reason: 'Internal keyboard and pointer detected' };
  if (key === 'sleep') return { status: 'PASS', reason: 'S3 suspend/resume verified' };
  if (key === 'accessibility') return { status: 'NOT_RUN', reason: 'No accessibility hardware requested' };
  if (key === 'camera' || key === 'microphone') return { status: 'NOT_RUN', reason: 'Not required by the assigned exam' };
  const v = profile[key];
  if (v === undefined) return { status: 'UNKNOWN', reason: 'Property unavailable' };
  if (typeof v === 'number') return v >= (key === 'ramGb' ? 8 : 64) ? { status: 'PASS', reason: `${v} ${key === 'ramGb' ? 'GB RAM' : 'GB storage'}` } : { status: 'FAIL', reason: `Only ${v} ${key === 'ramGb' ? 'GB RAM' : 'GB storage'}` };
  if (typeof v === 'boolean') return v ? { status: 'PASS', reason: 'Supported and enabled' } : { status: 'FAIL', reason: 'Not supported or disabled' };
  return { status: 'PASS', reason: String(v) };
};

export async function enrollDevices(a, { tenantId, centerId, count = 1 }) {
  need(a, 'device.manage'); assertScope(a, tenantId);
  const ce = await get('centers', centerId);
  if (!ce || ce.tenantId !== tenantId) fail('Pick a center.');
  if (ce.status !== 'active') fail('That center is inactive.');
  const n = Math.floor(Number(count)); if (!(n >= 1 && n <= 100)) fail('Count must be 1–100.');
  const devs = await all('devices'); const used = new Set(devs.filter((d) => d.centerId === centerId).map((d) => d.seat));
  const free = []; for (let i = 0; i < ce.capacity && free.length < n; i++) { const s = seatLabel(i); if (!used.has(s)) free.push(s); }
  if (free.length < n) fail(`Only ${free.length} free seat(s) at ${ce.code}.`);
  const stable = (await all('releases')).filter((r) => r.status === 'stable').sort((x, y) => cmpVer(y.version, x.version))[0];
  if (!stable) fail('No stable release to install. Approve and roll out a release first.');
  const pol = latestPublished(await all('policies'), tenantId); const now = Date.now(); const keys = [], out = [];
  for (const seat of free) {
    const did = id('dev'); const kp = await genKeyPair();
    keys.push({ id: did, priv: kp.privateKey, pub: await crypto.subtle.exportKey('jwk', kp.publicKey) });
    out.push(newDevice({ id: did, tenantId, centerId, seat, hostname: `${ce.code}-${seat}`, releaseId: stable.id, policyId: pol?.id || null, now, by: a.id }));
  }
  await putMany('keys', keys); await putMany('devices', out); await log(a, 'DEVICES_ENROLLED', `${ce.code} x${n}`);
  return `${n} device(s) enrolled at ${ce.code} with fresh hardware-bound identities.`;
}
function newDevice({ id, tenantId, centerId, seat, hostname, releaseId, policyId, now, by, serial = '', profile = 'standard-uefi' }) {
  return {
    id, tenantId, centerId, seat, hostname, serial: serial || `SN-${id.slice(-8).toUpperCase()}`,
    releaseId, policyId, status: 'enrolled', trust: 'unknown', isolated: false, tampered: false,
    lastSeen: now, lastAttested: 0, silentUntil: 0, enrolledAt: now, enrolledBy: by,
    profile, hardware: PROFILES[profile] || PROFILES['standard-uefi'], compatStatus: 'NOT_RUN', lastCompatAt: 0,
    compatFail: [], compatUnknown: [], exceptions: [], history: [{ at: now, by, action: 'Device enrolled' }],
  };
}

export async function enrollSingle(a, { tenantId, centerId, seat, hostname, serial, profile = 'standard-uefi', releaseId }) {
  need(a, 'device.manage'); assertScope(a, tenantId);
  const ce = await get('centers', centerId); if (!ce || ce.tenantId !== tenantId) fail('Pick a center in this institution.');
  const s = clean(seat, 8).toUpperCase(); if (!/^[A-Z]\d{2}$/.test(s)) fail('Seat looks like A01.');
  if ((await all('devices')).some((d) => d.centerId === centerId && d.seat === s)) fail('That seat already has a device.');
  const rel = releaseId ? await get('releases', releaseId) : (await all('releases')).filter((r) => r.status === 'stable').sort((x, y) => cmpVer(y.version, x.version))[0];
  if (!rel || rel.status === 'revoked') fail('Pick an approved release.');
  if (!PROFILES[profile]) fail('Unknown hardware profile.');
  const pol = latestPublished(await all('policies'), tenantId);
  const did = id('dev'); const kp = await genKeyPair();
  await put('keys', { id: did, priv: kp.privateKey, pub: await crypto.subtle.exportKey('jwk', kp.publicKey) });
  const d = newDevice({ id: did, tenantId, centerId, seat: s, hostname: clean(hostname, 60) || `${ce.code}-${s}`, releaseId: rel.id, policyId: pol?.id || null, now: Date.now(), by: a.id, serial: clean(serial, 40), profile });
  await put('devices', d); await log(a, 'DEVICE_ENROLLED', `${d.hostname} serial=${d.serial}`);
  return d;
}

export async function setDeviceStatus(a, d, status, reason) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 8);
  if (!['enrolled', 'suspended', 'revoked', 'rejected'].includes(status)) fail('Unknown device status.');
  if (d.status === 'revoked' && status === 'enrolled' && !['superadmin', 'ops_admin'].includes(a.role)) fail('Reauthorising a revoked device needs a platform approval.');
  if ((await all('sessions')).some((s) => s.deviceId === d.id && s.status === 'in_progress')) fail('End the active exam session on this device first.');
  const next = { ...d, status, statusReason: r, statusAt: Date.now(), trust: status === 'enrolled' ? 'unknown' : d.trust, history: [...(d.history || []), { at: Date.now(), by: a.id, action: `Status → ${status}`, reason: r }] };
  await put('devices', next); await log(a, 'DEVICE_' + status.toUpperCase(), `${d.hostname}: ${r}`);
  return `${d.hostname} is now ${status}.`;
}

export async function requestReauth(a, d, reason) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  if (d.status !== 'revoked') fail('Only a revoked device needs reauthorisation approval.');
  const ap = await requestApproval(a, { kind: 'device-reauth', label: `Reauthorise ${d.hostname}`, targetId: d.id, tenantId: d.tenantId, reason, data: {} });
  return `Reauthorisation requested (${ap.id}). A different privileged user must approve it.`;
}
export async function applyDeviceReauth(ap, approver) {
  const d = await get('devices', ap.targetId); if (!d) fail('Device no longer exists.');
  if (d.status !== 'revoked') fail('Device is no longer revoked.');
  await put('devices', { ...d, status: 'enrolled', trust: 'unknown', isolated: false, statusReason: `Reauthorised via ${ap.id}`, history: [...(d.history || []), { at: Date.now(), by: approver.id, action: 'Reauthorised by approval' }] });
  await log(approver, 'DEVICE_REAUTHORISED', `${d.hostname} via ${ap.id}`);
  return `${d.hostname} reauthorised. Re-attest before use.`;
}

export async function releaseIsolation(a, d) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  if (!d.isolated) fail('Device is not isolated.');
  await put('devices', { ...d, isolated: false, history: [...(d.history || []), { at: Date.now(), by: a.id, action: 'Isolation released' }] });
  await log(a, 'DEVICE_ISOLATION_RELEASED', d.hostname); return `${d.hostname} released. Re-attest it before use.`;
}
export async function simulateOutage(a, d, seconds = 70) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  await put('devices', { ...d, silentUntil: Date.now() + seconds * 1000 }); await log(a, 'SIM_OUTAGE', `${d.hostname} ${seconds}s`);
  return `${d.hostname} will stop sending heartbeats for ${seconds}s.`;
}
export async function reassignDevice(a, d, { centerId, seat, reason }) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 8);
  const ce = await get('centers', centerId); if (!ce || ce.tenantId !== d.tenantId) fail('Pick a center in this institution.');
  const s = clean(seat, 8).toUpperCase();
  if ((await all('devices')).some((x) => x.id !== d.id && x.centerId === centerId && x.seat === s)) fail('That seat is occupied.');
  await put('devices', { ...d, centerId, seat: s, hostname: `${ce.code}-${s}`, history: [...(d.history || []), { at: Date.now(), by: a.id, action: `Reassigned to ${ce.code}/${s}`, reason: r }] });
  await log(a, 'DEVICE_REASSIGNED', `${d.hostname} -> ${ce.code}/${s}: ${r}`);
  return 'Device reassigned. Re-run compatibility and attestation.';
}
export async function replaceDevice(a, d, { serial, reason }) {
  need(a, 'device.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 8);
  const sn = clean(serial, 40); if (sn.length < 4) fail('Enter the replacement serial number.');
  await put('devices', { ...d, status: 'revoked', statusReason: `Replaced by ${sn}: ${r}`, history: [...(d.history || []), { at: Date.now(), by: a.id, action: 'Device replaced', reason: r }] });
  await log(a, 'DEVICE_REPLACED', `${d.hostname} -> ${sn}: ${r}`);
  return `Old identity revoked. Enroll the replacement (${sn}) and re-attest it.`;
}

/* ---------------- Compatibility / preflight ---------------- */
export function evaluateDevice(d, profile = d.profile || 'standard-uefi') {
  const hw = PROFILES[profile] || PROFILES['standard-uefi'];
  const checks = CHECKS.map((c) => {
    const r = checkStatus(c.key, hw, d);
    const ex = (d.exceptions || []).find((x) => x.check === c.key && (!x.expiresAt || x.expiresAt > Date.now()));
    return { ...c, ...r, exception: ex || null, effective: ex ? 'PASS' : r.status };
  });
  const mandatory = checks.filter((c) => c.mandatory);
  const overall = mandatory.some((c) => c.effective === 'FAIL') ? 'FAIL' : mandatory.some((c) => c.effective === 'BLOCKED') ? 'BLOCKED' : mandatory.some((c) => c.effective === 'UNKNOWN' || c.effective === 'NOT_RUN') ? 'UNKNOWN' : 'PASS';
  return { checks, overall, profile };
}
export async function runCompatibility(a, d, profile) {
  need(a, 'compat.manage'); assertScope(a, d.tenantId);
  if (d.status !== 'enrolled') fail('Compatibility checks run only for enrolled devices.');
  const res = evaluateDevice(d, profile || d.profile);
  const rec = { id: id('cmp'), tenantId: d.tenantId, deviceId: d.id, hostname: d.hostname, profile: res.profile, runAt: Date.now(), releaseId: d.releaseId, checks: res.checks, overall: res.overall, by: a.id };
  await put('compat', rec);
  await put('devices', { ...d, profile: res.profile, compatStatus: res.overall, lastCompatAt: rec.runAt });
  await log(a, 'COMPAT_CHECK_RUN', `${d.hostname} ${res.overall}`);
  if (res.overall === 'FAIL') {
    const { raise } = await import('../incidents/service');
    await raise({ tenantId: d.tenantId, key: `compat:${d.id}`, title: `Compatibility failed · ${d.hostname}`, severity: 'medium', source: 'preflight', deviceId: d.id });
  }
  return res;
}
export async function grantException(a, d, checkKey, reason, days = 7) {
  need(a, 'compat.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 10);
  const check = CHECKS.find((c) => c.key === checkKey); if (!check) fail('Unknown check.');
  if (check.mandatory && !['superadmin', 'ops_admin', 'inst_admin'].includes(a.role)) fail('A mandatory check exception needs an institution administrator.');
  const ex = { check: checkKey, by: a.id, at: Date.now(), reason: r, expiresAt: Date.now() + Math.max(1, Math.min(30, Number(days) || 7)) * 864e5 };
  await put('devices', { ...d, exceptions: [...(d.exceptions || []).filter((x) => x.check !== checkKey), ex], history: [...(d.history || []), { at: Date.now(), by: a.id, action: `Exception for ${checkKey}`, reason: r }] });
  await log(a, 'COMPAT_EXCEPTION', `${d.hostname} ${checkKey}: ${r}`);
  return `Exception recorded for ${check.label}, expiring in ${days} day(s).`;
}
export const latestCompat = (list, deviceId) => list.filter((c) => c.deviceId === deviceId).sort((a, b) => b.runAt - a.runAt)[0];
export const deviceState = (d, t = Date.now()) => {
  if (d.status !== 'enrolled') return d.status;
  if (d.isolated) return 'isolated';
  if (!reachable(d, t)) return 'offline';
  if (d.trust === 'failed') return 'failed';
  if (d.compatStatus === 'FAIL') return 'compat-fail';
  return 'enrolled';
};
export const deviceStats = (devices, t = Date.now()) => ({
  total: devices.length,
  enrolled: devices.filter((d) => d.status === 'enrolled').length,
  pending: devices.filter((d) => d.status === 'pending').length,
  suspended: devices.filter((d) => d.status === 'suspended').length,
  revoked: devices.filter((d) => d.status === 'revoked').length,
  online: devices.filter((d) => reachable(d, t)).length,
  attested: devices.filter((d) => d.trust === 'attested').length,
  failed: devices.filter((d) => d.trust === 'failed').length,
});
