import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason } from '../../core/services/common';
import { sha256, canon } from '../../core/security/crypto';
import { verifyRelease } from '../releases/service';

export const STATUSES = ['prepared', 'verified', 'issued', 'returned', 'quarantined', 'lost', 'revoked', 'retired'];
export const HARDWARE_MODELS = ['SanDisk Extreme 64GB', 'Samsung BAR Plus 64GB', 'Kingston DataTraveler 128GB', 'Generic USB 3.0 32GB'];

export async function createUsb(a, { tenantId, assetId, serial, model = HARDWARE_MODELS[0], capacityGb = 64, notes = '' }) {
  need(a, 'usb.manage'); assertScope(a, tenantId);
  const asset = clean(assetId, 40).toUpperCase(); const sn = clean(serial, 40).toUpperCase();
  if (!/^[A-Z0-9-]{4,40}$/.test(asset)) fail('Asset ID: 4–40 letters, digits or -.');
  if (!/^[A-Z0-9-]{6,40}$/.test(sn)) fail('Serial: 6–40 letters, digits or -.');
  const list = await all('usbs');
  if (list.some((u) => u.assetId === asset)) fail('That asset ID already exists.');
  if (list.some((u) => u.serial === sn)) fail('That hardware serial is already registered.');
  const now = Date.now();
  const u = { id: id('usb'), tenantId, assetId: asset, serial: sn, model: clean(model, 60), capacityGb: Number(capacityGb) || 64, status: 'prepared', releaseId: null, imageDigest: null, writtenHash: null, station: '', preparedAt: 0, preparedBy: null, assigned: null, holder: null, custody: [], notes: clean(notes, 300), lastCheckAt: now, createdAt: now, createdBy: a.id };
  await put('usbs', u); await log(a, 'USB_REGISTERED', `${asset} ${sn}`);
  return u;
}

export async function prepareUsb(a, usb, { releaseId, station, writtenHash, confirmation, target }) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  if (['issued'].includes(usb.status)) fail('Return this USB before re-imaging it.');
  if (usb.status === 'revoked' || usb.status === 'retired') fail('This USB is revoked or retired. Use a new asset.');
  if (target !== 'removable-usb') fail('Explicitly identify the removable USB target. Internal disks are never eligible.');
  if (clean(confirmation, 60).toUpperCase() !== usb.assetId) fail(`Type the asset ID (${usb.assetId}) to confirm this erase operation.`);
  const rel = await get('releases', releaseId);
  if (!rel || !['approved', 'rolling', 'stable'].includes(rel.status)) fail('Pick an approved release.');
  if (!(await verifyRelease(rel))) fail('The release signature failed verification.');
  const stationName = clean(station, 60); if (stationName.length < 3) fail('Record the preparation station.');
  const hash = clean(writtenHash, 80).toLowerCase();
  if (hash && !/^[a-f0-9]{64}$/.test(hash)) fail('Written-image hash must be a SHA-256 hex digest.');
  const verified = hash === rel.digest;
  const now = Date.now();
  const custody = [...(usb.custody || []), { at: now, by: a.id, action: `Prepared with ${rel.version}`, station: stationName, hash: hash || null, verified }];
  const next = { ...usb, releaseId: rel.id, imageDigest: rel.digest, writtenHash: hash || null, station: stationName, preparedAt: now, preparedBy: a.id, status: verified ? 'verified' : 'quarantined', custody, lastCheckAt: now };
  await put('usbs', next);
  await log(a, 'USB_PREPARED', `${usb.assetId} ${rel.version} verified=${verified}`);
  if (!verified) fail('The written hash does not match the approved manifest. The USB was quarantined.');
  return `${usb.assetId} prepared and hash-verified against ${rel.version}.`;
}

export async function assignUsb(a, usb, { centerId = '', campusId = '', candidateId = '' }) {
  need(a, 'usb.assign'); assertScope(a, usb.tenantId);
  if (['revoked', 'retired', 'lost'].includes(usb.status)) fail(`A ${usb.status} USB cannot be assigned.`);
  if (usb.releaseId) {
    const rel = await get('releases', usb.releaseId);
    if (!rel || rel.status === 'revoked') fail('This USB is linked to a revoked release.');
  }
  const assigned = { centerId, campusId, candidateId, at: Date.now(), by: a.id };
  await put('usbs', { ...usb, assigned, custody: [...(usb.custody || []), { at: Date.now(), by: a.id, action: `Assigned to ${candidateId || centerId || campusId || 'institution'}` }] });
  await log(a, 'USB_ASSIGNED', `${usb.assetId} -> ${candidateId || centerId || campusId}`);
  return `${usb.assetId} assignment recorded.`;
}

export async function issueUsb(a, usb, { holderName, holderId, reason }) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  if (!['prepared', 'verified', 'returned'].includes(usb.status)) fail(`A ${usb.status} USB cannot be issued.`);
  if (!usb.releaseId) fail('Prepare and verify this USB before issuing it.');
  const rel = await get('releases', usb.releaseId);
  if (!rel || rel.status === 'revoked') fail('This USB is linked to a revoked release.');
  const name = clean(holderName, 80); if (name.length < 2) fail('Record who is taking custody.');
  const r = requireReason(reason || 'Exam issue', 5);
  const record = { at: Date.now(), by: a.id, action: 'Issued', holderName: name, holderId: clean(holderId, 40), reason: r };
  const custody = [...(usb.custody || []), record];
  const signature = await sha256(canon(record));
  await put('usbs', { ...usb, status: 'issued', holder: { name, id: clean(holderId, 40), since: Date.now() }, custody, lastCheckAt: Date.now() });
  await log(a, 'USB_ISSUED', `${usb.assetId} -> ${name} sig=${signature.slice(0, 10)}`);
  return `${usb.assetId} issued to ${name}. Custody receipt ${signature.slice(0, 12).toUpperCase()}.`;
}

export async function returnUsb(a, usb, { condition = 'good', reason = '' }) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  if (usb.status !== 'issued') fail('This USB is not currently issued.');
  const r = clean(reason, 200);
  const bad = condition !== 'good';
  const next = { ...usb, status: bad ? 'quarantined' : 'returned', holder: null, lastCheckAt: Date.now(), custody: [...(usb.custody || []), { at: Date.now(), by: a.id, action: `Returned (${condition})${r ? ': ' + r : ''}` }] };
  await put('usbs', next); await log(a, 'USB_RETURNED', `${usb.assetId} ${condition}`);
  return bad ? `${usb.assetId} returned and quarantined for inspection.` : `${usb.assetId} returned in good condition.`;
}

export async function reportUsb(a, usb, { kind, reason }) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  const r = requireReason(reason, 8);
  if (!['lost', 'damaged', 'stolen'].includes(kind)) fail('Unknown report type.');
  const status = kind === 'lost' || kind === 'stolen' ? 'lost' : 'quarantined';
  await put('usbs', { ...usb, status, incident: { kind, at: Date.now(), by: a.id, reason: r }, custody: [...(usb.custody || []), { at: Date.now(), by: a.id, action: `${kind}: ${r}` }] });
  await log(a, 'USB_' + kind.toUpperCase(), `${usb.assetId}: ${r}`);
  const { raise } = await import('../incidents/service');
  await raise({ tenantId: usb.tenantId, key: `usb:${usb.id}:${kind}`, title: `USB ${usb.assetId} ${kind}`, severity: kind === 'stolen' ? 'high' : 'medium', source: 'usb-inventory' });
  return `${usb.assetId} marked ${status}. An incident was raised.`;
}

export async function setUsbStatus(a, usb, status, reason) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  if (!['quarantined', 'revoked', 'retired'].includes(status)) fail('Use the custody actions for issue and return.');
  const r = requireReason(reason, 8);
  if (status === 'revoked' && !['superadmin', 'ops_admin', 'security_engineer'].includes(a.role)) fail('Revoking a USB needs a security role.');
  await put('usbs', { ...usb, status, statusReason: r, custody: [...(usb.custody || []), { at: Date.now(), by: a.id, action: `Status → ${status}: ${r}` }] });
  await log(a, 'USB_' + status.toUpperCase(), `${usb.assetId}: ${r}`);
  return `${usb.assetId} is now ${status}.`;
}

export async function inventoryCheck(a, usb, { present, location, reason = '' }) {
  need(a, 'usb.manage'); assertScope(a, usb.tenantId);
  const next = { ...usb, lastCheckAt: Date.now(), lastLocation: clean(location, 80), custody: [...(usb.custody || []), { at: Date.now(), by: a.id, action: present ? `Inventory check · ${location || 'present'}` : `Missing at inventory · ${reason}` }] };
  if (!present) next.status = 'quarantined';
  await put('usbs', next); await log(a, 'USB_INVENTORY_CHECK', `${usb.assetId} present=${present}`);
  return `Inventory check recorded for ${usb.assetId}.`;
}

export const usbStats = (list) => ({
  total: list.length,
  prepared: list.filter((u) => ['prepared', 'verified'].includes(u.status)).length,
  issued: list.filter((u) => u.status === 'issued').length,
  returned: list.filter((u) => u.status === 'returned').length,
  quarantined: list.filter((u) => u.status === 'quarantined').length,
  revoked: list.filter((u) => ['revoked', 'retired', 'lost'].includes(u.status)).length,
  stale: list.filter((u) => !u.lastCheckAt || Date.now() - u.lastCheckAt > 30 * 864e5).length,
});
export async function revokedReleaseFlag(usb) {
  if (!usb.releaseId) return false;
  const r = await get('releases', usb.releaseId);
  return !r || r.status === 'revoked';
}
export const custodyHash = async (usb) => sha256(canon(usb.custody || []));
