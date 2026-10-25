import { all, get, put, putMany } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log } from '../../core/services/common';
import { verifyRelease } from '../releases/service';

export async function createProfile(a, { tenantId, name, releaseId, lockdown, blockClipboard, blockCapture }) {
  need(a, 'kiosk.manage'); name = clean(name, 60);
  if (name.length < 3) fail('Give the profile a name.');
  const rel = await get('releases', releaseId);
  if (!rel || !['approved', 'rolling', 'stable'].includes(rel.status)) fail('Pick an approved, rolling or stable release.');
  if ((await all('kiosks')).some((k) => k.tenantId === tenantId && k.name === name && k.releaseId === releaseId)) fail('This profile already exists for that release.');
  await put('kiosks', { id: id('kio'), tenantId, name, releaseId, lockdown, blockClipboard: !!blockClipboard, blockCapture: !!blockCapture, status: 'canary', createdBy: a.id, createdAt: Date.now() });
  await log(a, 'KIOSK_PROFILE_CREATED', `${name} -> ${rel.version}`); return `Profile ${name} created as canary.`;
}
export async function promote(a, k) {
  need(a, 'kiosk.manage'); if (k.status !== 'canary') fail('Only canary profiles can be promoted.');
  const rel = await get('releases', k.releaseId);
  if (!rel || rel.status === 'revoked' || rel.status === 'candidate') fail('The linked release is not approved.');
  if (!(await verifyRelease(rel))) fail('Release signature failed verification.');
  await put('kiosks', { ...k, status: 'stable' }); await log(a, 'KIOSK_PROMOTED', k.name); return `${k.name} is stable.`;
}
export async function retire(a, k, reason) { need(a, 'kiosk.manage'); await put('kiosks', { ...k, status: 'retired' }); await log(a, 'KIOSK_RETIRED', `${k.name}: ${reason}`); }
export async function assignToCenter(a, k, centerId) {
  need(a, 'kiosk.manage'); if (k.status === 'retired') fail('Retired profiles cannot be assigned.');
  const c = await get('centers', centerId); if (!c || c.tenantId !== k.tenantId) fail('Pick a center.');
  const devs = (await all('devices')).filter((d) => d.centerId === centerId && d.status === 'enrolled');
  if (!devs.length) fail('No enrolled devices at that center.');
  await putMany('devices', devs.map((d) => ({ ...d, kioskId: k.id }))); await log(a, 'KIOSK_ASSIGNED', `${k.name} -> ${c.code} (${devs.length})`);
  return `${k.name} assigned to ${devs.length} device(s) at ${c.code}.`;
}
