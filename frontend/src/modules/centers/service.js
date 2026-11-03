import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason } from '../../core/services/common';
import * as Api from '../../core/api/services';

export async function listCenters(tenantId) {
  return (await all('centers')).filter((c) => !tenantId || c.tenantId === tenantId);
}

export async function createCenter(a, { tenantId, campusId = '', code, name, city, labs, seatsPerLab }) {
  need(a, 'center.manage'); assertScope(a, tenantId);
  const t = await get('tenants', tenantId);
  if (!t || t.status !== 'active') fail('The institution is not active.');
  code = clean(code, 10).toUpperCase();
  if (!/^[A-Z]{3}-\d{1,3}$/.test(code)) fail('Center code looks like BLR-87.');
  const cs = (await all('centers')).filter((c) => c.tenantId === tenantId);
  if (cs.some((c) => c.code === code)) fail('Center code is already used.');
  if (cs.length >= t.maxCenters) fail(`Plan limit reached: ${t.maxCenters} centers.`);
  if (campusId) { const cp = await get('campuses', campusId); if (!cp || cp.tenantId !== tenantId) fail('Pick a campus in this institution.'); }
  labs = Number(labs); seatsPerLab = Number(seatsPerLab);
  if (!(labs >= 1 && labs <= 12)) fail('Labs must be 1–12.');
  if (!(seatsPerLab >= 8 && seatsPerLab <= 96)) fail('Seats per lab must be 8–96.');
  if (labs * seatsPerLab > 416) fail('Capacity cannot exceed 416 seats per center.');
  if (clean(name, 80).length < 3) fail('Enter a center name.');

  let centerId;
  try {
    const res = await Api.createCampus({ tenantId, name: clean(name, 80), code, city: clean(city, 40), capacity: labs * seatsPerLab });
    centerId = res?.campus_id || res?.id;
  } catch (err) {
    fail(err.message || 'Backend center creation failed.');
  }

  const centerObj = {
    id: centerId || id('ctr'), tenantId, campusId, code, name: clean(name, 80),
    city: clean(city, 40), labs, seatsPerLab, capacity: labs * seatsPerLab,
    status: 'active', createdAt: Date.now(),
  };
  await put('centers', centerObj);
  await log(a, 'CENTER_CREATED', code);
  return `Center ${code} created with ${labs * seatsPerLab} seats.`;
}

export async function updateCenter(a, c, patch) {
  need(a, 'center.manage'); assertScope(a, c.tenantId);
  const next = { ...c };
  if (patch.name !== undefined) next.name = clean(patch.name, 80);
  if (patch.city !== undefined) next.city = clean(patch.city, 40);
  if (patch.labs !== undefined || patch.seatsPerLab !== undefined) {
    const labs = Number(patch.labs ?? c.labs), seats = Number(patch.seatsPerLab ?? c.seatsPerLab);
    if (!(labs >= 1 && labs <= 12)) fail('Labs must be 1–12.');
    if (!(seats >= 8 && seats <= 96)) fail('Seats per lab must be 8–96.');
    if (labs * seats > 416) fail('Capacity cannot exceed 416 seats per center.');
    next.labs = labs; next.seatsPerLab = seats; next.capacity = labs * seats;
  }
  if (patch.campusId !== undefined) next.campusId = patch.campusId || '';

  try {
    await Api.updateCampus(c.id, { name: next.name, city: next.city, capacity: next.capacity });
  } catch (err) {
    fail(err.message || 'Backend center update failed.');
  }

  await put('centers', next);
  await log(a, 'CENTER_UPDATED', c.code);
  return 'Center updated.';
}

export async function setCenterStatus(a, c, status, reason) {
  need(a, 'center.manage'); assertScope(a, c.tenantId);
  const r = requireReason(reason, 8);
  if (status === 'inactive' && (await all('exams')).some((e) => e.centerIds.includes(c.id) && !['closed', 'cancelled'].includes(e.status)))
    fail('An open exam uses this center. Close or cancel it first.');

  try {
    await Api.setCampusStatus(c.id, status, r);
  } catch (err) {
    fail(err.message || 'Backend center status update failed.');
  }

  await put('centers', { ...c, status, statusReason: r });
  await log(a, 'CENTER_' + status.toUpperCase(), `${c.code}: ${r}`);
  return `${c.code} is now ${status}.`;
}

export async function assignCenterCampus(a, c, campusId) {
  need(a, 'center.manage'); assertScope(a, c.tenantId);
  if (campusId) { const cp = await get('campuses', campusId); if (!cp || cp.tenantId !== c.tenantId) fail('Pick a campus in this institution.'); }
  await put('centers', { ...c, campusId });
  await log(a, 'CENTER_CAMPUS_ASSIGNED', `${c.code} -> ${campusId || 'none'}`);
  return 'Center linked to campus.';
}
