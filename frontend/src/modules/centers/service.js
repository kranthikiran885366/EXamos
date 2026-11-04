import { clean } from '../../core/security/sanitize';
import * as Api from '../../core/api/services';

export async function listCenters(tenantId) {
  const response = await Api.listCenters();
  if (!Array.isArray(response?.centers)) {
    throw new Error('The backend returned an invalid centers response.');
  }
  const centers = response.centers.map((center) => ({
    ...center,
    id: center.id || center.center_id,
    tenantId: center.tenantId || center.tenant_id,
    campusId: center.campusId || center.campus_id || '',
    seatsPerLab: center.seatsPerLab ?? center.seats_per_lab,
  }));
  return tenantId ? centers.filter((center) => center.tenantId === tenantId) : centers;
}

export async function createCenter({ tenantId, campusId = '', code, name, city, labs, seatsPerLab }) {
  if (!tenantId) throw new Error('Select an institution before creating a center.');
  const normalizedCode = clean(code, 10).toUpperCase();
  const normalizedName = clean(name, 80);
  const normalizedCity = clean(city, 40);
  const labCount = Number(labs);
  const seats = Number(seatsPerLab);
  if (!/^[A-Z]{3}-\d{1,3}$/.test(normalizedCode)) throw new Error('Center code must look like BLR-87.');
  if (normalizedName.length < 3) throw new Error('Enter a center name of at least 3 characters.');
  if (!Number.isInteger(labCount) || labCount < 1 || labCount > 12) throw new Error('Labs must be 1–12.');
  if (!Number.isInteger(seats) || seats < 8 || seats > 96) throw new Error('Seats per lab must be 8–96.');
  if (labCount * seats > 416) throw new Error('Capacity cannot exceed 416 seats per center.');

  const response = await Api.createCenter({
    tenantId,
    campusId,
    code: normalizedCode,
    name: normalizedName,
    city: normalizedCity,
    labs: labCount,
    seatsPerLab: seats,
  });
  return response?.message || `Center ${normalizedCode} created.`;
}

export async function setCenterStatus(center, status, reason) {
  const response = await Api.setCenterStatus(center.id, status, reason);
  return response?.message || `${center.code} is now ${status}.`;
}
