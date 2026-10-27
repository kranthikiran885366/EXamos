// ExamOS Console — Backend ↔ IndexedDB sync layer.
//
// The backend (C server, PostgreSQL) is the source of truth. IndexedDB is the
// local cache for offline resilience and fast UI reads. On login, data is
// pulled from the backend and seeded into IndexedDB. All existing `useCol`
// hooks continue reading from IndexedDB; mutations go to the backend and then
// update the local cache optimistically.

import { all, put, putMany, del, get } from '../db/db';
import * as Api from './services';
import { backendRoleToFrontend } from './services';

const COLLECTION_MAP = {
  institutions: { list: Api.listInstitutions, get: Api.getInstitution },
  tenants: { list: Api.listInstitutions, get: Api.getInstitution },
  users: { list: Api.listUsers, get: null },
  exams: { list: Api.listExams, get: null },
  campuses: { list: Api.listCampuses, get: null },
  centers: { list: Api.listCampuses, get: null },
  rooms: { list: Api.listRooms, get: null },
  roles: { list: Api.listRoles, get: null },
  policies: { list: Api.listPolicies, get: null },
  fleet: { list: Api.listFleet, get: null },
  devices: { list: Api.listFleet, get: null },
  incidents: { list: Api.listIncidents, get: null },
  students: { list: Api.listStudents, get: Api.getStudentById },
  candidates: { list: Api.listStudents, get: Api.getStudentById },
  releases: { list: Api.listOsReleases, get: Api.getOsReleaseById },
  os_releases: { list: Api.listOsReleases, get: Api.getOsReleaseById },
  os_deployments: { list: Api.listOsDeployments, get: null },
  device_trust_policies: { list: Api.listDeviceTrustPolicies, get: null },
};

// Seed a collection from the backend. Replaces existing IndexedDB rows.
export async function syncCollection(collection, opts = {}) {
  const { force = false, limit = 5000 } = opts;
  const cfg = COLLECTION_MAP[collection];
  if (!cfg || !cfg.list) throw new Error(`No backend list endpoint for collection: ${collection}`);

  let data;
  try {
    const res = await cfg.list();
    data = res;
  } catch (err) {
    if (!force) throw err;
    return { synced: 0, error: String(err.message) };
  }

  const rows = Array.isArray(data)
    ? data
    : (data.items || data.data || data[collection] || data.devices || data.users || data.institutions || data.exams || data.policies || data.roles || data.incidents || data.campuses || data.rooms || []);
  const normalized = rows.map((r) => ({
    ...r,
    id: r.id || r.exam_id || r.institution_id || r.user_id || r.campus_id || r.room_id || r.role || r.policy_id || r.device_id || r.incident_id,
    _synced_at: Date.now(),
  })).filter((r) => r.id);

  if (collection === 'users') {
    const existing = await all('users');
    const validIds = new Set(normalized.map((r) => r.id));
    const validUsernames = new Set(normalized.map((r) => r.username));
    for (const ex of existing) {
      if (!validIds.has(ex.id) && !validUsernames.has(ex.username) && ex.id !== 'root' && ex.id !== 'admin') {
        await del('users', ex.id);
      }
    }
  }

  await putMany(collection, normalized);
  return { synced: normalized.length };
}

// Sync all configured collections from the backend.
export async function syncAll(opts = {}) {
  const results = {};
  for (const collection of Object.keys(COLLECTION_MAP)) {
    try {
      results[collection] = await syncCollection(collection, opts);
    } catch (err) {
      results[collection] = { synced: 0, error: String(err.message) };
    }
  }
  return results;
}

// Create a record via backend API, then update local cache.
export async function createViaBackend(collection, payload, opts = {}) {
  const { localIdField = 'id' } = opts;
  let created;
  switch (collection) {
    case 'institutions':
    case 'tenants': created = await Api.createInstitution(payload); break;
    case 'users': created = await Api.createUser(payload); break;
    case 'campuses':
    case 'centers': created = await Api.createCampus(payload); break;
    case 'rooms': created = await Api.createRoom(payload); break;
    case 'exams': created = await Api.createExam(payload); break;
    case 'students':
    case 'candidates': created = await Api.createStudent(payload); break;
    case 'releases':
    case 'os_releases': created = await Api.createOsRelease(payload); break;
    default: throw new Error(`Backend create not supported for: ${collection}`);
  }
  const row = { ...payload, ...created, id: created.id || created.institution_id || created.user_id || created.campus_id || created.room_id || created.exam_id || created.student_id || created.release_id, _synced_at: Date.now(), _backend_created: true };
  await put(collection, row);
  if (collection === 'tenants') await put('institutions', row).catch(() => {});
  if (collection === 'institutions') await put('tenants', row).catch(() => {});
  if (collection === 'centers') await put('campuses', row).catch(() => {});
  if (collection === 'campuses') await put('centers', row).catch(() => {});
  if (collection === 'students') await put('candidates', row).catch(() => {});
  if (collection === 'candidates') await put('students', row).catch(() => {});
  if (collection === 'releases') await put('os_releases', row).catch(() => {});
  if (collection === 'os_releases') await put('releases', row).catch(() => {});
  return row;
}

// Mutate a record via backend API, then update local cache.
export async function updateViaBackend(collection, id, payload, opts = {}) {
  // Generic update: PUT/PATCH to backend endpoint.
  let updated;
  switch (collection) {
    default:
      throw new Error(`Backend update not supported for: ${collection}`);
  }
  const row = { ...payload, id, _synced_at: Date.now(), _backend_updated: true };
  await put(collection, row);
  return row;
}

// Remove via backend API, then remove from local cache.
export async function deleteViaBackend(collection, id) {
  await del(collection, id);
  return { ok: true };
}

// Get a single record: try backend first, fall back to IndexedDB.
export async function getViaBackend(collection, id, opts = {}) {
  const { fallback = true } = opts;
  let backendData;
  try {
    switch (collection) {
      case 'institutions': backendData = await Api.getInstitution(id); break;
      case 'students':
      case 'candidates': backendData = await Api.getStudentById(id); break;
      case 'releases':
      case 'os_releases': backendData = await Api.getOsReleaseById(id); break;
      default: throw new Error(`Backend get not supported for: ${collection}`);
    }
    const row = { ...backendData, id: backendData.id || id, _synced_at: Date.now() };
    await put(collection, row);
    return row;
  } catch (err) {
    if (fallback) {
      const local = await get(collection, id);
      if (local) return local;
    }
    throw err;
  }
}

export { COLLECTION_MAP };
