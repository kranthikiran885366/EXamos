// Application records are read and written only through the authenticated API.
import { api } from '../api/client';
import { ENDPOINTS } from '../../config/api';

const listeners = new Set();
const collectionWatchers = new Map();
let refreshTimer;
const latency = [];

export const COLS = [
  'tenants', 'campuses', 'departments', 'staff', 'centers',
  'users', 'invitations', 'authSessions', 'roles',
  'exams', 'candidates', 'sessions',
  'devices', 'attestations', 'compat', 'usbs', 'custody',
  'policies', 'approvals', 'rules', 'kiosks',
  'incidents', 'securityEvents', 'vulnerabilities', 'evidence',
  'releases', 'releaseEvidence', 'rollouts',
  'support', 'notifications', 'reports',
  'plans', 'subscriptions', 'invoices',
  'privacy', 'retention', 'features', 'configs', 'integrations',
  'services', 'alerts', 'jobs', 'backups',
  'audit', 'apiAudit', 'meta',
];

export const onChange = (callback) => {
  listeners.add(callback);
  return () => listeners.delete(callback);
};
const emit = (collection) => listeners.forEach((callback) => callback(collection));

function pathFor(collection, recordId) {
  if (!COLS.includes(collection) || ['authSessions', 'apiAudit'].includes(collection)) {
    throw new Error(`Unsupported server collection: ${collection}`);
  }
  const path = `${ENDPOINTS.consoleData}/${encodeURIComponent(collection)}`;
  return recordId === undefined ? path : `${path}/${encodeURIComponent(String(recordId))}`;
}

async function timed(operation) {
  const beganAt = performance.now();
  try {
    const result = await operation();
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('examos:backend-online'));
    return result;
  } catch (error) {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('examos:backend-error', { detail: error.message || String(error) }));
    }
    throw error;
  } finally {
    latency.push(performance.now() - beganAt);
    if (latency.length > 300) latency.shift();
  }
}

export const all = (collection) => timed(async () => {
  const response = await api.get(pathFor(collection), { actor: 'console' });
  if (!Array.isArray(response.data)) throw new Error(`Invalid response for ${collection}: expected an array.`);
  return response.data;
});

export const get = (collection, recordId) => timed(async () => {
  const response = await api.get(pathFor(collection, recordId), { actor: 'console' });
  return response.data ?? undefined;
});

export const put = async (collection, value) => {
  if (!value || typeof value.id !== 'string' || !value.id) throw new Error(`A record id is required for ${collection}.`);
  const response = await timed(() => api.put(pathFor(collection, value.id), value, { actor: 'console', sign: true }));
  value = response.data;
  emit(collection);
  return value;
};

export const putMany = async (collection, values) => {
  if (!values.length) return;
  await Promise.all(values.map((value) => put(collection, value)));
};

export const del = async (collection, recordId) => {
  await timed(() => api.del(pathFor(collection, recordId), { actor: 'console' }));
  emit(collection);
};

export const delMany = async (collection, recordIds) => {
  await Promise.all(recordIds.map((recordId) => del(collection, recordId)));
};

export const watchCollection = (collection, callback) => {
  let callbacks = collectionWatchers.get(collection);
  if (!callbacks) {
    callbacks = new Set();
    collectionWatchers.set(collection, callbacks);
  }
  callbacks.add(callback);
  if (!refreshTimer) {
    refreshTimer = setInterval(async () => {
      for (const [name, subscribers] of collectionWatchers) {
        try {
          const records = await all(name);
          subscribers.forEach((subscriber) => subscriber(records, null));
        } catch (error) {
          subscribers.forEach((subscriber) => subscriber(null, error));
        }
      }
    }, 30000);
  }
  return () => {
    callbacks.delete(callback);
    if (!callbacks.size) collectionWatchers.delete(collection);
    if (!collectionWatchers.size && refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  };
};

export const lat = latency;
export const p95 = () => {
  if (!latency.length) return 0;
  const sorted = [...latency].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
};
export const storeNames = () => [...COLS];
