// Application records are stored in PostgreSQL. IndexedDB is reserved for
// non-exportable signing material and is never used as an application cache.
import { api } from '../api/client';
import { ENDPOINTS } from '../../config/api';

const KEY_STORE = 'examos-console-keys';
const KEY_COLLECTION = 'keys';
const listeners = new Set();
const collectionWatchers = new Map();
let refreshTimer;
let migrationPromise;
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
  'audit', 'apiAudit', 'meta', KEY_COLLECTION,
];

export const onChange = (callback) => {
  listeners.add(callback);
  return () => listeners.delete(callback);
};
const emit = (collection) => listeners.forEach((callback) => callback(collection));

function openKeyStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_STORE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(KEY_COLLECTION)) {
        request.result.createObjectStore(KEY_COLLECTION, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function keyTransaction(mode, operation) {
  const db = await openKeyStore();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_COLLECTION, mode);
    const request = operation(transaction.objectStore(KEY_COLLECTION));
    transaction.oncomplete = () => resolve(request?.result);
    transaction.onerror = transaction.onabort = () => reject(transaction.error);
  });
}

export function removeLegacyApplicationCache() {
  if (migrationPromise) return migrationPromise;
  migrationPromise = (async () => {
    const legacy = await new Promise((resolve, reject) => {
      const request = indexedDB.open('examos-console');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    let keys = [];
    if (legacy.objectStoreNames.contains(KEY_COLLECTION)) {
      keys = await new Promise((resolve, reject) => {
        const transaction = legacy.transaction(KEY_COLLECTION, 'readonly');
        const request = transaction.objectStore(KEY_COLLECTION).getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    }
    legacy.close();
    for (const key of keys) await keyTransaction('readwrite', (store) => store.put(key));
    await new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase('examos-console');
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('Close other ExamOS tabs to remove the legacy local data cache.'));
    });
  })();
  return migrationPromise;
}

function pathFor(collection, recordId) {
  if (!COLS.includes(collection) || ['keys', 'authSessions', 'apiAudit'].includes(collection)) {
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

export const all = (collection) => collection === KEY_COLLECTION
  ? keyTransaction('readonly', (store) => store.getAll())
  : timed(async () => {
    const response = await api.get(pathFor(collection), { actor: 'console' });
    if (!Array.isArray(response.data)) throw new Error(`Invalid response for ${collection}: expected an array.`);
    return response.data;
  });

export const get = (collection, recordId) => collection === KEY_COLLECTION
  ? keyTransaction('readonly', (store) => store.get(recordId))
  : timed(async () => {
    const response = await api.get(pathFor(collection, recordId), { actor: 'console' });
    return response.data ?? undefined;
  });

export const put = async (collection, value) => {
  if (!value || typeof value.id !== 'string' || !value.id) throw new Error(`A record id is required for ${collection}.`);
  if (collection === KEY_COLLECTION) await keyTransaction('readwrite', (store) => store.put(value));
  else {
    const response = await timed(() => api.put(pathFor(collection, value.id), value, { actor: 'console', sign: true }));
    value = response.data;
  }
  emit(collection);
  return value;
};

export const putMany = async (collection, values) => {
  if (!values.length) return;
  if (collection !== KEY_COLLECTION) {
    await Promise.all(values.map((value) => put(collection, value)));
    return;
  }
  await keyTransaction('readwrite', (store) => values.forEach((value) => store.put(value)));
  emit(collection);
};

export const del = async (collection, recordId) => {
  if (collection === KEY_COLLECTION) await keyTransaction('readwrite', (store) => store.delete(recordId));
  else await timed(() => api.del(pathFor(collection, recordId), { actor: 'console' }));
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
export async function wipe() {
  throw new Error('Workspace reset is unavailable for server-backed records.');
}
