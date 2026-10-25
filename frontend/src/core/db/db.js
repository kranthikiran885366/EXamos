// IndexedDB persistence layer. All module data lives here; nothing is hardcoded in the UI.
const NAME = 'examos-console', VER = 4;
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
  'audit', 'apiAudit', 'meta', 'keys',
];
let dbp; const L = new Set();
const bc = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('examos') : null;
if (bc) bc.onmessage = (e) => L.forEach((f) => f(e.data));
export const onChange = (f) => { L.add(f); return () => L.delete(f); };
const emit = (c) => { L.forEach((f) => f(c)); bc?.postMessage(c); };
export const lat = []; // measured operation latencies (ms), used for the real p95 KPI
const open = () => dbp || (dbp = new Promise((res, rej) => {
  const r = indexedDB.open(NAME, VER);
  r.onupgradeneeded = () => {
    const db = r.result;
    for (const c of COLS) if (!db.objectStoreNames.contains(c)) db.createObjectStore(c, { keyPath: 'id' });
  };
  r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
}));
async function tx(col, mode, fn) {
  const db = await open(); const t0 = performance.now();
  return new Promise((res, rej) => {
    const t = db.transaction(col, mode); const r = fn(t.objectStore(col));
    t.oncomplete = () => { lat.push(performance.now() - t0); if (lat.length > 300) lat.shift(); res(r && 'result' in r ? r.result : undefined); };
    t.onerror = t.onabort = () => rej(t.error);
  });
}
export const all = (c) => tx(c, 'readonly', (s) => s.getAll());
export const get = (c, id) => tx(c, 'readonly', (s) => s.get(id));
export const put = async (c, v) => { await tx(c, 'readwrite', (s) => s.put(v)); emit(c); return v; };
export const putMany = async (c, vs) => { if (!vs.length) return; await tx(c, 'readwrite', (s) => { vs.forEach((v) => s.put(v)); }); emit(c); };
export const del = async (c, id) => { await tx(c, 'readwrite', (s) => s.delete(id)); emit(c); };
export const delMany = async (c, ids) => { if (!ids.length) return; await tx(c, 'readwrite', (s) => { ids.forEach((id) => s.delete(id)); }); emit(c); };
export const p95 = () => { if (!lat.length) return 0; const s = [...lat].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * 0.95))]; };
export const storeNames = () => [...COLS];
export async function wipe() { (await open()).close(); dbp = null; await new Promise((r) => { const q = indexedDB.deleteDatabase(NAME); q.onsuccess = q.onerror = q.onblocked = r; }); }
