import { can, isGlobal } from '../security/rbac';
import { record } from '../security/auditChain';
import { randomId, sha256 } from '../security/crypto';
import { get, put } from '../db/db';
import { genKeyPair } from '../security/crypto';
import { clean } from '../security/sanitize';

export const id = (p) => `${p}_${randomId(5)}`;
export const SYSTEM = { id: 'system', role: 'system' };
export const need = (a, perm) => { if (!can(a?.role, perm)) throw new Error(`Permission denied: your role cannot ${perm}.`); };
export const fail = (m) => { throw new Error(m); };
export const log = (a, ev, detail = '') => record(a.id, ev, detail);
export const now = () => Date.now();
export const day = 864e5;

/** Tenant boundary check. Platform-level roles are global; everyone else is pinned to their institution. */
export const inScope = (a, tenantId) => isGlobal(a?.role) || !a?.tenantId || a.tenantId === tenantId;
export function assertScope(a, tenantId) {
  if (!tenantId) fail('No institution context. Select an institution first.');
  if (!inScope(a, tenantId)) fail('This record belongs to another institution.');
}
export const requireReason = (reason, min = 8) => {
  const r = clean(reason, 300);
  if (r.length < min) fail(`Enter a reason of at least ${min} characters.`);
  return r;
};

export const cmpVer = (a, b) => {
  const x = String(a).split('-')[0].split('.').map(Number), y = String(b).split('-')[0].split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  const pa = String(a).includes('-'), pb = String(b).includes('-'); return pa === pb ? 0 : pa ? -1 : 1;
};
export const seatLabel = (i) => String.fromCharCode(65 + Math.floor(i / 16)) + String((i % 16) + 1).padStart(2, '0');
export async function ensureKey(kid) {
  let k = await get('keys', kid);
  if (!k) { const p = await genKeyPair(); k = { id: kid, priv: p.privateKey, pub: await crypto.subtle.exportKey('jwk', p.publicKey) }; await put('keys', k); }
  return k;
}
export const PCRS = [0, 2, 4, 7, 11];
export function genQuestions(n, rnd = Math.random) {
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1)); const out = [];
  for (let i = 0; i < n; i++) {
    const k = ri(0, 2), a = ri(12, 99), b = ri(3, 19), c = ri(2, 40); let q, ans;
    if (k === 0) { q = `What is ${a} × ${b} + ${c}?`; ans = a * b + c; }
    else if (k === 1) { q = `A train covers ${a * b} km in ${b} hours. What is its average speed in km/h?`; ans = a; }
    else { q = `What is ${c}% of ${a * 100}?`; ans = c * a; }
    const set = new Set([ans]); while (set.size < 4) set.add(ans + (ri(-15, 15) || 16));
    const opts = [...set].sort(() => rnd() - 0.5);
    out.push({ q, options: opts.map(String), answer: opts.indexOf(ans) });
  }
  return out;
}
export const score = (exam, answers) => exam.questions.reduce((s, q, i) => s + (answers[i] === q.answer ? 1 : 0), 0);
export const mulberry32 = (a) => () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };

export const isEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e)) && String(e).length <= 120;
export const validHttps = (u) => { try { const x = new URL(u); return x.protocol === 'https:' && !x.username && !x.password; } catch { return false; } };
export const fmtBytes = (b) => { const n = Number(b) || 0; return n > 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(0)} KB`; };
export const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
export const unique = (arr) => [...new Set(arr)];
export const sortBy = (arr, key, dir = 'asc') => [...arr].sort((x, y) => (x[key] > y[key] ? 1 : x[key] < y[key] ? -1 : 0) * (dir === 'asc' ? 1 : -1));
export const within = (t, from, to) => (!from || t >= Date.parse(from)) && (!to || t <= Date.parse(to) + day - 1);
export const age = (t) => (t ? Date.now() - t : Infinity);
export async function hashOf(v) { return sha256(typeof v === 'string' ? v : JSON.stringify(v)); }

const CSV = (rows) => rows.map((r) => r.map((c) => {
  let s = String(c ?? '').replace(/"/g, '""');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s}"`;
}).join(',')).join('\n');
export function downloadCsv(filename, cols, rows) {
  const csv = CSV([cols, ...rows]);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
export function downloadJson(filename, data) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
