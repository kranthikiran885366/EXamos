import { sha256 } from './crypto';
import { all, put } from '../db/db';
// Persistent, hash-chained audit log. Each entry commits to the previous hash; verification reads the stored rows.
let chain = [];
const subs = new Set();
const body = (e, prev) => JSON.stringify([e.seq, e.ts, e.actor, e.event, e.detail, prev]);
let lock = Promise.resolve();
export async function initChain() { chain = (await all('audit')).sort((a, b) => a.seq - b.seq); subs.forEach((f) => f()); }
export function record(actor, event, detail = '') {
  lock = lock.then(async () => {
    const prev = chain.length ? chain[chain.length - 1].hash : 'GENESIS';
    const seq = chain.length + 1;
    const e = { id: String(seq).padStart(8, '0'), seq, ts: new Date().toISOString(), actor, event, detail: String(detail).slice(0, 300), prev };
    e.hash = await sha256(body(e, prev));
    chain = [...chain, Object.freeze(e)];
    await put('audit', e);
    subs.forEach((f) => f());
    return e;
  }).catch(() => {});
  return lock;
}
export const getChain = () => chain;
export const subscribe = (f) => { subs.add(f); return () => subs.delete(f); };
export async function verifyChain() {
  const rows = (await all('audit')).sort((a, b) => a.seq - b.seq);
  let prev = 'GENESIS', n = 0;
  for (const e of rows) {
    if (e.seq !== ++n || e.prev !== prev || (await sha256(body(e, prev))) !== e.hash) return { ok: false, at: e.seq };
    prev = e.hash;
  }
  return { ok: true, count: rows.length };
}
