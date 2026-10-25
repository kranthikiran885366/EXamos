import { all, putMany, p95 } from '../../core/db/db';
import { SYSTEM } from '../../core/services/common';
import { attest } from '../tpm/service';
import { raise } from '../incidents/service';
import { compliant, reachable } from '../fleet/service';
import { latestPublished } from '../policies/service';

// Simulated device agent + control-plane loop. Everything it does goes through the real services.
export const hist = { compliance: [], latency: [], active: [] };
let timer = null, busy = false;
const push = (k, v) => { hist[k].push(v); if (hist[k].length > 30) hist[k].shift(); };

async function tick() {
  if (busy) return; busy = true;
  try {
    const now = Date.now();
    const [devs, pols, rels, exams] = await Promise.all(['devices', 'policies', 'releases', 'exams'].map(all));
    const dirty = new Map();
    const touch = (d, patch) => dirty.set(d.id, { ...(dirty.get(d.id) || d), ...patch });
    for (const d of devs) {
      if (d.status !== 'enrolled') continue;
      if (now >= d.silentUntil) {
        touch(d, { lastSeen: now });
        const pol = latestPublished(pols, d.tenantId);
        if (pol && d.policyId !== pol.id && Math.random() < 0.3) touch(d, { policyId: pol.id }); // staged policy rollout
        if (Math.random() < 0.0003) touch(d, { silentUntil: now + 50000 + Math.random() * 70000 });
      } else if (!reachable(d, now) && !d.isolated) {
        touch(d, { isolated: true }); // policy action: isolate on heartbeat loss
        await raise({ tenantId: d.tenantId, key: `hb:${d.id}`, title: `Heartbeat timeout · ${d.hostname}`, severity: 'high', source: 'fleet-agent', deviceId: d.id });
      }
    }
    await putMany('devices', [...dirty.values()]);
    const pool = devs.filter((d) => d.status === 'enrolled' && !d.isolated && now >= d.silentUntil && (d.trust === 'unknown' || now - d.lastAttested > 90000));
    for (let i = 0; i < Math.min(4, pool.length); i++) await attest(SYSTEM, pool[Math.floor(Math.random() * pool.length)].id).catch(() => {});
    const fresh = await all('devices'); const live = fresh.filter((d) => d.status === 'enrolled');
    push('compliance', live.length ? (live.filter((d) => compliant(d, pols, rels, now)).length / live.length) * 100 : 100);
    push('latency', p95()); push('active', exams.filter((e) => e.status === 'live').length);
  } finally { busy = false; }
}
export const startEngine = () => { if (!timer) { tick(); timer = setInterval(tick, 5000); } };
export const stopEngine = () => { clearInterval(timer); timer = null; };
