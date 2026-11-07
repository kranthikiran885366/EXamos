import { all, p95 } from '../../core/db/db';
import { compliant } from '../fleet/service';

export const hist = { compliance: [], latency: [], active: [] };
let timer = null, busy = false;
const push = (k, v) => { hist[k].push(v); if (hist[k].length > 30) hist[k].shift(); };

async function tick() {
  if (busy) return; busy = true;
  try {
    const now = Date.now();
    const [devs, pols, rels, exams] = await Promise.all(['devices', 'policies', 'releases', 'exams'].map(all));
    const enrolled = devs.filter((d) => d.status === 'enrolled');
    push('compliance', enrolled.length
      ? (enrolled.filter((d) => compliant(d, pols, rels, now)).length / enrolled.length) * 100
      : 0);
    push('latency', p95()); push('active', exams.filter((e) => e.status === 'live').length);
  } finally { busy = false; }
}
export const startEngine = () => { if (!timer) { tick(); timer = setInterval(tick, 5000); } };
export const stopEngine = () => { clearInterval(timer); timer = null; };
