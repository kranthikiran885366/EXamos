const G = ['attested', 'active', 'verified', 'compliant', 'published', 'live', 'signed', 'healthy', 'ready', 'enforced', 'closed', 'complete', 'resolved', 'stable', 'allow'];
const A = ['review', 'pending', 'draft', 'investigating', 'canary', 'warning', 'stale', 'scheduled', 'partial'];
const R = ['unreachable', 'isolated', 'critical', 'revoked', 'failed', 'suspended', 'offline', 'deny', 'blocked', 'high'];
export const tone = (v) => { const s = String(v).toLowerCase(); return G.includes(s) ? 'g' : A.includes(s) ? 'a' : R.includes(s) ? 'r' : 'n'; };
export default function Badge({ children }) {
  return <span className={'badge ' + tone(children)}><i />{children}</span>;
}
