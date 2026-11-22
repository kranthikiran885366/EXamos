import { displayValue, formatStatus } from './normalizers';

const G = ['attested', 'active', 'verified', 'compliant', 'published', 'live', 'signed', 'healthy', 'ready', 'enforced', 'closed', 'complete', 'resolved', 'stable', 'allow', 'pass', 'observed'];
const A = ['review', 'pending', 'pending_approval', 'draft', 'investigating', 'canary', 'warning', 'stale', 'scheduled', 'partial', 'warn', 'unverified', 'configured'];
const R = ['unreachable', 'isolated', 'critical', 'revoked', 'failed', 'suspended', 'offline', 'deny', 'blocked', 'high', 'fail', 'danger', 'cancelled', 'not enrolled'];

export const tone = (v) => {
  const s = String(v ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return G.includes(s) ? 'g' : A.includes(s) ? 'a' : R.includes(s) ? 'r' : 'n';
};

export default function Badge({ children, value, tone: explicitTone, className = '', dot = true }) {
  const v = value ?? children;
  const label = typeof v === 'string' ? formatStatus(displayValue(v, '—'), '—') : (v ?? '—');
  const t = explicitTone || tone(v);
  return <span className={'badge ' + t + (className ? ' ' + className : '')}>{dot && <i />}{label}</span>;
}
