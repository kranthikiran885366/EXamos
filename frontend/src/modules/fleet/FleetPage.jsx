import { useState } from 'react';
import Crud from '../../core/ui/Crud';
import Badge from '../../core/ui/Badge';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { useTick } from '../../core/ui/useTick';
import { ago } from '../../core/ui/format';
import { setDeviceStatus, requestReauth, releaseIsolation, simulateOutage, reachable, compliant } from './service';
import { attest } from '../tpm/service';

export default function FleetPage() {
  const { user } = useAuth(); useTick(2000);
  const devices = useCol('devices'), rels = useCol('releases', false), pols = useCol('policies');
  const [only, setOnly] = useState(false);
  const rows = devices.filter((d) => !only || !compliant(d, pols, rels)).sort((a, b) => Number(compliant(a, pols, rels)) - Number(compliant(b, pols, rels)) || a.hostname.localeCompare(b.hostname));
  return (
    <Crud title="Fleet" desc="Device inventory, trust status, and governance actions." rows={rows} search={(d) => `${d.hostname} ${d.status} ${d.trust}`}
      toolbar={<label className="chk inline"><input type="checkbox" checked={only} onChange={(e) => setOnly(e.target.checked)} /> Exceptions only</label>}
      columns={[{ label: 'Device', render: (d) => <span className="mono">{d.hostname}</span> }, { label: 'Release', render: (d) => rels.find((r) => r.id === d.releaseId)?.version || '—' },
        { label: 'TPM trust', render: (d) => <Badge>{!reachable(d) && d.status === 'enrolled' ? 'Unreachable' : d.backendTrustOutcome === 'ALLOW' ? 'Verified' : 'Unverified'}</Badge> },
        { label: 'Policy', render: (d) => { const p = pols.find((x) => x.id === d.policyId); return p ? `v${p.version}${p.status === 'published' ? '' : ' (stale)'}` : '—'; } },
        { label: 'Heartbeat', render: (d) => <span className={reachable(d) ? '' : 'redt'}>{ago(d.lastSeen)}</span> }, { label: 'State', render: (d) => <Badge>{d.isolated ? 'Isolated' : d.status === 'enrolled' ? (compliant(d, pols, rels) ? 'Compliant' : 'Review') : d.status}</Badge> }]}
      actions={[{ label: 'Attest', perm: 'tpm.run', show: (d) => d.status === 'enrolled', run: (d) => attest(user, d.id) },
        { label: 'Release isolation', perm: 'device.manage', show: (d) => d.isolated, run: (d) => releaseIsolation(user, d) },
        { label: 'Outage 70s', perm: 'device.manage', show: (d) => d.status === 'enrolled' && !d.isolated, run: (d) => simulateOutage(user, d) },
        { label: 'Suspend', perm: 'device.manage', reason: true, show: (d) => d.status === 'enrolled', run: (d, r) => setDeviceStatus(user, d, 'suspended', r) },
        { label: 'Revoke', perm: 'device.manage', danger: true, reason: true, stepUp: true, show: (d) => d.status !== 'revoked', run: (d, r) => setDeviceStatus(user, d, 'revoked', r) },
        { label: 'Approve enrollment', perm: 'device.manage', reason: true, show: (d) => d.status === 'pending_approval', run: (d, r) => setDeviceStatus(user, d, 'enrolled', r) },
        { label: 'Request reauthorization', perm: 'device.manage', reason: true, stepUp: true, show: (d) => d.status === 'revoked', run: (d, r) => requestReauth(user, d, r) }]} />
  );
}
