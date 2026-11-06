import { useEffect, useState } from 'react';
import Crud, { useRun, Flash } from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { can } from '../../core/security/rbac';
import { createRelease, approveRelease, rollout, revokeRelease, recoverDevices, STEPS, listReleases } from './service';

export default function ReleasesPage() {
  const { user } = useAuth(); const [rels, setRels] = useState([]); const [msg, run, setMsg] = useRun();
  useEffect(() => { listReleases().then(setRels).catch(() => setRels([])); }, []);
  const latest = [...rels].sort((a, b) => b.createdAt - a.createdAt)[0];
  return (
    <Crud title="Releases" desc="Backend-persisted release drafts. Signing, vulnerability scanning, and device dispatch are not available." rows={[...rels].sort((a, b) => b.createdAt - a.createdAt)} search={(r) => `${r.version} ${r.status}`}
      head={<button className="btn" disabled={!can(user.role, 'release.manage')} onClick={() => run(() => recoverDevices(user))}>Recover devices from revoked</button>}
      top={<Flash msg={msg} onClose={() => setMsg(null)} />}
      columns={[{ label: 'Version', key: 'version' }, { label: 'Digest', render: (r) => <span className="mono">{r.digest ? `${r.digest.slice(0, 12)}…` : 'Backend digest unavailable'}</span> }, { label: 'Backend status', render: (r) => r.backendStatus || r.status },
        { label: 'Manifest components', render: (r) => r.manifest.components?.length ?? 'Unavailable' }, { label: 'CVEs', render: (r) => r.criticalCves === null ? 'Not scanned' : `${r.criticalCves} critical` },
        { label: 'Configured target (not progress)', render: (r) => `${r.rollout}%` }, { label: 'Built / approved', render: (r) => `${r.createdBy || '—'} / ${r.approvedBy || '—'}` }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New release draft', perm: 'release.manage', fields: [{ name: 'version', label: 'Version', placeholder: '2.19.0' }, { name: 'components', label: 'Manifest component list (name@version per line)', type: 'textarea', rows: 6, default: latest ? latest.manifest.components?.map((c) => `${c.name}@${c.version}`).join('\n') : '' }], submit: (v) => createRelease(user, v) }}
      actions={[{ label: 'Request approval', perm: 'release.approve', reason: true, show: (r) => r.status === 'candidate', run: (r, reason) => approveRelease(user, r, reason) },
        { label: 'Roll out', perm: 'release.manage', show: (r) => ['approved', 'rolling', 'stable'].includes(r.status) && r.rollout < 100, field: { label: 'Percent of fleet', options: STEPS.map((s) => ({ v: s, l: `${s}%` })) }, run: (r, _x, v) => rollout(user, r, v) },
        { label: 'Revoke', perm: 'release.manage', danger: true, reason: true, stepUp: true, show: (r) => r.status !== 'revoked', run: (r, why) => revokeRelease(user, r, why) }]} />
  );
}
