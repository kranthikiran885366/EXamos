import { useEffect, useState } from 'react';
import Crud, { useRun, Flash } from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { createRelease, approveRelease, rollout, revokeRelease, recoverDevices, verifyRelease, addAdvisory, advisories, STEPS } from './service';

function Advisories() {
  const { user } = useAuth(); const meta = useCol('meta', false); const [list, setList] = useState([]); const [f, setF] = useState({ name: '', below: '', cve: '', sev: 'high' }); const [msg, run, setMsg] = useRun();
  useEffect(() => { advisories().then(setList); }, [meta]);
  return (
    <div className="card pad2"><b>Vulnerability advisories ({list.length})</b><p className="muted sm">New releases are scanned against this list; critical findings block approval.</p>
      <div className="row wrap">{['name', 'below', 'cve'].map((k) => <input key={k} placeholder={k === 'below' ? 'fixed in 3.0.14' : k === 'cve' ? 'CVE-2024-0001' : 'package'} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} />)}
        <select value={f.sev} onChange={(e) => setF({ ...f, sev: e.target.value })}><option>high</option><option>critical</option></select>
        <button className="btn" disabled={!can(user.role, 'release.manage')} onClick={() => run(() => addAdvisory(user, f))}>Add</button></div>
      <Flash msg={msg} onClose={() => setMsg(null)} /><p className="sm muted">{list.map((a) => `${a.name}<${a.below} ${a.cve} (${a.sev})`).join(' · ')}</p></div>
  );
}
export default function ReleasesPage() {
  const { user } = useAuth(); const rels = useCol('releases', false); const [ver, setVer] = useState({}); const [msg, run, setMsg] = useRun();
  useEffect(() => { (async () => { const m = {}; for (const r of rels) m[r.id] = await verifyRelease(r); setVer(m); })(); }, [rels]);
  const latest = [...rels].sort((a, b) => b.createdAt - a.createdAt)[0];
  return (
    <Crud title="Releases" desc="Signed builds with SBOM scanning, two-person approval, staged rollout, anti-downgrade and revocation." rows={[...rels].sort((a, b) => b.createdAt - a.createdAt)} search={(r) => `${r.version} ${r.status}`}
      head={<button className="btn" disabled={!can(user.role, 'release.manage')} onClick={() => run(() => recoverDevices(user))}>Recover devices from revoked</button>}
      top={<><Flash msg={msg} onClose={() => setMsg(null)} /><Advisories /></>}
      columns={[{ label: 'Version', key: 'version' }, { label: 'Digest', render: (r) => <span className="mono">{r.digest.slice(0, 12)}…</span> }, { label: 'Signature', render: (r) => (ver[r.id] === undefined ? '…' : ver[r.id] ? '✓ verified' : '✗ INVALID') },
        { label: 'SBOM', render: (r) => `${r.manifest.components.length} components` }, { label: 'CVEs', render: (r) => <span className={r.criticalCves ? 'redt' : ''} title={r.findings.map((f) => `${f.cve} ${f.component}`).join('\n')}>{r.criticalCves} critical / {r.findings.length}</span> },
        { label: 'Rollout', render: (r) => `${r.rollout}%` }, { label: 'Built / approved', render: (r) => `${r.createdBy} / ${r.approvedBy || '—'}` }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New release', perm: 'release.manage', fields: [{ name: 'version', label: 'Version', placeholder: '2.19.0' }, { name: 'components', label: 'SBOM components (name@version per line)', type: 'textarea', rows: 6, default: latest ? latest.manifest.components.map((c) => `${c.name}@${c.version}`).join('\n') : '' }], submit: (v) => createRelease(user, v) }}
      actions={[{ label: 'Approve', perm: 'release.approve', show: (r) => r.status === 'candidate', run: (r) => approveRelease(user, r) },
        { label: 'Roll out', perm: 'release.manage', show: (r) => ['approved', 'rolling', 'stable'].includes(r.status) && r.rollout < 100, field: { label: 'Percent of fleet', options: STEPS.map((s) => ({ v: s, l: `${s}%` })) }, run: (r, _x, v) => rollout(user, r, v) },
        { label: 'Revoke', perm: 'release.manage', danger: true, reason: true, stepUp: true, show: (r) => r.status !== 'revoked', run: (r, why) => revokeRelease(user, r, why) }]} />
  );
}
