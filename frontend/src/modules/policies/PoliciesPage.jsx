import { useEffect, useState } from 'react';
import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { fmt } from '../../core/ui/format';
import Badge from '../../core/ui/Badge';
import { useRun, Flash } from '../../core/ui/Crud';
import { createPolicy, publishPolicy, discardDraft, verifyPolicy, requestRollback, decideApproval, ACTIONS } from './service';

export default function PoliciesPage() {
  const { user } = useAuth(); const { tenantId } = useTenant();
  const pols = useCol('policies').filter((p) => p.status !== 'discarded'), approvals = useCol('approvals'); const [ver, setVer] = useState({}); const [msg, run, setMsg] = useRun();
  useEffect(() => { (async () => { const m = {}; for (const p of pols) m[p.id] = p.status === 'draft' ? null : await verifyPolicy(p); setVer(m); })(); }, [pols.length, pols.map((p) => p.status).join()]);
  const pend = approvals.filter((a) => a.status === 'pending');
  const top = (
    <div className="card pad2"><b>Approval queue ({pend.length})</b><p className="muted sm">Rollbacks need a second person. The requester cannot approve their own request.</p><Flash msg={msg} onClose={() => setMsg(null)} />
      {pend.map((a) => <div className="row" key={a.id}><span className="grow">{a.label} · requested by <b>{a.requestedBy}</b> · “{a.reason}”</span>
        <button className="mini" disabled={!can(user.role, 'policy.rollback')} onClick={() => run(() => decideApproval(user, a, true))}>Approve</button><button className="mini danger" onClick={() => run(() => decideApproval(user, a, false))}>Reject</button></div>)}
      {!pend.length && <p className="muted sm">Nothing waiting.</p>}</div>);
  return (
    <Crud title="Policies" desc="Versioned kiosk policies, signed with ECDSA P-256 on publish. Signatures are re-verified here on every load." rows={[...pols].sort((a, b) => a.name.localeCompare(b.name) || b.version - a.version)} search={(p) => `${p.name} ${p.status}`} top={top}
      columns={[{ label: 'Policy', render: (p) => `${p.name} v${p.version}${p.rolledBackFrom ? ` (rollback of v${p.rolledBackFrom})` : ''}` }, { label: 'TPM', render: (p) => (p.config.requireTpm ? 'required' : 'off') }, { label: 'Lockdown', render: (p) => (p.config.kioskLockdown ? 'on' : 'off') }, { label: 'USB', render: (p) => (p.config.allowUsb ? 'allowed' : 'blocked') },
        { label: 'On violation', render: (p) => p.config.onViolation }, { label: 'Origins', render: (p) => p.config.origins.length }, { label: 'Signature', render: (p) => (p.status === 'draft' ? '—' : ver[p.id] === undefined ? '…' : ver[p.id] ? <Badge>Verified</Badge> : <Badge>Failed</Badge>) },
        { label: 'Published', render: (p) => (p.publishedAt ? `${p.publishedBy} · ${fmt(p.publishedAt)}` : `draft by ${p.createdBy}`) }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New draft', perm: 'policy.edit', fields: [{ name: 'name', label: 'Policy name', default: 'nqt-secure-kiosk', help: 'Same name creates the next version.' }, { name: 'requireTpm', label: 'Require TPM 2.0 attestation', type: 'checkbox', default: true }, { name: 'kioskLockdown', label: 'Enforce kiosk lockdown', type: 'checkbox', default: true }, { name: 'allowUsb', label: 'Allow USB storage', type: 'checkbox' }, { name: 'onViolation', label: 'On violation', type: 'select', options: ACTIONS, default: ACTIONS[0] }, { name: 'origins', label: 'Allowed https origins (space or comma separated)', type: 'textarea', default: 'https://exam.examos.in' }], submit: async (v) => { const p = await createPolicy(user, { tenantId, ...v }); return `Draft ${p.name} v${p.version} saved. Publish it to sign and roll out.`; } }}
      actions={[{ label: 'Publish', perm: 'policy.publish', stepUp: true, reason: true, show: (p) => p.status === 'draft', run: async (p) => { const o = await publishPolicy(user, p.id); return `Published ${o.name} v${o.version}.`; } },
        { label: 'Discard', perm: 'policy.edit', danger: true, show: (p) => p.status === 'draft', run: (p) => discardDraft(user, p) },
        { label: 'Request rollback', perm: 'policy.rollback', stepUp: true, reason: true, show: (p) => p.status === 'superseded', run: (p, r) => requestRollback(user, p, r) }]} />
  );
}
