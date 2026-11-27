import { Link } from 'react-router-dom';
import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { fmt } from '../../core/ui/format';
import Badge from '../../core/ui/Badge';
import { createPolicy, requestPolicyPublication, discardDraft, requestRollback, verifyPolicySignature, ACTIONS } from './service';
import { useApprovalRequests } from '../../core/services/useApprovalRequests';
import { Alert } from '../../core/ui/kit';

export default function PoliciesPage() {
  const { user } = useAuth(); const { tenantId } = useTenant();
  const pols = useCol('policies').filter((p) => p.status !== 'discarded');
  const approvalState = useApprovalRequests();
  const pend = approvalState.requests.filter((a) => a.status === 'pending_review' && ['policy-publish', 'policy-rollback'].includes(a.kind));
  const top = (
    <div className="card pad2"><b>Approval queue ({pend.length})</b><p className="muted sm">Two-person governance: once an independent reviewer approves a policy publication or rollback request, the server signs and publishes it.</p>
      {approvalState.error && <Alert tone="danger">{approvalState.error.message || 'Approval requests could not be loaded.'}</Alert>}
      {pend.map((a) => <div className="row" key={a.id}><span className="grow">{a.label} · requested by <b>{a.requesterName || a.requestedBy}</b> · “{a.reason}”</span>
        <Link className="mini" to="/admin/approvals">Review request</Link></div>)}
      {!pend.length && !approvalState.error && <p className="muted sm">Nothing waiting.</p>}</div>);
  return (
    <Crud title="Policies" desc="Server-persisted, cryptographically signed policy versions with two-person approval and rollback." rows={[...pols].sort((a, b) => a.name.localeCompare(b.name) || b.version - a.version)} search={(p) => `${p.name} ${p.status}`} top={top}
      columns={[{ label: 'Policy', render: (p) => `${p.name} v${p.version}${p.rolledBackFrom ? ` (rollback of v${p.rolledBackFrom})` : ''}` }, { label: 'TPM', render: (p) => (p.config.requireTpm ? 'required' : 'off') }, { label: 'Lockdown', render: (p) => (p.config.kioskLockdown ? 'on' : 'off') }, { label: 'USB', render: (p) => (p.config.allowUsb ? 'allowed' : 'blocked') },
        { label: 'On violation', render: (p) => p.config.onViolation }, { label: 'Origins', render: (p) => p.config.origins.length }, { label: 'Signature', render: (p) => (p.status === 'draft' ? '—' : <Badge value={p.signatureStatus === 'verified' ? 'verified' : 'unverified'} />) },
        { label: 'Published', render: (p) => (p.publishedAt ? `${p.publishedBy} · ${fmt(p.publishedAt)}` : `draft by ${p.createdBy}`) }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New draft', perm: 'policy.edit', fields: [{ name: 'name', label: 'Policy name', default: 'nqt-secure-kiosk', help: 'Same name creates the next version.' }, { name: 'requireTpm', label: 'Require TPM 2.0 attestation', type: 'checkbox', default: true }, { name: 'kioskLockdown', label: 'Enforce kiosk lockdown', type: 'checkbox', default: true }, { name: 'allowUsb', label: 'Allow USB storage', type: 'checkbox' }, { name: 'onViolation', label: 'On violation', type: 'select', options: ACTIONS, default: ACTIONS[0] }, { name: 'origins', label: 'Allowed https origins (space or comma separated)', type: 'textarea', default: 'https://exam.examos.in' }], submit: async (v) => { const p = await createPolicy(user, { tenantId, ...v }); return `Draft ${p.name} v${p.version} saved. Request publication for two-person sign-off.`; } }}
      actions={[{ label: 'Request publication', perm: 'policy.publish', stepUp: true, reason: true, show: (p) => p.status === 'draft', run: async (p, reason) => { const r = await requestPolicyPublication(user, p.id, reason); return `Publication approval requested (${r.id}). Once approved, it will be signed and published.`; } },
        { label: 'Verify signature', show: (p) => p.status === 'published' || p.status === 'superseded', run: async (p) => { const res = await verifyPolicySignature(p); return res.ok ? `Verified (${res.algorithm}, digest ${res.digest.slice(0, 12)}…)` : Promise.reject(new Error(res.reason)); } },
        { label: 'Discard', perm: 'policy.edit', danger: true, show: (p) => p.status === 'draft', run: (p) => discardDraft(user, p) },
        { label: 'Request rollback', perm: 'policy.rollback', stepUp: true, reason: true, show: (p) => p.status === 'superseded', run: (p, r) => requestRollback(user, p, r) }]} />
  );
}
