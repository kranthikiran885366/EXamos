import { useEffect, useState } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import ReauthModal from '../../core/ui/ReauthModal';
import { useRun, Flash } from '../../core/ui/Crud';
import { createPolicy, requestPolicyPublication, requestRollback, ACTIONS } from '../policies/service';
import { verifyRelease } from '../releases/service';
import { cmpVer } from '../../core/services/common';
import { useApprovalRequests } from '../../core/services/useApprovalRequests';

const Switch = ({ on, onChange, disabled, label }) => <button role="switch" aria-checked={on} aria-label={label} disabled={disabled} className={'sw' + (on ? ' on' : '')} onClick={() => onChange(!on)}><i /></button>;

export default function PolicyInspector() {
  const { user } = useAuth(); const { tenantId } = useTenant();
  const pols = useCol('policies'), devices = useCol('devices'), rels = useCol('releases', false);
  const approvalState = useApprovalRequests();
  const names = [...new Set(pols.filter((p) => p.status !== 'discarded').map((p) => p.name))];
  const [name, setName] = useState(''); const cur = name || names[0];
  const pub = pols.find((p) => p.name === cur && p.status === 'published');
  const [d, setD] = useState(null); const [modal, setModal] = useState(null); const [target, setTarget] = useState(''); const [msg, run, setMsg] = useRun(); const [sig, setSig] = useState(null);
  useEffect(() => { if (pub) setD({ ...pub.config, origins: pub.config.origins.join('\n') }); }, [pub?.id]);
  const stable = rels.filter((r) => r.status === 'stable').sort((a, b) => cmpVer(b.version, a.version))[0];
  useEffect(() => { if (stable) verifyRelease(stable).then(setSig); }, [stable?.id]);
  if (!pub || !d) return <aside className="inspector"><div className="ihead"><b>Policy inspector</b><small>No published policy for this tenant</small></div></aside>;
  const dirty = ['requireTpm', 'kioskLockdown', 'allowUsb', 'onViolation'].filter((k) => d[k] !== pub.config[k]).length + (d.origins.trim() !== pub.config.origins.join('\n') ? 1 : 0);
  const can_ = can(user.role, 'policy.publish'); const sa = can(user.role, 'policy.weaken');
  const mine = devices.filter((x) => x.status === 'enrolled'); const onNew = mine.filter((x) => x.policyId === pub.id).length;
  const old = pols.filter((p) => p.name === cur && p.status === 'superseded').sort((a, b) => b.version - a.version);
  const pending = approvalState.requests.filter((a) => a.status === 'pending_review' &&
    ['policy-publish', 'policy-rollback'].includes(a.kind) && pols.find((p) => p.id === a.targetId)?.name === cur).length;
  const set = (k) => (v) => setD({ ...d, [k]: v });
  const publish = async (reason) => {
    setModal(null);
    await run(async () => {
      const p = await createPolicy(user, { tenantId, name: cur, ...d });
      const request = await requestPolicyPublication(user, p.id, reason);
      return `Publication approval requested (${request.id}). Policy v${p.version} remains a draft until a verified execution integration is available.`;
    });
  };
  return (
    <aside className="inspector" aria-label="Policy inspector">
      <div className="ihead"><b>Policy inspector</b><small>Kiosk security / Production</small></div>
      <div className="ibody">
        <div className="pname"><select value={cur} onChange={(e) => setName(e.target.value)}>{names.map((n) => <option key={n}>{n}</option>)}</select><span className="draft">v{pub.version}{dirty ? ' · edited' : ''}</span></div>
        <div className="muted sm">{mine.length} devices · {onNew} on v{pub.version} {dirty > 0 && <a className="unsaved">{dirty} unsaved change{dirty > 1 ? 's' : ''}</a>}</div>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <h6>POLICY CONFIGURATION</h6>
        <div className="prow"><div><b>Require TPM 2.0 attestation</b><small>Block devices without a valid trust quote</small></div><Switch label="Require TPM attestation" on={d.requireTpm} onChange={set('requireTpm')} disabled={!can_} /></div>
        <div className="prow"><div><b>Enforce kiosk lockdown</b><small>Restrict apps, clipboard and screen capture</small></div><Switch label="Enforce kiosk lockdown" on={d.kioskLockdown} onChange={set('kioskLockdown')} disabled={!can_} /></div>
        <div className="prow"><div><b>Allow USB storage</b><small>Exception requires supervisor approval</small></div><Switch label="Allow USB storage" on={d.allowUsb} onChange={set('allowUsb')} disabled={!sa} /></div>
        <label className="sel">On policy violation<select value={d.onViolation} onChange={(e) => set('onViolation')(e.target.value)} disabled={!can_}>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</select></label>
        <label className="sel">Allowed origins<textarea rows={2} value={d.origins} onChange={(e) => set('origins')(e.target.value)} disabled={!can_} /></label>
        <div className="warn">A publication request does not change the live policy. Active exams keep policy v{pub.version}.</div>
        {!sa && ((!d.requireTpm && pub.config.requireTpm) || (!d.kioskLockdown && pub.config.kioskLockdown)) && <div className="err">Weakening a security control needs a super admin; publish will be refused.</div>}
        <h6>SBOM &amp; ARTIFACT SIGNER</h6>
        {stable ? <div className="sbom"><div className="split"><code>kiosk-agent:{stable.version}</code><span className={'badge ' + (sig ? 'g' : 'r')}><i />{sig === null ? 'Checking' : sig ? 'Verified' : 'Invalid'}</span></div>
          <small>SBOM · {stable.manifest.components.length} components · {stable.criticalCves} critical CVEs</small>
          <div className="signer"><span className="ok2">✓</span><div><b>release-signer · ECDSA P-256</b><small>Approved by {stable.approvedBy}</small></div></div><small className="mono">SHA256 {stable.digest.slice(0, 8)}…{stable.digest.slice(-8)}</small></div> : <p className="muted sm">No stable release.</p>}
        <h6>ROLLBACK CONTROL</h6>
        {approvalState.error && <div className="err">Approval queue unavailable: {approvalState.error.message || 'backend request failed'}</div>}
        <select className="full" value={target} onChange={(e) => setTarget(e.target.value)}><option value="">Previous version…</option>{old.map((p) => <option key={p.id} value={p.id}>v{p.version} · superseded</option>)}</select>
        <small className="muted">Independent approval is required; approval does not execute the change.{pending > 0 && ` ${pending} request(s) waiting in Policies.`}</small>
        <button className="btn danger full" disabled={!target || !can(user.role, 'policy.rollback')} onClick={() => setModal('rollback')}>↺ Request rollback</button>
      </div>
      <div className="ifoot"><button className="btn" disabled={!dirty} onClick={() => setD({ ...pub.config, origins: pub.config.origins.join('\n') })}>Discard</button><button className="btn primary grow" disabled={!dirty || !can_} onClick={() => setModal('publish')}>→ Review &amp; publish</button></div>
      {modal === 'publish' && <ReauthModal title={`Request publication of ${cur} v${pub.version + 1}`} text={`${dirty} change(s) will be submitted for independent review. This does not sign or roll out the policy.`} confirmLabel="Request approval" onClose={() => setModal(null)} onConfirm={publish} />}
      {modal === 'rollback' && <ReauthModal title="Request rollback" text="A different approver must confirm before anything changes." confirmLabel="Request" onClose={() => setModal(null)} onConfirm={async (r) => { setModal(null); await run(() => requestRollback(user, pols.find((p) => p.id === target), r)); setTarget(''); }} />}
    </aside>
  );
}
