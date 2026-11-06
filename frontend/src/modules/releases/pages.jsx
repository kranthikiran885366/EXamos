import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useLoad, usePerm } from '../../core/ui/hooks';
import {
  Page, Card, Stat, StatGrid, Badge, DataTable, Empty, Icon, Alert, KeyValue, Flash, useFlash,
  Tabs, Modal, Field, Input, Select, Textarea, ActionDialog, Loading,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import {
  STEPS, EVIDENCE_KINDS, createRelease, verifyRelease, approveRelease,
  revokeRelease, recoverDevices, addReleaseEvidence, verifyReleaseEvidence,
  rollbackRelease, rollout, rolloutStats, releaseReadiness, releaseStats, listReleases, listReleaseEvidence, listReleaseDevices,
  listReleaseDeployments,
} from './service';

export function ReleasesPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const [releases, setReleases] = useState([]);
  const [loadError, setLoadError] = useState('');
  const refresh = async () => {
    try { setLoadError(''); setReleases(await listReleases()); }
    catch (error) { setReleases([]); setLoadError(error.message || 'Unable to load OS releases.'); }
  };
  useEffect(() => { refresh(); const timer = setInterval(refresh, 30000); return () => clearInterval(timer); }, []);
  const { msg, run, busy, setMsg } = useFlash();
  const can = usePerm();
  const [create, setCreate] = useState(false);
  const [action, setAction] = useState(null);
  const [f, setF] = useState({ version: '', components: '' });
  const stats = releaseStats(releases);
  return <Page title="Releases" desc="Backend-persisted release drafts, evidence, and verified lifecycle state."
    actions={can('release.manage') ? <><button className="btn" onClick={() => run(() => recoverDevices(user))}>Recover devices</button><button className="btn primary" onClick={() => setCreate(true)}><Icon name="plus" size={15} /> New release</button></> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    {loadError && <Alert tone="danger">{loadError}</Alert>}
    <StatGrid cols={5}>
      <Stat label="Releases" value={stats.total} icon="package" />
      <Stat label="Candidates" value={stats.candidates} tone="amber" icon="clock" />
      <Stat label="Rolling" value={stats.rolling} tone="violet" icon="upload" />
      <Stat label="Stable" value={stats.stable} tone="green" icon="check" />
      <Stat label="Critical CVEs" value={stats.criticalCves ?? 'Not scanned'} tone={stats.criticalCves ? 'red' : 'amber'} icon="bug" />
    </StatGrid>
    <DataTable rows={[...releases].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))} search={['version']} title="Release register"
      filters={[{ key: 'status', label: 'Status', options: ['draft', 'candidate', 'unverified', 'approved', 'rolling', 'paused', 'stable', 'revoked', 'superseded'] }]}
      columns={[
        { key: 'version', label: 'Version', sortable: true, render: (r) => <><Link to={`/releases/${r.id}`}><b>{r.version}</b></Link><br /><small className="muted">sha256 {r.digest?.slice(0, 10)}…</small></> },
        { key: 'status', label: 'Status', render: (r) => <Badge value={r.status} /> },
        { key: 'rollout', label: 'Configured target (not progress)', render: (r) => `${r.rollout || 0}%` },
        { key: 'findings', label: 'Manifest scan', render: (r) => r.findings ? <>{r.findings.length} findings<br /><small className="muted">{r.criticalCves ?? '—'} critical</small></> : 'Not scanned' },
        { key: 'evidence', label: 'Evidence', render: (r) => r.evidenceCount ?? '—' },
        { key: 'createdAt', label: 'Created', render: (r) => ago(r.createdAt) },
        { key: 'approvedBy', label: 'Approved by', render: (r) => r.approvedBy || '—' },
      ]}
      actions={(r) => [
        { label: 'Open', onClick: () => nav(`/releases/${r.id}`) },
        { label: 'Verify signature', onClick: () => run(async () => (await verifyRelease(r)) ? `${r.version} has a backend-verified signature.` : Promise.reject(new Error('The backend has not verified a trusted signature for this release.'))) },
        ...(r.status === 'candidate' && can('release.approve') ? [{ label: 'Approve', onClick: () => setAction({ kind: 'approve', r }) }] : []),
        ...(['approved', 'rolling', 'stable', 'paused'].includes(r.status) && can('release.rollout') ? [{ label: 'Roll out', onClick: () => setAction({ kind: 'rollout', r }) }] : []),
        ...(r.status !== 'revoked' && can('release.manage') ? [{ label: 'Revoke', danger: true, onClick: () => setAction({ kind: 'revoke', r }) }] : []),
      ]} />
    {create && <Modal title="Create release draft" desc="The backend stores the manifest and computes its digest. Signing, vulnerability scanning, and rollout dispatch are not available here." wide onClose={() => setCreate(false)} footer={<><button className="btn" onClick={() => setCreate(false)}>Cancel</button><button className="btn primary" form="release-form" disabled={busy}>Create draft</button></>}>
      <form id="release-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { const m = await createRelease(user, f); setCreate(false); setF({ version: '', components: '' }); await refresh(); return m; }); }}>
        <Field label="Version" required help="Semantic version, e.g. 2.19.0 or 2.19.0-rc1"><Input value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} maxLength={30} /></Field>
        <Field label="Manifest component list" required help="One package per line as name@version; this is not a complete SBOM." className="span2"><Textarea rows={9} value={f.components} onChange={(e) => setF({ ...f, components: e.target.value })} className="mono" maxLength={12000} /></Field>
      </form>
    </Modal>}
    {action?.kind === 'approve' && <ActionDialog title={`Request approval for ${action.r.version}`} desc="This submits a review request only. It does not approve or publish the release." confirmLabel="Submit request" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await approveRelease(user, action.r, reason); await refresh(); setAction(null); })} />}
    {action?.kind === 'revoke' && <ActionDialog title={`Revoke ${action.r.version}`} desc="Devices on this release will fail attestation until they are recovered or moved." danger confirmLabel="Revoke release" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await revokeRelease(user, action.r, reason); await refresh(); setAction(null); })} />}
    {action?.kind === 'rollout' && <ActionDialog title={`Create deployment plan for ${action.r.version}`} desc="This records a deployment group only; it does not assign devices, dispatch an update, or report progress." field={{ label: 'Configured target stage', options: STEPS.map((n) => ({ v: n, l: `${n}% target` })) }} requireReason={false} confirmLabel="Create plan" onClose={() => setAction(null)} onConfirm={(why, step) => run(async () => { await rollout(user, action.r, Number(step)); await refresh(); setAction(null); })} />}
  </Page>;
}

export function ReleaseDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [releases, setReleases] = useState([]);
  const [loadError, setLoadError] = useState('');
  useEffect(() => { listReleases().then(setReleases).catch((error) => setLoadError(error.message || 'Unable to load the release.')); }, []);
  const [devices, setDevices] = useState([]);
  useEffect(() => { listReleaseDevices().then(setDevices).catch((error) => setLoadError(error.message || 'Unable to load release devices.')); }, []);
  const [evidence, setEvidence] = useState([]);
  useEffect(() => { if (id) listReleaseEvidence(id).then(setEvidence).catch((error) => setLoadError(error.message || 'Unable to load release evidence.')); }, [id]);
  const { msg, run, setMsg } = useFlash();
  const can = usePerm();
  const [tab, setTab] = useState('overview');
  const [action, setAction] = useState(null);
  const [addEv, setAddEv] = useState(false);
  const [f, setF] = useState({ title: '', kind: 'test-report', classification: 'internal', content: '', link: '' });
  const r = releases.find((x) => x.id === id);
  const readiness = useLoad(() => (r ? releaseReadiness(r, { devices, evidence }) : Promise.resolve([])), [r?.id, devices.length, evidence.length]);
  const ev = evidence.filter((e) => e.releaseId === id);
  const cov = r ? rolloutStats(r, devices) : null;
  const onRelease = devices.filter((d) => d.releaseId === id);
  if (!r) return <Page title="Release">{loadError ? <Alert tone="danger">{loadError}</Alert> : <Empty icon="package" title="Release not found" action={<Link className="btn" to="/admin/releases">Back to releases</Link>} />}</Page>;
  const checks = readiness.data || [];
  return <Page title={`Release ${r.version}`} desc={`${r.status} · configured target ${r.rollout || 0}% · ${r.manifestVerified ? 'signature verified' : 'signature unverified'}`}
    breadcrumb={<div className="crumbs-inline"><Link to="/admin/releases">Releases</Link><Icon name="arrow" size={12} /><span>{r.version}</span></div>}
    actions={<><Badge value={r.status} />{can('release.rollout') && ['approved', 'rolling', 'stable', 'paused'].includes(r.status) && <button className="btn primary" onClick={() => setAction({ kind: 'rollout' })}>Roll out</button>}</>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    {loadError && <Alert tone="danger">{loadError}</Alert>}
    {r.status === 'revoked' && <Alert tone="danger" title="Release revoked">{r.revokedReason}</Alert>}
    {r.criticalCves > 0 && <Alert tone="danger" title={`${r.criticalCves} critical CVE(s)`}>Approval is blocked until the vulnerable components are replaced.</Alert>}
    <StatGrid cols={5}>
      <Stat label="Configured target" value={`${r.rollout || 0}%`} icon="upload" sub="Not a device completion percentage" />
      <Stat label="Devices reporting release" value={`${cov.onRelease} / ${cov.total}`} icon="device" />
      <Stat label="Attested on release" value={cov.attested} tone={cov.attested === cov.onRelease ? 'green' : 'amber'} icon="shield" />
      <Stat label="Pending attestation" value={cov.pendingAttestation} tone="amber" icon="clock" />
      <Stat label="Evidence" value={ev.length} icon="lock" sub={`${ev.filter((e) => e.verification === 'integrity-mismatch').length} digest mismatch`} />
    </StatGrid>
    <Tabs tabs={[{ key: 'overview', label: 'Overview' }, { key: 'readiness', label: 'Readiness', count: checks.filter((c) => c.status === 'PASS').length }, { key: 'evidence', label: 'Evidence', count: ev.length }, { key: 'devices', label: 'Devices', count: onRelease.length }]} value={tab} onChange={setTab} />
    {tab === 'overview' && <div className="two">
      <Card title="Release"><KeyValue items={[['Version', r.version], ['Backend status', r.backendStatus], ['Manifest digest', <span className="mono">{r.digest || '—'}</span>], ['Trusted signature verified', r.manifestVerified ? 'Yes' : 'No'], ['Created', fmt(r.createdAt)], ['Created by', r.createdBy], ['Approved by', r.approvedBy || '—'], ['Approved at', fmt(r.approvedAt)], ['Configured target', `${r.rollout || 0}%`]]} />
        <div className="row wrap mt">
          <button className="btn" onClick={() => run(async () => (await verifyRelease(r)) ? 'Backend signature verification confirmed.' : Promise.reject(new Error('No trusted backend signature verification is available for this release.')))}>Verify signature</button>
          {r.status === 'candidate' && can('release.approve') && <button className="btn primary" onClick={() => setAction({ kind: 'approve' })}>Approve</button>}
          {['rolling', 'paused', 'stable', 'approved'].includes(r.status) && can('release.rollout') && <button className="btn danger" onClick={() => setAction({ kind: 'rollback' })}>Roll back</button>}
          {r.status !== 'revoked' && can('release.manage') && <button className="btn danger" onClick={() => setAction({ kind: 'revoke' })}>Revoke</button>}
        </div>
      </Card>
      <Card title="Manifest" desc="Backend-persisted component list; it is not signed or vulnerability-scanned.">
        <DataTable rows={r.manifest?.components || []} pageSize={8} dense columns={[{ key: 'name', label: 'Component' }, { key: 'version', label: 'Version', mono: true }]} />
      </Card>
    </div>}
    {tab === 'readiness' && <Card title="Release readiness" desc="Approval and rollout gates.">{readiness.loading ? <Loading /> : <div className="stack">{checks.map((c) => <div key={c.key} className="checkrow"><Badge value={c.status} /><b>{c.label}</b><span className="muted">{c.detail}</span></div>)}</div>}</Card>}
    {tab === 'evidence' && <>
      <div className="row wrap"><span className="grow" />{can('release.manage') && <button className="btn primary" onClick={() => setAddEv(true)}>Submit evidence</button>}</div>
      <DataTable rows={ev} search={['title', 'kind']} title="Submitted evidence"
        columns={[{ key: 'title', label: 'Evidence', render: (e) => <><b>{e.title}</b><br /><small className="muted">{e.kind} · {e.classification}</small></> }, { key: 'status', label: 'Backend status', render: (e) => <Badge value={e.status} /> }, { key: 'verification', label: 'Digest', render: (e) => <Badge value={e.verification} /> }, { key: 'createdAt', label: 'Submitted', render: (e) => fmt(e.createdAt) }, { key: 'hash', label: 'SHA-256', render: (e) => <span className="mono muted">{e.hash || '—'}</span> }]}
        actions={(e) => [{ label: 'Check digest', onClick: () => run(async () => { const x = await verifyReleaseEvidence(e); return x.ok ? 'Backend evidence digest matches the stored submitted record.' : Promise.reject(new Error('Evidence digest does not match or is not independently verifiable.')); }) }]} />
    </>}
    {tab === 'devices' && <DataTable rows={onRelease} search={['hostname']} title="Devices on this release"
      columns={[{ key: 'hostname', label: 'Device', render: (d) => <Link to={`/devices/${d.id}`}>{d.hostname}</Link> }, { key: 'trust', label: 'Trust', render: (d) => <Badge value={d.trust} /> }, { key: 'status', label: 'Status', badge: true }, { key: 'lastAttested', label: 'Last attested', render: (d) => d.lastAttested ? ago(d.lastAttested) : 'never' }]} />}
    {action?.kind === 'rollout' && <ActionDialog title={`Create deployment plan for ${r.version}`} desc="This records a deployment group only. It does not assign devices, dispatch an update, or report rollout progress." field={{ label: 'Configured target stage', options: STEPS.filter((n) => n > (r.rollout || 0)).map((n) => ({ v: n, l: `${n}% target` })) }} requireReason={false} confirmLabel="Create plan" onClose={() => setAction(null)} onConfirm={(why, step) => run(async () => { await rollout(user, r, Number(step)); setAction(null); })} />}
    {action?.kind === 'approve' && <ActionDialog title={`Request approval for ${r.version}`} desc="This submits a review request only; it does not approve or publish the release." confirmLabel="Submit request" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await approveRelease(user, r, reason); setAction(null); })} />}
    {action?.kind === 'revoke' && <ActionDialog title={`Revoke ${r.version}`} danger confirmLabel="Revoke" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await revokeRelease(user, r, reason); setAction(null); })} />}
    {action?.kind === 'rollback' && <ActionDialog title={`Request recovery from ${r.version}`} desc="This submits device recovery requests; it does not confirm that devices have rolled back. Each device must acknowledge and re-attest." danger confirmLabel="Submit recovery requests" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await rollbackRelease(user, r, reason); setAction(null); })} />}
    {addEv && <Modal title={`Submit evidence · ${r.version}`} wide onClose={() => setAddEv(false)} footer={<><button className="btn" onClick={() => setAddEv(false)}>Cancel</button><button className="btn primary" form="rev-evidence">Submit evidence</button></>}>
      <form id="rev-evidence" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await addReleaseEvidence(user, { releaseId: r.id, ...f }); setEvidence(await listReleaseEvidence(r.id)); setAddEv(false); }); }}>
        <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} maxLength={120} /></Field>
        <Field label="Type"><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })} options={EVIDENCE_KINDS} placeholder={false} /></Field>
        <Field label="Classification"><Select value={f.classification} onChange={(e) => setF({ ...f, classification: e.target.value })} options={['internal', 'confidential', 'restricted', 'auditor-only']} placeholder={false} /></Field>
        <Field label="Link"><Input value={f.link} onChange={(e) => setF({ ...f, link: e.target.value })} maxLength={300} /></Field>
        <Field label="Content" className="span2"><Textarea rows={7} value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} maxLength={4000} help="A submitted record is not an automated validation result." /></Field>
      </form>
    </Modal>}
  </Page>;
}

export function RolloutsPage() {
  const [deployments, setDeployments] = useState([]);
  const [loadError, setLoadError] = useState('');
  useEffect(() => {
    let active = true;
    listReleaseDeployments()
      .then((items) => { if (active) setDeployments(items); })
      .catch((error) => { if (active) setLoadError(error.message || 'Unable to load deployment groups.'); });
    return () => { active = false; };
  }, []);
  const assigned = deployments.reduce((total, d) => total + Number(d.devices_assigned || 0), 0);
  const completed = deployments.reduce((total, d) => total + Number(d.devices_completed || 0), 0);
  const failed = deployments.reduce((total, d) => total + Number(d.devices_failed || 0), 0);
  return <Page title="Release rollouts" desc="Backend-persisted deployment groups and their reported device assignments.">
    {loadError && <Alert tone="danger">{loadError}</Alert>}
    <Alert tone="warn" title="Deployment records are not device rollouts">
      The backend stores deployment groups, but does not assign devices or dispatch updates. Counts below are persisted group assignments only.
    </Alert>
    <StatGrid cols={4}>
      <Stat label="Deployment groups" value={deployments.length} icon="upload" />
      <Stat label="Assigned devices" value={assigned} icon="device" />
      <Stat label="Device completions" value={completed} tone="green" icon="check" />
      <Stat label="Device failures" value={failed} tone={failed ? 'red' : 'green'} icon="warn" />
    </StatGrid>
    {deployments.map((deployment) => <Card key={deployment.id} title={`${deployment.group_name} · ${deployment.status}`}
      desc={`${deployment.target_version} · ${deployment.rollout_stage} · ${deployment.institution_id}`}>
      <div className="covgrid">
        <span><b>{deployment.devices_assigned || 0}</b><small>assigned</small></span>
        <span><b>{deployment.devices_completed || 0}</b><small>completed</small></span>
        <span><b>{deployment.devices_failed || 0}</b><small>failed</small></span>
        <span><b>{deployment.dispatched ? 'Yes' : 'No'}</b><small>dispatched</small></span>
      </div>
    </Card>)}
    {!deployments.length && !loadError && <Empty icon="upload" title="No deployment groups" action={<Link className="btn" to="/admin/releases">Open releases</Link>} />}
  </Page>;
}

export function ReleaseValidationPage() {
  const { user } = useAuth();
  const [releases, setReleases] = useState([]);
  const [loadError, setLoadError] = useState('');
  useEffect(() => {
    let active = true;
    listReleases().then((items) => { if (active) setReleases(items); })
      .catch((error) => { if (active) setLoadError(error.message || 'Unable to load OS releases.'); });
    return () => { active = false; };
  }, []);
  const [evidence, setEvidence] = useState([]);
  const { msg, run, setMsg } = useFlash();
  const can = usePerm();
  const [addEv, setAddEv] = useState(false);
  const [f, setF] = useState({ releaseId: '', title: '', kind: 'test-report', classification: 'internal', content: '', link: '' });
  useEffect(() => {
    let active = true;
    Promise.all(releases.map((release) => listReleaseEvidence(release.id)))
      .then((groups) => { if (active) setEvidence(groups.flat()); })
      .catch((error) => { if (active) setLoadError(error.message || 'Unable to load release evidence.'); });
    return () => { active = false; };
  }, [releases]);
  const rows = [...evidence].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  const tampered = rows.filter((e) => e.verification === 'integrity-mismatch').length;
  const covered = new Set(rows.map((e) => e.releaseId)).size;
  return <Page title="Validation & evidence" desc="Backend-persisted evidence submissions and their content digests."
    actions={can('release.manage') ? <button className="btn primary" onClick={() => setAddEv(true)}><Icon name="plus" size={15} /> Submit evidence</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    {loadError && <Alert tone="danger">{loadError}</Alert>}
    <Alert tone="warn">Evidence submitted here is stored and digest-checked, but it does not count as a successful automated validation.</Alert>
    <StatGrid cols={4}>
      <Stat label="Evidence records" value={rows.length} icon="lock" />
      <Stat label="Releases covered" value={covered} icon="package" sub={`${releases.length} total`} />
      <Stat label="Digest mismatches" value={tampered} tone={tampered ? 'red' : 'green'} icon="warn" />
      <Stat label="Critical CVEs" value={!releases.length || releases.some((r) => r.criticalCves === null) ? 'Not scanned' : releases.reduce((n, r) => n + r.criticalCves, 0)} tone="amber" icon="bug" />
    </StatGrid>
    <Card title="Release coverage">
      <div className="coverage-list">{releases.map((r) => { const n = rows.filter((e) => e.releaseId === r.id).length; return <Link key={r.id} to={`/releases/${r.id}`} className="covrow"><Badge value={r.status} /><b>{r.version}</b><span className="grow" /><small className="muted">{n} evidence record(s)</small></Link>; })}</div>
    </Card>
    <DataTable rows={rows} search={['title', 'kind', 'version']} title="Validation evidence"
      filters={[{ key: 'kind', label: 'Type', options: EVIDENCE_KINDS }, { key: 'verification', label: 'Digest', options: ['digest-matched', 'integrity-mismatch', 'unverified'] }]}
      columns={[
        { key: 'title', label: 'Evidence', render: (e) => <><b>{e.title}</b><br /><small className="muted">{e.kind} · {e.classification}</small></> },
        { key: 'version', label: 'Release', render: (e) => <Link to={`/releases/${e.releaseId}`}>{e.version}</Link> },
        { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
        { key: 'verification', label: 'Digest', render: (e) => <Badge value={e.verification} /> },
        { key: 'createdAt', label: 'Submitted', render: (e) => fmt(e.createdAt) },
        { key: 'hash', label: 'SHA-256', render: (e) => <span className="mono muted">{e.hash || '—'}</span> },
      ]}
      actions={(e) => [{ label: 'Check digest', onClick: () => run(async () => { const x = await verifyReleaseEvidence(e); return x.ok ? 'Backend evidence digest matches the stored submitted record.' : Promise.reject(new Error('Evidence digest does not match or is not independently verifiable.')); }) }]} />
    {addEv && <Modal title="Submit validation evidence" wide onClose={() => setAddEv(false)} footer={<><button className="btn" onClick={() => setAddEv(false)}>Cancel</button><button className="btn primary" form="val-form">Submit evidence</button></>}>
      <form id="val-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await addReleaseEvidence(user, f); setEvidence((await Promise.all(releases.map((release) => listReleaseEvidence(release.id)))).flat()); setAddEv(false); }); }}>
        <Field label="Release" required><Select value={f.releaseId} onChange={(e) => setF({ ...f, releaseId: e.target.value })} options={releases.map((r) => ({ v: r.id, l: `${r.version} · ${r.status}` }))} /></Field>
        <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} maxLength={120} /></Field>
        <Field label="Type"><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })} options={EVIDENCE_KINDS} placeholder={false} /></Field>
        <Field label="Classification"><Select value={f.classification} onChange={(e) => setF({ ...f, classification: e.target.value })} options={['internal', 'confidential', 'restricted', 'auditor-only']} placeholder={false} /></Field>
        <Field label="Content" className="span2"><Textarea rows={7} value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} maxLength={4000} help="A submitted record is not an automated validation result." /></Field>
      </form>
    </Modal>}
  </Page>;
}

export default ReleasesPage;
