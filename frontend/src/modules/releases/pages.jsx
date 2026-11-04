import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { useLoad, usePerm } from '../../core/ui/hooks';
import * as Api from '../../core/api/services';
import {
  Page, Card, Stat, StatGrid, Badge, DataTable, Empty, Icon, Alert, KeyValue, Flash, useFlash,
  Tabs, Modal, Field, Input, Select, Textarea, ActionDialog, Timeline, Progress, Loading, CopyField,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { pct, downloadCsv } from '../../core/services/common';
import {
  STEPS, EVIDENCE_KINDS, createRelease, verifyRelease, approveRelease, requestReleaseApproval,
  revokeRelease, recoverDevices, addReleaseEvidence, verifyReleaseEvidence, pauseRollout, resumeRollout,
  rollbackRelease, rollout, rolloutStats, releaseReadiness, releaseStats, listReleases, listReleaseEvidence,
} from './service';

const statusTone = (s) => (s === 'stable' ? 'green' : s === 'revoked' ? 'red' : s === 'candidate' ? 'amber' : 'violet');

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
  return <Page title="Releases" desc="Signed release candidates, SBOM review, approval and staged rollout."
    actions={can('release.manage') ? <><button className="btn" onClick={() => run(() => recoverDevices(user))}>Recover devices</button><button className="btn primary" onClick={() => setCreate(true)}><Icon name="plus" size={15} /> New release</button></> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    {loadError && <Alert tone="danger">{loadError}</Alert>}
    <StatGrid cols={5}>
      <Stat label="Releases" value={stats.total} icon="package" />
      <Stat label="Candidates" value={stats.candidates} tone="amber" icon="clock" />
      <Stat label="Rolling" value={stats.rolling} tone="violet" icon="upload" />
      <Stat label="Stable" value={stats.stable} tone="green" icon="check" />
      <Stat label="Critical CVEs" value={stats.criticalCves} tone={stats.criticalCves ? 'red' : 'green'} icon="bug" />
    </StatGrid>
    <DataTable rows={[...releases].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))} search={['version']} title="Release register"
      filters={[{ key: 'status', label: 'Status', options: ['candidate', 'approved', 'rolling', 'paused', 'stable', 'revoked', 'superseded'] }]}
      columns={[
        { key: 'version', label: 'Version', sortable: true, render: (r) => <><Link to={`/releases/${r.id}`}><b>{r.version}</b></Link><br /><small className="muted">sha256 {r.digest?.slice(0, 10)}…</small></> },
        { key: 'status', label: 'Status', render: (r) => <Badge value={r.status} /> },
        { key: 'rollout', label: 'Rollout', render: (r) => <div className="miniprog"><Progress value={r.rollout || 0} /><small className="muted">{r.rollout || 0}%</small></div> },
        { key: 'findings', label: 'SBOM', render: (r) => <>{r.findings?.length || 0} findings<br /><small className="muted">{r.criticalCves || 0} critical</small></> },
        { key: 'evidence', label: 'Evidence', render: (r) => r.evidenceCount ?? '—' },
        { key: 'createdAt', label: 'Created', render: (r) => ago(r.createdAt) },
        { key: 'approvedBy', label: 'Approved by', render: (r) => r.approvedBy || '—' },
      ]}
      actions={(r) => [
        { label: 'Open', onClick: () => nav(`/releases/${r.id}`) },
        { label: 'Verify', onClick: () => run(async () => { const result = await Api.getOsReleaseDetails(r.id); return result?.release ? `${r.version} is present in the OS release store.` : Promise.reject(new Error('Release was not found in the OS release store.')); }) },
        ...(r.status === 'candidate' && can('release.manage') ? [{ label: 'Request approval', onClick: () => setAction({ kind: 'request', r }) }] : []),
        ...(r.status === 'candidate' && can('release.approve') ? [{ label: 'Approve', onClick: () => setAction({ kind: 'approve', r }) }] : []),
        ...(['approved', 'rolling', 'stable', 'paused'].includes(r.status) && can('release.rollout') ? [{ label: 'Roll out', onClick: () => setAction({ kind: 'rollout', r }) }] : []),
        ...(r.status !== 'revoked' && can('release.manage') ? [{ label: 'Revoke', danger: true, onClick: () => setAction({ kind: 'revoke', r }) }] : []),
      ]} />
    {create && <Modal title="Create release candidate" desc="The manifest is hashed and signed. SBOM components are scanned against current advisories." wide onClose={() => setCreate(false)} footer={<><button className="btn" onClick={() => setCreate(false)}>Cancel</button><button className="btn primary" form="release-form" disabled={busy}>Sign release</button></>}>
      <form id="release-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { const m = await createRelease(user, f); setCreate(false); return m; }); }}>
        <Field label="Version" required help="Semantic version, e.g. 2.19.0 or 2.19.0-rc1"><Input value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} maxLength={30} /></Field>
        <Field label="SBOM components" required help="One component per line as name@version" className="span2"><Textarea rows={9} value={f.components} onChange={(e) => setF({ ...f, components: e.target.value })} className="mono" /></Field>
      </form>
    </Modal>}
    {action?.kind === 'request' && <ActionDialog title={`Request approval for ${action.r.version}`} desc="A different privileged user must approve the release." confirmLabel="Request approval" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await requestReleaseApproval(user, action.r, reason); await refresh(); setAction(null); })} />}
    {action?.kind === 'approve' && <ActionDialog title={`Approve ${action.r.version}`} desc="The signature, digest and SBOM are re-verified." confirmLabel="Approve release" onClose={() => setAction(null)} onConfirm={() => run(async () => { await approveRelease(user, action.r); await refresh(); setAction(null); })} />}
    {action?.kind === 'revoke' && <ActionDialog title={`Revoke ${action.r.version}`} desc="Devices on this release will fail attestation until they are recovered or moved." danger confirmLabel="Revoke release" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await revokeRelease(user, action.r, reason); await refresh(); setAction(null); })} />}
    {action?.kind === 'rollout' && <ActionDialog title={`Roll out ${action.r.version}`} desc="Devices moved to a new release must re-attest." field={{ label: 'Rollout step', options: STEPS.map((n) => ({ v: n, l: `${n}% of fleet` })) }} requireReason={false} confirmLabel="Start rollout" onClose={() => setAction(null)} onConfirm={(why, step) => run(async () => { await rollout(user, action.r, Number(step)); await refresh(); setAction(null); })} />}
  </Page>;
}

export function ReleaseDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [releases, setReleases] = useState([]);
  useEffect(() => { listReleases().then(setReleases).catch(() => setReleases([])); }, []);
  const devices = useCol('devices');
  const [evidence, setEvidence] = useState([]);
  useEffect(() => { if (id) listReleaseEvidence(id).then(setEvidence).catch(() => setEvidence([])); }, [id]);
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
  if (!r) return <Page title="Release"><Empty icon="package" title="Release not found" action={<Link className="btn" to="/admin/releases">Back to releases</Link>} /></Page>;
  const checks = readiness.data || [];
  return <Page title={`Release ${r.version}`} desc={`${r.status} · ${r.rollout || 0}% rollout · signed ${r.digest?.slice(0, 16)}…`}
    breadcrumb={<div className="crumbs-inline"><Link to="/admin/releases">Releases</Link><Icon name="arrow" size={12} /><span>{r.version}</span></div>}
    actions={<><Badge value={r.status} />{can('release.rollout') && ['approved', 'rolling', 'stable', 'paused'].includes(r.status) && <button className="btn primary" onClick={() => setAction({ kind: 'rollout' })}>Roll out</button>}</>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    {r.status === 'revoked' && <Alert tone="danger" title="Release revoked">{r.revokedReason}</Alert>}
    {r.criticalCves > 0 && <Alert tone="danger" title={`${r.criticalCves} critical CVE(s)`}>Approval is blocked until the vulnerable components are replaced.</Alert>}
    <StatGrid cols={4}>
      <Stat label="Rollout" value={`${r.rollout || 0}%`} icon="upload" sub={`${cov.onRelease} of ${cov.total} devices`} />
      <Stat label="Attested on release" value={cov.attested} tone={cov.attested === cov.onRelease ? 'green' : 'amber'} icon="shield" />
      <Stat label="Pending attestation" value={cov.pendingAttestation} tone="amber" icon="clock" />
      <Stat label="Evidence" value={ev.length} icon="lock" sub={`${ev.filter((e) => e.verification === 'tampered').length} tampered`} />
    </StatGrid>
    <Tabs tabs={[{ key: 'overview', label: 'Overview' }, { key: 'readiness', label: 'Readiness', count: checks.filter((c) => c.status === 'PASS').length }, { key: 'evidence', label: 'Evidence', count: ev.length }, { key: 'devices', label: 'Devices', count: onRelease.length }]} value={tab} onChange={setTab} />
    {tab === 'overview' && <div className="two">
      <Card title="Release"><KeyValue items={[['Version', r.version], ['Status', r.status], ['Digest', <span className="mono">{r.digest?.slice(0, 32)}…</span>], ['Created', fmt(r.createdAt)], ['Created by', r.createdBy], ['Approved by', r.approvedBy || '—'], ['Approved at', fmt(r.approvedAt)], ['Rollout target', `${r.rollout || 0}%`]]} />
        <div className="row wrap mt">
          <button className="btn" onClick={() => run(async () => (await verifyRelease(r)) ? 'Signature verified.' : Promise.reject(new Error('Signature verification failed.')))}>Verify signature</button>
          {r.status === 'candidate' && can('release.manage') && <button className="btn" onClick={() => setAction({ kind: 'request' })}>Request approval</button>}
          {r.status === 'candidate' && can('release.approve') && <button className="btn primary" onClick={() => setAction({ kind: 'approve' })}>Approve</button>}
          {['rolling', 'paused', 'stable', 'approved'].includes(r.status) && can('release.rollout') && <button className="btn danger" onClick={() => setAction({ kind: 'rollback' })}>Roll back</button>}
          {r.status !== 'revoked' && can('release.manage') && <button className="btn danger" onClick={() => setAction({ kind: 'revoke' })}>Revoke</button>}
        </div>
      </Card>
      <Card title="Manifest" desc="Signed SBOM used for rollout and vulnerability scanning.">
        <DataTable rows={r.manifest?.components || []} pageSize={8} dense columns={[{ key: 'name', label: 'Component' }, { key: 'version', label: 'Version', mono: true }]} />
      </Card>
    </div>}
    {tab === 'readiness' && <Card title="Release readiness" desc="Approval and rollout gates.">{readiness.loading ? <Loading /> : <div className="stack">{checks.map((c) => <div key={c.key} className="checkrow"><Badge value={c.status} /><b>{c.label}</b><span className="muted">{c.detail}</span></div>)}</div>}</Card>}
    {tab === 'evidence' && <>
      <div className="row wrap"><span className="grow" />{can('release.manage') && <button className="btn primary" onClick={() => setAddEv(true)}>Add evidence</button>}</div>
      <DataTable rows={ev} search={['title', 'kind']} title="Validation evidence"
        columns={[{ key: 'title', label: 'Evidence', render: (e) => <><b>{e.title}</b><br /><small className="muted">{e.kind} · {e.classification}</small></> }, { key: 'verification', label: 'Integrity', render: (e) => <Badge value={e.verification} /> }, { key: 'createdAt', label: 'Sealed', render: (e) => fmt(e.createdAt) }, { key: 'hash', label: 'SHA-256', render: (e) => <span className="mono muted">{e.hash.slice(0, 12)}…</span> }]}
        actions={(e) => [{ label: 'Verify', onClick: () => run(async () => { const x = await verifyReleaseEvidence(e); return x.ok ? 'Evidence verified.' : Promise.reject(new Error('Evidence was tampered with.')); }) }]} />
    </>}
    {tab === 'devices' && <DataTable rows={onRelease} search={['hostname']} title="Devices on this release"
      columns={[{ key: 'hostname', label: 'Device', render: (d) => <Link to={`/devices/${d.id}`}>{d.hostname}</Link> }, { key: 'trust', label: 'Trust', render: (d) => <Badge value={d.trust} /> }, { key: 'status', label: 'Status', badge: true }, { key: 'lastAttested', label: 'Last attested', render: (d) => d.lastAttested ? ago(d.lastAttested) : 'never' }]} />}
    {action?.kind === 'rollout' && <ActionDialog title={`Roll out ${r.version}`} field={{ label: 'Step', options: STEPS.filter((n) => n > (r.rollout || 0)).map((n) => ({ v: n, l: `${n}% of fleet` })) }} requireReason={false} confirmLabel="Apply" onClose={() => setAction(null)} onConfirm={(why, step) => run(async () => { await rollout(user, r, Number(step)); setAction(null); })} />}
    {action?.kind === 'request' && <ActionDialog title={`Request approval for ${r.version}`} confirmLabel="Request" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await requestReleaseApproval(user, r, reason); setAction(null); })} />}
    {action?.kind === 'approve' && <ActionDialog title={`Approve ${r.version}`} confirmLabel="Approve" onClose={() => setAction(null)} onConfirm={() => run(async () => { await approveRelease(user, r); setAction(null); })} />}
    {action?.kind === 'revoke' && <ActionDialog title={`Revoke ${r.version}`} danger confirmLabel="Revoke" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await revokeRelease(user, r, reason); setAction(null); })} />}
    {action?.kind === 'rollback' && <ActionDialog title={`Roll back ${r.version}`} desc="Devices move to the newest earlier stable release and must re-attest." danger confirmLabel="Roll back" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await rollbackRelease(user, r, reason); setAction(null); })} />}
    {addEv && <Modal title={`Add evidence · ${r.version}`} wide onClose={() => setAddEv(false)} footer={<><button className="btn" onClick={() => setAddEv(false)}>Cancel</button><button className="btn primary" form="rev-evidence">Seal evidence</button></>}>
      <form id="rev-evidence" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await addReleaseEvidence(user, { releaseId: r.id, ...f }); setAddEv(false); }); }}>
        <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} maxLength={120} /></Field>
        <Field label="Type"><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })} options={EVIDENCE_KINDS} placeholder={false} /></Field>
        <Field label="Classification"><Select value={f.classification} onChange={(e) => setF({ ...f, classification: e.target.value })} options={['internal', 'confidential', 'restricted', 'auditor-only']} placeholder={false} /></Field>
        <Field label="Link"><Input value={f.link} onChange={(e) => setF({ ...f, link: e.target.value })} maxLength={300} /></Field>
        <Field label="Content" className="span2"><Textarea rows={7} value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} maxLength={200000} /></Field>
      </form>
    </Modal>}
  </Page>;
}

export function RolloutsPage() {
  const { user } = useAuth();
  const [releases, setReleases] = useState([]);
  useEffect(() => { listReleases().then(setReleases).catch(() => setReleases([])); }, []);
  const devices = useCol('devices');
  const { msg, run, setMsg } = useFlash();
  const can = usePerm();
  const [action, setAction] = useState(null);
  const rows = releases.filter((r) => ['approved', 'rolling', 'paused', 'stable'].includes(r.status)).map((r) => ({ ...r, cov: rolloutStats(r, devices) }));
  return <Page title="Release rollouts" desc="Staged fleet rollout with pause, rollback and device re-attestation.">
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={4}>
      <Stat label="Active rollouts" value={rows.filter((r) => r.status === 'rolling').length} tone="violet" icon="upload" />
      <Stat label="Paused" value={rows.filter((r) => r.status === 'paused').length} tone="amber" icon="clock" />
      <Stat label="Stable" value={rows.filter((r) => r.status === 'stable').length} tone="green" icon="check" />
      <Stat label="Devices" value={devices.length} icon="device" />
    </StatGrid>
    {rows.map((r) => <Card key={r.id} title={`${r.version} · ${r.status}`} desc={`${r.cov.onRelease} of ${r.cov.total} devices · ${r.cov.attested} attested`}
      actions={<><Link className="mini" to={`/releases/${r.id}`}>Details</Link>{can('release.rollout') && <button className="mini" onClick={() => setAction({ kind: 'rollout', r })}>Advance</button>}{can('release.rollout') && r.status === 'rolling' && <button className="mini" onClick={() => setAction({ kind: 'pause', r })}>Pause</button>}{can('release.rollout') && r.status === 'paused' && <button className="mini" onClick={() => run(() => resumeRollout(user, r))}>Resume</button>}{can('release.rollout') && <button className="mini danger" onClick={() => setAction({ kind: 'rollback', r })}>Rollback</button>}</>}>
      <Progress value={r.cov.pct} label={`Fleet coverage · target ${r.rollout || 0}%`} />
      <div className="covgrid"><span><b>{r.cov.enrolled}</b><small>enrolled</small></span><span><b>{r.cov.attested}</b><small>attested</small></span><span><b>{r.cov.pendingAttestation}</b><small>pending</small></span><span><b>{r.cov.failed}</b><small>failed</small></span></div>
    </Card>)}
    {!rows.length && <Empty icon="upload" title="No rollouts" action={<Link className="btn" to="/admin/releases">Open releases</Link>} />}
    {action?.kind === 'rollout' && <ActionDialog title={`Advance ${action.r.version}`} field={{ label: 'Step', options: STEPS.filter((n) => n > (action.r.rollout || 0)).map((n) => ({ v: n, l: `${n}%` })) }} requireReason={false} confirmLabel="Apply" onClose={() => setAction(null)} onConfirm={(why, step) => run(async () => { await rollout(user, action.r, Number(step)); setAction(null); })} />}
    {action?.kind === 'pause' && <ActionDialog title={`Pause ${action.r.version}`} confirmLabel="Pause rollout" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await pauseRollout(user, action.r, reason); setAction(null); })} />}
    {action?.kind === 'rollback' && <ActionDialog title={`Roll back ${action.r.version}`} danger confirmLabel="Roll back" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await rollbackRelease(user, action.r, reason); setAction(null); })} />}
  </Page>;
}

export function ReleaseValidationPage() {
  const { user } = useAuth();
  const [releases, setReleases] = useState([]);
  useEffect(() => { listReleases().then(setReleases).catch(() => setReleases([])); }, []);
  const [evidence, setEvidence] = useState([]);
  const { msg, run, setMsg } = useFlash();
  const can = usePerm();
  const [addEv, setAddEv] = useState(false);
  const [f, setF] = useState({ releaseId: '', title: '', kind: 'test-report', classification: 'internal', content: '', link: '' });
  useEffect(() => {
    let active = true;
    Promise.all(releases.map((release) => listReleaseEvidence(release.id).catch(() => [])))
      .then((groups) => { if (active) setEvidence(groups.flat()); });
    return () => { active = false; };
  }, [releases]);
  const rows = [...evidence].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  const tampered = rows.filter((e) => e.verification === 'tampered').length;
  const covered = new Set(rows.map((e) => e.releaseId)).size;
  return <Page title="Validation & evidence" desc="Sealed validation artefacts that gate release approval."
    actions={can('release.manage') ? <button className="btn primary" onClick={() => setAddEv(true)}><Icon name="plus" size={15} /> Add evidence</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={4}>
      <Stat label="Evidence records" value={rows.length} icon="lock" />
      <Stat label="Releases covered" value={covered} icon="package" sub={`${releases.length} total`} />
      <Stat label="Tampered" value={tampered} tone={tampered ? 'red' : 'green'} icon="warn" />
      <Stat label="Critical CVEs" value={releases.reduce((n, r) => n + (r.criticalCves || 0), 0)} tone="amber" icon="bug" />
    </StatGrid>
    <Card title="Release coverage">
      <div className="coverage-list">{releases.map((r) => { const n = rows.filter((e) => e.releaseId === r.id).length; return <Link key={r.id} to={`/releases/${r.id}`} className="covrow"><Badge value={r.status} /><b>{r.version}</b><span className="grow" /><small className="muted">{n} evidence record(s)</small></Link>; })}</div>
    </Card>
    <DataTable rows={rows} search={['title', 'kind', 'version']} title="Validation evidence"
      filters={[{ key: 'kind', label: 'Type', options: EVIDENCE_KINDS }, { key: 'verification', label: 'Integrity', options: ['sealed', 'verified', 'tampered'] }]}
      columns={[
        { key: 'title', label: 'Evidence', render: (e) => <><b>{e.title}</b><br /><small className="muted">{e.kind} · {e.classification}</small></> },
        { key: 'version', label: 'Release', render: (e) => <Link to={`/releases/${e.releaseId}`}>{e.version}</Link> },
        { key: 'verification', label: 'Integrity', render: (e) => <Badge value={e.verification} /> },
        { key: 'createdAt', label: 'Sealed', render: (e) => fmt(e.createdAt) },
        { key: 'hash', label: 'Backend status', render: (e) => <Badge value={e.verification} /> },
      ]}
      actions={(e) => [{ label: 'Verify', onClick: () => run(async () => { const x = await verifyReleaseEvidence(e); return x.ok ? 'Evidence verified.' : Promise.reject(new Error('Evidence was tampered with.')); }) }]} />
    {addEv && <Modal title="Add validation evidence" wide onClose={() => setAddEv(false)} footer={<><button className="btn" onClick={() => setAddEv(false)}>Cancel</button><button className="btn primary" form="val-form">Submit validation</button></>}>
      <form id="val-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await addReleaseEvidence(user, f); setEvidence((await Promise.all(releases.map((release) => listReleaseEvidence(release.id).catch(() => [])))).flat()); setAddEv(false); }); }}>
        <Field label="Release" required><Select value={f.releaseId} onChange={(e) => setF({ ...f, releaseId: e.target.value })} options={releases.map((r) => ({ v: r.id, l: `${r.version} · ${r.status}` }))} /></Field>
        <Field label="Title" required><Input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} maxLength={120} /></Field>
        <Field label="Type"><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })} options={EVIDENCE_KINDS} placeholder={false} /></Field>
        <Field label="Classification"><Select value={f.classification} onChange={(e) => setF({ ...f, classification: e.target.value })} options={['internal', 'confidential', 'restricted', 'auditor-only']} placeholder={false} /></Field>
        <Field label="Content" className="span2"><Textarea rows={7} value={f.content} onChange={(e) => setF({ ...f, content: e.target.value })} maxLength={200000} /></Field>
      </form>
    </Modal>}
  </Page>;
}

export default ReleasesPage;
