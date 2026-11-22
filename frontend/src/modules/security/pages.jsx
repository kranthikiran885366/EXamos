import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs, Progress,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { useLoad, usePerm } from '../../core/ui/hooks';
import {
  logSecurityEvent, acknowledgeEvent, resolveEvent, escalateEvent,
  createVulnerability, updateVulnerability, syncVulnerabilities,
  addEvidence, verifyEvidenceRecord, verifyAllEvidence, deleteEvidence,
  SEVERITIES, EVENT_TYPES, VULN_STATUSES, EVIDENCE_KINDS, EVIDENCE_CLASS,
  securityOverview, bootIntegrity, evidenceStats, vulnStats,
} from './service';
import { createPolicy, requestPolicyPublication, discardDraft, requestRollback, ACTIONS } from '../policies/service';
import { raise, move, addNote, assign, falsePositive, promote, FLOW } from '../incidents/service';

const NEXT_LABEL = { investigating: 'Start investigating', contained: 'Contain', resolved: 'Resolve', closed: 'Close', open: 'Reopen' };
const pcrDigest = (pcr) => {
  if (!pcr) return '';
  if (typeof pcr === 'string') return pcr;
  if (Array.isArray(pcr)) return pcr.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join('·');
  if (typeof pcr === 'object') return Object.values(pcr).map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join('·');
  return String(pcr);
};

/* ------------------------------------------------------------------ overview */
export function SecurityOverviewPage() {
  const { tenantId, tenant } = useTenant();
  const { data: o, loading, error, reload } = useLoad(() => securityOverview(tenantId), [tenantId]);
  const perms = usePerm();

  return (
    <Page title="Security overview" desc="Security events, incidents, device trust and platform posture."
      actions={<button className="btn" onClick={reload} disabled={loading}><Icon name="refresh" size={15} /> Refresh</button>}>
      {error && <Alert tone="danger" title="Could not compute posture">{error.message}</Alert>}
      {loading || !o ? <Loading label="Computing security posture…" /> : (
        <>
          <StatGrid cols={6}>
            <Stat label="Security score" value={o.score} unit="/100" icon={o.score >= 90 ? 'check' : 'warn'} tone={o.score >= 90 ? 'green' : o.score >= 70 ? 'amber' : 'red'} />
            <Stat label="Devices" value={o.devices} icon="device" sub={`${o.attested} server-verified`} />
            <Stat label="Boot intact" value={o.bootIntact} icon="boot" tone={o.devices > 0 && o.bootIntact === o.devices ? 'green' : 'amber'} />
            <Stat label="Open incidents" value={o.openIncidents} icon="alert" tone={o.openIncidents ? 'amber' : 'green'} />
            <Stat label="Critical vulns" value={o.criticalVulns} icon={o.criticalVulns ? 'warn' : 'check'} tone={o.criticalVulns ? 'red' : 'green'} />
            <Stat label="Audit chain" value={o.chainOk ? 'Intact' : 'Broken'} icon="shield" tone={o.chainOk ? 'green' : 'red'} sub={`${o.chainCount} entries`} />
          </StatGrid>
          {!o.chainOk && <Alert tone="danger" title="Audit chain verification failed">The hash chain is broken. Preserve the database and escalate to the platform team immediately.</Alert>}
          {o.evidenceTampered > 0 && <Alert tone="danger" title={`${o.evidenceTampered} evidence record(s) failed verification`} action={<Link className="btn" to="/security/evidence">Open vault</Link>}>Do not use affected evidence in audits until it is re-sealed.</Alert>}
          <div className="two">
            <Card title="Posture breakdown" pad>
              <Progress label={`Server-verified device trust · ${o.attestedPct}%`} value={o.attestedPct} max={100} />
              <Progress label={`Server-verified boot integrity · ${o.bootPct}%`} value={o.bootPct} max={100} />
              <Progress label="Security score" value={o.score} max={100} />
              <KeyValue cols={2} items={[
                ['Isolated devices', o.isolated], ['Failed trust', o.failed],
                ['Open events', o.openEvents], ['Open vulnerabilities', o.openVulns],
                ['Evidence records', `${o.evidence} (${o.evidenceTampered} tampered)`],
                ['Published policies', o.publishedPolicies],
                ['Releases', `${o.releases} (${o.revokedReleases} revoked)`],
                ['Critical incidents', o.criticalIncidents],
              ]} />
            </Card>
            <Card title="Recommended actions" desc={tenant ? `Posture for ${tenant.name}` : 'Platform posture'}>
              <ul className="checklist">
                {o.criticalVulns > 0 && <li>Remediate {o.criticalVulns} critical vulnerabilities.</li>}
                {o.attestedPct < 90 && <li>Complete trusted device provisioning and server-side TPM quote verification before relying on device posture.</li>}
                {o.openEvents > 0 && <li>Acknowledge and triage {o.openEvents} open security events.</li>}
                {o.evidenceTampered > 0 && <li>Re-seal or retire tampered evidence records.</li>}
                {o.revokedReleases > 0 && <li>Review devices still running revoked releases.</li>}
                {!o.criticalVulns && o.attestedPct >= 90 && !o.openEvents && !o.evidenceTampered && <li>No urgent actions. Keep monitoring.</li>}
              </ul>
              <div className="row wrap">
                {perms('security.manage') && <Link className="btn" to="/security/events">Security events</Link>}
                {perms('incident.manage') && <Link className="btn" to="/security/incident-response">Incidents</Link>}
                <Link className="btn" to="/security/boot-integrity">Boot integrity</Link>
              </div>
            </Card>
          </div>
        </>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ boot integrity */
export function BootIntegrityPage() {
  const { tenantId } = useTenant();
  const nav = useNavigate();
  const devices = useCol('devices', false);
  const attestations = useCol('attestations', false);
  const releases = useCol('releases', false);
  const policies = useCol('policies', false);
  const { data: rows, loading, error } = useLoad(
    () => bootIntegrity(tenantId, { devices, attestations, releases, policies }),
    [tenantId, devices, attestations, releases, policies],
  );

  return (
    <Page title="Boot integrity" desc="Server-verified boot integrity is unavailable. Local device fields and historical quote reports are unverified.">
      {error && <Alert tone="danger" title="Could not load boot integrity">{error.message}</Alert>}
      {loading ? <Loading /> : (
        <DataTable
          title="Reported boot data" desc="PCR values below come from historical local reports and are not verified evidence."
          rows={rows || []} search={(d) => `${d.hostname} ${d.bootStatus} ${d.trust}`}
          filters={[{ key: 'bootStatus', label: 'Boot status', options: ['intact', 'failed', 'unknown', 'tampered', 'release-revoked'].map((s) => ({ v: s, l: s })) }]}
          columns={[
            { key: 'hostname', label: 'Device', render: (d) => <Link className="strong-link mono" to={`/devices/${d.id}`}>{d.hostname}</Link> },
            { key: 'bootStatus', label: 'Boot status', render: (d) => <Badge value={d.bootStatus} /> },
            { key: 'secureBoot', label: 'Reported Secure Boot', render: (d) => <Badge value={d.secureBoot ? 'reported on' : 'unverified'} tone="amber" /> },
            { key: 'tpm', label: 'Reported TPM 2.0', render: (d) => <Badge value={d.tpm ? 'reported present' : 'unverified'} tone="amber" /> },
            { key: 'release', label: 'Release', render: (d) => (d.release ? `${d.release.version} (${d.release.status})` : '—') },
            { key: 'measuredAt', label: 'Last local report', sortable: true, render: (d) => (d.measuredAt ? fmt(d.measuredAt) : 'Never') },
            { key: 'pcr', label: 'PCR', render: (d) => <span className="mono sm">{pcrDigest(d.pcr) ? `${pcrDigest(d.pcr).slice(0, 20)}…` : '—'}</span> },
          ]}
          actions={(d) => [{ label: 'Open device', onClick: () => nav(`/devices/${d.id}`) }]}
        />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ attestation */
export function AttestationPage() {
  const { tenantId } = useTenant();
  const attestations = useCol('attestations', false);
  const devices = useCol('devices', false);
  const [view, setView] = useState(null);

  const mine = devices.filter((d) => d.tenantId === tenantId);
  const rows = useMemo(() => attestations
    .filter((a) => mine.some((d) => d.id === a.deviceId))
    .sort((a, b) => (b.verifiedAt || b.issuedAt || 0) - (a.verifiedAt || a.issuedAt || 0)), [attestations, mine]);

  return (
    <Page title="Attestation reports" desc="Historical local reports are unverified. Trusted hardware status requires backend-verified TPM evidence, which is not available in this console.">
      <Alert tone="warn" title="Quote verification unavailable">
        Existing report results and PCR matches are not server-verified and cannot establish device trust.
      </Alert>
      <StatGrid cols={4}>
        <Stat label="Legacy reports" value={rows.length} icon="shield" />
        <Stat label="Reported success claims" value={rows.filter((a) => a.result === 'attested' || a.result === 'pass').length} icon="check" tone="amber" />
        <Stat label="Reported failure claims" value={rows.filter((a) => ['failed', 'fail'].includes(a.result)).length} icon="warn" tone="amber" />
        <Stat label="Devices" value={mine.length} icon="device" />
      </StatGrid>
      <DataTable
        title="Legacy report history" desc="Newest first; report values are not trusted evidence."
        rows={rows} search={(a) => `${a.deviceId} ${a.result} ${a.reason || ''}`}
        filters={[{ key: 'result', label: 'Result', options: ['attested', 'failed', 'unknown'].map((s) => ({ v: s, l: s })) }]}
        columns={[
          { key: 'deviceId', label: 'Device', render: (a) => { const d = mine.find((x) => x.id === a.deviceId); return d ? <Link className="strong-link mono" to={`/devices/${d.id}`}>{d.hostname}</Link> : a.deviceId; } },
          { key: 'result', label: 'Reported result', render: (a) => <Badge value={a.result || a.status || 'Unknown'} tone="amber" /> },
          { key: 'pcrMatch', label: 'Reported PCR match', render: (a) => <Badge value={a.pcrMatch ? 'claimed match' : 'not verified'} tone="amber" /> },
          { key: 'nonce', label: 'Nonce', render: (a) => <span className="mono sm">{a.nonce ? `${a.nonce.slice(0, 12)}…` : '—'}</span> },
          { key: 'issuedAt', label: 'Issued', sortable: true, render: (a) => fmt(a.issuedAt || a.verifiedAt) },
          { key: 'reason', label: 'Detail', render: (a) => a.reason || '—' },
        ]}
        actions={(a) => [{ label: 'View quote', onClick: () => setView(a) }]}
      />
      {view && (
        <Modal wide title="Attestation quote" desc={view.deviceId} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={2} items={[
            ['Reported result', <Badge key="r" value={view.result || view.status || 'Unknown'} tone="amber" />],
            ['Reported PCR match', <Badge key="p" value={view.pcrMatch ? 'claimed match' : 'not verified'} tone="amber" />],
            ['Nonce', <code key="n">{view.nonce || '—'}</code>],
            ['Issued', fmt(view.issuedAt)], ['Reported verification time', view.verifiedAt ? fmt(view.verifiedAt) : '—'],
          ]} />
          {view.reason && <Alert tone="warn">{view.reason} (unverified legacy report)</Alert>}
          <pre className="codeblock">{JSON.stringify(view.quote || view.pcr || {}, null, 2)}</pre>
        </Modal>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ policies */
function PolicyModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ name: 'nqt-secure-kiosk', requireTpm: true, kioskLockdown: true, allowUsb: false, onViolation: ACTIONS[0], origins: 'https://exam.examos.in' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      const p = await createPolicy(user, { tenantId, ...v, origins: v.origins.split(/[\s,]+/).filter(Boolean) });
      onDone?.(`Draft ${p.name} v${p.version} saved.`); onClose();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal wide title="New policy draft" desc="Drafts are stored by the server. Trusted signing and publication are not available in this console." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="policy-form" disabled={busy}>{busy ? 'Saving…' : 'Save draft'}</button></>}>
      <form id="policy-form" onSubmit={submit} className="formgrid">
        <Field label="Policy name" required className="span2"><Input value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} maxLength={60} /></Field>
        <Field label="Violation action" required className="span2">
          <Select value={v.onViolation} onChange={(e) => setV({ ...v, onViolation: e.target.value })} options={ACTIONS} placeholder={false} />
        </Field>
        <Field label="Allowed origins" required className="span2" help="Space or comma separated HTTPS URLs. Insecure HTTP is strictly rejected.">
          <Textarea rows={2} value={v.origins} onChange={(e) => setV({ ...v, origins: e.target.value })} maxLength={500} />
        </Field>
        {v.origins && v.origins.split(/[\s,]+/).some((o) => o.trim().toLowerCase().startsWith('http://')) && (
          <div className="span2"><Alert tone="danger" title="Insecure HTTP origin rejected">
            All policy origins must use HTTPS. Insecure HTTP origins are blocked for zero-trust security.
          </Alert></div>
        )}
        <label className="check"><input type="checkbox" checked={v.requireTpm} onChange={(e) => setV({ ...v, requireTpm: e.target.checked })} /><span>Require TPM 2.0 attestation</span></label>
        <label className="check"><input type="checkbox" checked={v.kioskLockdown} onChange={(e) => setV({ ...v, kioskLockdown: e.target.checked })} /><span>Kiosk lockdown</span></label>
        <label className="check"><input type="checkbox" checked={v.allowUsb} onChange={(e) => setV({ ...v, allowUsb: e.target.checked })} /><span>Allow USB storage</span></label>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function SecurityPoliciesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const policies = useCol('policies', false);
  const [modal, setModal] = useState(false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const rows = policies.filter((p) => p.tenantId === tenantId);

  return (
    <Page title="Security policies" desc="Server-persisted policy drafts and approval requests. Trusted signing and execution remain unavailable."
      actions={perms('policy.edit') ? <button className="btn primary" onClick={() => setModal(true)}><Icon name="plus" size={15} /> New draft</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Policies" value={new Set(rows.map((p) => p.name)).size} icon="policy" />
        <Stat label="Published" value={rows.filter((p) => p.status === 'published').length} icon="check" tone="green" />
        <Stat label="Drafts" value={rows.filter((p) => p.status === 'draft').length} icon="clock" tone="amber" />
        <Stat label="Superseded" value={rows.filter((p) => p.status === 'superseded').length} icon="history" />
      </StatGrid>
      <DataTable
        title="Policy versions" desc="Newest versions first. Weakening a policy needs a super admin."
        rows={[...rows].sort((a, b) => b.createdAt - a.createdAt)}
        search={(p) => `${p.name} v${p.version} ${p.status} ${p.config?.onViolation}`}
        filters={[{ key: 'status', label: 'Status', options: ['draft', 'published', 'superseded', 'discarded'].map((s) => ({ v: s, l: s })) }]}
        columns={[
          { key: 'name', label: 'Policy', render: (p) => <><b>{p.name}</b><div className="muted sm mono">v{p.version}</div></> },
          { key: 'status', label: 'Status', render: (p) => <Badge value={p.status} /> },
          { key: 'requireTpm', label: 'TPM', render: (p) => <Badge value={p.config?.requireTpm ? 'required' : 'optional'} /> },
          { key: 'kioskLockdown', label: 'Kiosk', render: (p) => <Badge value={p.config?.kioskLockdown ? 'locked' : 'open'} /> },
          { key: 'allowUsb', label: 'USB', render: (p) => <Badge value={p.config?.allowUsb ? 'allowed' : 'blocked'} /> },
          { key: 'onViolation', label: 'On violation', render: (p) => <span className="muted sm">{p.config?.onViolation}</span> },
          { key: 'publishedAt', label: 'Published', sortable: true, render: (p) => (p.publishedAt ? fmt(p.publishedAt) : '—') },
        ]}
        actions={(p) => [
          { label: 'View', onClick: () => setView(p) },
          ...(perms('policy.publish') && p.status === 'draft' ? [{ label: 'Publish', onClick: () => setAct({ type: 'publish', row: p }) }] : []),
          ...(perms('policy.edit') && p.status === 'draft' ? [{ label: 'Discard', danger: true, onClick: () => setAct({ type: 'discard', row: p }) }] : []),
          ...(perms('policy.rollback') && p.status === 'superseded' ? [{ label: 'Request rollback', onClick: () => setAct({ type: 'rollback', row: p }) }] : []),
        ]}
      />
      {modal && <PolicyModal tenantId={tenantId} onClose={() => setModal(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {view && (
        <Modal wide title={`${view.name} v${view.version}`} desc={view.status} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={2} items={[
            ['Status', <Badge key="s" value={view.status} />],
            ['On violation', view.config?.onViolation],
            ['Require TPM', view.config?.requireTpm ? 'Yes' : 'No'],
            ['Kiosk lockdown', view.config?.kioskLockdown ? 'Yes' : 'No'],
            ['Allow USB', view.config?.allowUsb ? 'Yes' : 'No'],
            ['Published', view.publishedAt ? fmt(view.publishedAt) : '—'],
            ['Stored hash (unverified)', <code key="h">{view.hash ? `${view.hash.slice(0, 24)}…` : '—'}</code>],
            ['Stored signature (unverified)', <code key="g">{view.sig ? `${String(view.sig).slice(0, 24)}…` : '—'}</code>],
          ]} />
          <Field label="Allowed origins"><div className="chips">{(view.config?.origins || []).map((o) => <span key={o} className="chip mono">{o}</span>)}</div></Field>
        </Modal>
      )}
      {act?.type === 'publish' && (
        <ActionDialog title="Request policy publication" desc={`${act.row.name} v${act.row.version} will remain a draft until a separate execution integration is available.`} confirmLabel="Request approval" password requireReason
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(async () => { const request = await requestPolicyPublication(user, act.row.id, reason); return `Approval requested (${request.id}). The policy remains a draft.`; })} />
      )}
      {act?.type === 'discard' && (
        <ActionDialog title="Discard draft" desc={`${act.row.name} v${act.row.version}`} danger confirmLabel="Discard" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(async () => { await discardDraft(user, act.row); return 'Draft discarded.'; })} />
      )}
      {act?.type === 'rollback' && (
        <ActionDialog title="Request rollback" desc={`Roll back ${act.row.name} to v${act.row.version}. A different approver must confirm.`} confirmLabel="Request rollback"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => requestRollback(user, act.row, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ events */
export function SecurityEventsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const events = useCol('securityEvents', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const [tab, setTab] = useState('open');
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => events.filter((e) => e.tenantId === tenantId).sort((a, b) => (b.at || 0) - (a.at || 0)), [events, tenantId]);
  const open = rows.filter((e) => ['open', 'acknowledged', 'escalated'].includes(e.status));
  const closed = rows.filter((e) => !['open', 'acknowledged', 'escalated'].includes(e.status));
  const shown = tab === 'open' ? open : closed;

  return (
    <Page title="Security events" desc="Authenticated security events from approved sources. Acknowledge, resolve or escalate."
      actions={perms('security.manage') ? <button className="btn primary" onClick={() => setAct({ type: 'log' })}><Icon name="plus" size={15} /> Log event</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Open" value={open.filter((e) => e.status === 'open').length} icon="alert" tone="red" />
        <Stat label="Acknowledged" value={rows.filter((e) => e.status === 'acknowledged').length} icon="eye" tone="amber" />
        <Stat label="Escalated" value={rows.filter((e) => e.status === 'escalated').length} icon="upload" tone="amber" />
        <Stat label="Resolved" value={rows.filter((e) => e.status === 'resolved').length} icon="check" tone="green" />
      </StatGrid>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: 'open', label: 'Needs attention', count: open.length }, { key: 'closed', label: 'Closed', count: closed.length }]} />
      <DataTable
        title="Security events" desc="Newest first."
        rows={shown} search={(e) => `${e.type} ${e.severity} ${e.title} ${e.actor} ${e.detail}`}
        filters={[
          { key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ v: s, l: s })) },
          { key: 'type', label: 'Type', options: EVENT_TYPES.map((s) => ({ v: s, l: s })) },
        ]}
        columns={[
          { key: 'at', label: 'Time', sortable: true, render: (e) => fmt(e.at) },
          { key: 'type', label: 'Type', render: (e) => <Badge value={e.type} /> },
          { key: 'severity', label: 'Severity', render: (e) => <Badge value={e.severity} /> },
          { key: 'title', label: 'Title', render: (e) => <b>{e.title}</b> },
          { key: 'actor', label: 'Actor', mono: true },
          { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
        ]}
        actions={(e) => [
          { label: 'View', onClick: () => setView(e) },
          ...(perms('security.manage') && e.status === 'open' ? [{ label: 'Acknowledge', onClick: () => setAct({ type: 'ack', row: e }) }] : []),
          ...(perms('security.manage') && ['open', 'acknowledged'].includes(e.status) ? [
            { label: 'Resolve', onClick: () => setAct({ type: 'resolve', row: e }) },
            { label: 'Escalate', danger: true, onClick: () => setAct({ type: 'escalate', row: e }) },
          ] : []),
        ]}
      />
      {view && (
        <Modal wide title={view.title} desc={`${view.type} · ${view.severity}`} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={2} items={[
            ['Status', <Badge key="s" value={view.status} />], ['Actor', view.actor],
            ['Source', view.source], ['Device', view.deviceId || '—'],
            ['Raised', fmt(view.at)], ['Acknowledged', view.ackAt ? `${view.ackBy} · ${fmt(view.ackAt)}` : '—'],
            ['Resolved', view.resolvedAt ? `${view.resolvedBy} · ${fmt(view.resolvedAt)}` : '—'],
            ['Incident', view.incidentId || '—'],
          ]} />
          {view.detail && <Alert tone="info">{view.detail}</Alert>}
          {view.resolution && <Alert tone="success" title="Resolution">{view.resolution}</Alert>}
          {view.escalationReason && <Alert tone="warn" title="Escalation reason">{view.escalationReason}</Alert>}
        </Modal>
      )}
      {act?.type === 'log' && <LogEventModal tenantId={tenantId} onClose={() => setAct(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act?.type === 'ack' && (
        <ActionDialog title="Acknowledge event" desc={act.row.title} confirmLabel="Acknowledge" requireReason={false}
          field={{ label: 'Note (optional)', type: 'textarea' }} onClose={() => setAct(null)}
          onConfirm={(_r, val) => flash.run(() => acknowledgeEvent(user, act.row, val))} />
      )}
      {act?.type === 'resolve' && (
        <ActionDialog title="Resolve event" desc={act.row.title} confirmLabel="Resolve" reasonLabel="Resolution"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => resolveEvent(user, act.row, reason))} />
      )}
      {act?.type === 'escalate' && (
        <ActionDialog title="Escalate to incident" desc={act.row.title} danger confirmLabel="Escalate" reasonLabel="Escalation reason"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => escalateEvent(user, act.row, reason))} />
      )}
    </Page>
  );
}

function LogEventModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ type: EVENT_TYPES[0], severity: 'medium', title: '', detail: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const ev = await logSecurityEvent(user, { tenantId, ...v }); onDone?.(`Event logged · ${ev.id}`); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Log security event" onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="event-form" disabled={busy}>{busy ? 'Saving…' : 'Log event'}</button></>}>
      <form id="event-form" onSubmit={submit} className="formgrid">
        <Field label="Type" required><Select value={v.type} onChange={(e) => setV({ ...v, type: e.target.value })} options={EVENT_TYPES} placeholder={false} /></Field>
        <Field label="Severity" required><Select value={v.severity} onChange={(e) => setV({ ...v, severity: e.target.value })} options={SEVERITIES} placeholder={false} /></Field>
        <Field label="Title" required className="span2"><Input value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} maxLength={140} autoFocus /></Field>
        <Field label="Detail" className="span2"><Textarea rows={3} value={v.detail} onChange={(e) => setV({ ...v, detail: e.target.value })} maxLength={500} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ incidents */
export function IncidentResponsePage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const incidents = useCol('incidents', false);
  const users = useCol('users', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: '', severity: 'high', description: '' });
  const [tab, setTab] = useState('open');
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => incidents.filter((i) => i.tenantId === tenantId).sort((a, b) => b.createdAt - a.createdAt), [incidents, tenantId]);
  const open = rows.filter((i) => ['open', 'investigating', 'contained'].includes(i.status));
  const closed = rows.filter((i) => !['open', 'investigating', 'contained'].includes(i.status));
  const shown = tab === 'open' ? open : closed;

  const create = async (e) => {
    e.preventDefault();
    await flash.run(async () => {
      const inc = await raise({ tenantId, key: `sec:${Date.now()}`, title: form.title, severity: form.severity, source: 'security-console' });
      if (form.description.trim()) await addNote(user, inc, form.description);
      setCreating(false); setForm({ title: '', severity: 'high', description: '' });
      return `INC-${inc.no} raised.`;
    });
  };

  return (
    <Page title="Incident response" desc="Investigate, contain, remediate and close security incidents."
      actions={perms('incident.manage') ? <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New incident</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Open" value={open.filter((i) => i.status === 'open').length} icon="alert" tone="red" />
        <Stat label="Investigating" value={rows.filter((i) => i.status === 'investigating').length} icon="search" tone="amber" />
        <Stat label="Resolved" value={rows.filter((i) => ['resolved', 'closed'].includes(i.status)).length} icon="check" tone="green" />
        <Stat label="Critical open" value={open.filter((i) => i.severity === 'critical').length} icon="warn" tone="red" />
      </StatGrid>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: 'open', label: 'Open', count: open.length }, { key: 'closed', label: 'Closed', count: closed.length }]} />
      <DataTable
        title="Incidents" desc="Every transition and note is written to the audit trail."
        rows={shown} search={(i) => `${i.no} ${i.title} ${i.severity} ${i.status} ${i.owner || ''}`}
        filters={[
          { key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ v: s, l: s })) },
          { key: 'status', label: 'Status', options: ['open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'].map((s) => ({ v: s, l: s })) },
        ]}
        columns={[
          { key: 'no', label: 'Ref', render: (i) => <span className="mono">INC-{i.no}</span> },
          { key: 'title', label: 'Title', render: (i) => <><b>{i.title}</b>{i.kind === 'finding' && <Badge className="ml" value="finding" />}</> },
          { key: 'severity', label: 'Severity', render: (i) => <Badge value={i.severity} /> },
          { key: 'status', label: 'Status', render: (i) => <Badge value={i.status} /> },
          { key: 'owner', label: 'Owner', render: (i) => i.owner || 'Unassigned' },
          { key: 'createdAt', label: 'Raised', sortable: true, render: (i) => ago(i.createdAt) },
        ]}
        actions={(i) => {
          const out = [{ label: 'View', onClick: () => setView(i) }];
          if (!perms('incident.manage')) return out;
          for (const to of (FLOW[i.status] || [])) out.push({ label: NEXT_LABEL[to] || to, onClick: () => setAct({ type: 'move', row: i, to }) });
          out.push({ label: 'Note', onClick: () => setAct({ type: 'note', row: i }) });
          out.push({ label: 'Assign', onClick: () => setAct({ type: 'assign', row: i }) });
          if (!['false_positive', 'closed'].includes(i.status)) out.push({ label: 'False positive', danger: true, onClick: () => setAct({ type: 'false', row: i }) });
          if (i.kind !== 'finding') out.push({ label: 'Promote', onClick: () => setAct({ type: 'promote', row: i }) });
          return out;
        }}
      />

      {creating && (
        <Modal title="Raise incident" onClose={() => setCreating(false)}
          footer={<><button className="btn" onClick={() => setCreating(false)}>Cancel</button><button className="btn primary" form="sec-incident-form" disabled={flash.busy}>{flash.busy ? 'Saving…' : 'Raise incident'}</button></>}>
          <form id="sec-incident-form" onSubmit={create} className="formgrid">
            <Field label="Title" required className="span2"><Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} maxLength={140} autoFocus /></Field>
            <Field label="Severity"><Select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} options={SEVERITIES} placeholder={false} /></Field>
            <Field label="Description" className="span2"><Textarea rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} maxLength={400} /></Field>
          </form>
        </Modal>
      )}
      {view && (
        <Modal wide title={`INC-${view.no} · ${view.title}`} desc={`${view.severity} · ${view.status}`} onClose={() => setView(null)}
          footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={3} items={[
            ['Source', view.source || '—'], ['Owner', view.owner || 'Unassigned'],
            ['Kind', view.kind || 'alert'], ['Raised', fmt(view.createdAt)],
            ['Device', view.deviceId || '—'], ['Exam', view.examId || '—'],
          ]} />
          <h4>Investigation notes</h4>
          {view.notes?.length ? <Timeline items={view.notes.map((n) => ({ id: String(n.at), title: n.by, meta: fmt(n.at), body: n.text }))} /> : <Empty icon="ticket" title="No notes yet" />}
        </Modal>
      )}
      {act?.type === 'move' && (
        <ActionDialog title={NEXT_LABEL[act.to] || `Move to ${act.to}`} desc={`INC-${act.row.no}: ${act.row.title}`} confirmLabel="Confirm" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => move(user, act.row, act.to))} />
      )}
      {act?.type === 'note' && (
        <ActionDialog title="Add investigation note" desc={`INC-${act.row.no}`} confirmLabel="Add note" requireReason={false}
          field={{ label: 'Note', type: 'textarea', max: 400 }} onClose={() => setAct(null)}
          onConfirm={(_r, val) => flash.run(() => addNote(user, act.row, val))} />
      )}
      {act?.type === 'assign' && (
        <ActionDialog title="Assign incident" desc={`INC-${act.row.no}`} confirmLabel="Assign" requireReason={false}
          field={{ label: 'Owner', options: users.filter((u) => u.tenantId === tenantId || !u.tenantId).map((u) => ({ v: u.id, l: `${u.name} (${u.role})` })) }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(() => assign(user, act.row, val))} />
      )}
      {act?.type === 'false' && (
        <ActionDialog title="Mark false positive" desc={`INC-${act.row.no}`} danger confirmLabel="Mark false positive"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => falsePositive(user, act.row, reason))} />
      )}
      {act?.type === 'promote' && (
        <ActionDialog title="Promote to finding" desc="Promote only after a human has reviewed the evidence." confirmLabel="Promote" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => promote(user, act.row))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ vulnerabilities */
function VulnModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ cve: '', component: '', title: '', severity: 'medium', cvss: '5', affected: '', fixedIn: '', owner: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const x = await createVulnerability(user, { tenantId, ...v }); onDone?.(`${x.cve || x.component} recorded.`); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Add vulnerability finding" onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="vuln-form" disabled={busy}>{busy ? 'Saving…' : 'Save finding'}</button></>}>
      <form id="vuln-form" onSubmit={submit} className="formgrid">
        <Field label="CVE id"><Input value={v.cve} onChange={(e) => setV({ ...v, cve: e.target.value })} placeholder="CVE-2026-12345" maxLength={30} /></Field>
        <Field label="Component" required><Input value={v.component} onChange={(e) => setV({ ...v, component: e.target.value })} maxLength={60} /></Field>
        <Field label="Title" required className="span2"><Input value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} maxLength={120} /></Field>
        <Field label="Severity"><Select value={v.severity} onChange={(e) => setV({ ...v, severity: e.target.value })} options={SEVERITIES} placeholder={false} /></Field>
        <Field label="CVSS (0–10)"><Input type="number" min="0" max="10" step="0.1" value={v.cvss} onChange={(e) => setV({ ...v, cvss: e.target.value })} /></Field>
        <Field label="Affected version"><Input value={v.affected} onChange={(e) => setV({ ...v, affected: e.target.value })} maxLength={120} /></Field>
        <Field label="Fixed in"><Input value={v.fixedIn} onChange={(e) => setV({ ...v, fixedIn: e.target.value })} maxLength={40} /></Field>
        <Field label="Owner"><Input value={v.owner} onChange={(e) => setV({ ...v, owner: e.target.value })} maxLength={40} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function VulnerabilitiesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const vulns = useCol('vulnerabilities', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const rows = vulns.filter((v) => v.tenantId === tenantId);
  const stats = vulnStats(rows);

  return (
    <Page title="Vulnerabilities" desc="CVE advisories and affected component tracking, synced from release SBOM scans."
      actions={perms('security.manage') ? <>
        <button className="btn" onClick={() => flash.run(() => syncVulnerabilities(user, tenantId))}><Icon name="refresh" size={15} /> Sync from SBOM</button>
        <button className="btn primary" onClick={() => setAct({ type: 'add' })}><Icon name="plus" size={15} /> Add finding</button>
      </> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={5}>
        <Stat label="Findings" value={stats.total} icon="bug" />
        <Stat label="Open" value={stats.open} icon="alert" tone="amber" />
        <Stat label="Critical" value={stats.critical} icon="warn" tone="red" />
        <Stat label="Fixed" value={stats.fixed} icon="check" tone="green" />
        <Stat label="Mean CVSS" value={stats.meanCvss} icon="chart" />
      </StatGrid>
      <DataTable
        title="Vulnerability register" desc="Accepted and false-positive findings require a justification."
        rows={rows} search={(v) => `${v.cve} ${v.component} ${v.title} ${v.status} ${v.severity} ${v.owner}`}
        filters={[
          { key: 'status', label: 'Status', options: VULN_STATUSES.map((s) => ({ v: s, l: s })) },
          { key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ v: s, l: s })) },
        ]}
        columns={[
          { key: 'cve', label: 'CVE', render: (v) => <span className="mono">{v.cve || '—'}</span> },
          { key: 'component', label: 'Component', render: (v) => <b>{v.component}</b> },
          { key: 'title', label: 'Title', render: (v) => <span className="muted sm">{v.title}</span> },
          { key: 'severity', label: 'Severity', render: (v) => <Badge value={v.severity} /> },
          { key: 'cvss', label: 'CVSS', sortable: true, render: (v) => v.cvss },
          { key: 'status', label: 'Status', render: (v) => <Badge value={v.status} /> },
          { key: 'owner', label: 'Owner', render: (v) => v.owner || '—' },
          { key: 'createdAt', label: 'Raised', sortable: true, render: (v) => ago(v.createdAt) },
        ]}
        actions={(v) => [
          { label: 'View', onClick: () => setView(v) },
          ...(perms('security.manage') ? [{ label: 'Update', onClick: () => setAct({ type: 'update', row: v }) }] : []),
        ]}
      />
      {act?.type === 'add' && <VulnModal tenantId={tenantId} onClose={() => setAct(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act?.type === 'update' && (
        <ActionDialog title="Update vulnerability" desc={`${act.row.cve || act.row.component} · ${act.row.title}`} confirmLabel="Update" reasonLabel="Note / justification"
          field={{ label: 'Status', options: VULN_STATUSES, default: act.row.status }}
          onClose={() => setAct(null)}
          onConfirm={(reason, val) => flash.run(() => updateVulnerability(user, act.row, { status: val }, reason))} />
      )}
      {view && (
        <Modal wide title={view.cve || view.component} desc={view.title} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={3} items={[
            ['Severity', <Badge key="s" value={view.severity} />], ['CVSS', view.cvss],
            ['Status', <Badge key="t" value={view.status} />], ['Component', view.component],
            ['Affected', view.affected || '—'], ['Fixed in', view.fixedIn || '—'],
            ['Source', view.source], ['Owner', view.owner || '—'], ['Raised', fmt(view.createdAt)],
          ]} />
          {view.acceptReason && <Alert tone="warn" title="Acceptance justification">{view.acceptReason}</Alert>}
          {view.history?.length > 0 && <Timeline items={view.history.map((h) => ({ id: String(h.at), title: `${h.from} → ${h.to}`, meta: `${h.by} · ${fmt(h.at)}`, body: h.note }))} />}
        </Modal>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ evidence */
function EvidenceModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ title: '', kind: EVIDENCE_KINDS[0], classification: 'internal', content: '', link: '', tags: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const m = await addEvidence(user, { tenantId, ...v, tags: v.tags }); onDone?.(m); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal wide title="Seal evidence" desc="Evidence is hashed with SHA-256 on write; keep the original body intact." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="evidence-form" disabled={busy}>{busy ? 'Sealing…' : 'Seal evidence'}</button></>}>
      <form id="evidence-form" onSubmit={submit} className="formgrid">
        <Field label="Title" required className="span2"><Input value={v.title} onChange={(e) => setV({ ...v, title: e.target.value })} maxLength={120} autoFocus /></Field>
        <Field label="Type"><Select value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })} options={EVIDENCE_KINDS} placeholder={false} /></Field>
        <Field label="Classification"><Select value={v.classification} onChange={(e) => setV({ ...v, classification: e.target.value })} options={EVIDENCE_CLASS} placeholder={false} /></Field>
        <Field label="Link (optional)"><Input value={v.link} onChange={(e) => setV({ ...v, link: e.target.value })} maxLength={300} /></Field>
        <Field label="Tags"><Input value={v.tags} onChange={(e) => setV({ ...v, tags: e.target.value })} placeholder="release-4.2 audit" maxLength={120} /></Field>
        <Field label="Content" required className="span2"><Textarea rows={6} value={v.content} onChange={(e) => setV({ ...v, content: e.target.value })} maxLength={200000} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function EvidencePage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const evidence = useCol('evidence', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const rows = evidence.filter((e) => e.tenantId === tenantId && e.status !== 'retained');
  const stats = evidenceStats(rows);

  return (
    <Page title="Evidence vault" desc="Sealed validation artefacts with SHA-256 integrity. Verify or retire records."
      actions={<>
        {perms('evidence.view') && <button className="btn" onClick={() => flash.run(() => verifyAllEvidence(user, tenantId))}><Icon name="shield" size={15} /> Verify all</button>}
        {perms('evidence.manage') && <button className="btn primary" onClick={() => setAct({ type: 'add' })}><Icon name="plus" size={15} /> Add evidence</button>}
      </>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={5}>
        <Stat label="Records" value={stats.total} icon="package" />
        <Stat label="Sealed" value={stats.sealed} icon="lock" tone="green" />
        <Stat label="Verified" value={stats.verified} icon="check" tone="green" />
        <Stat label="Tampered" value={stats.tampered} icon="warn" tone={stats.tampered ? 'red' : 'green'} />
        <Stat label="Restricted" value={stats.restricted} icon="eye" tone="amber" />
      </StatGrid>
      {stats.tampered > 0 && <Alert tone="danger" title={`${stats.tampered} record(s) failed integrity verification`}>Do not use them as audit evidence. Retire and re-seal from the original source.</Alert>}
      <DataTable
        title="Evidence records" desc="Records attached to a release cannot be deleted; supersede them instead."
        rows={rows} search={(e) => `${e.title} ${e.kind} ${e.classification} ${e.status} ${e.verification} ${(e.tags || []).join(' ')}`}
        filters={[
          { key: 'verification', label: 'Integrity', options: ['sealed', 'verified', 'tampered'].map((s) => ({ v: s, l: s })) },
          { key: 'classification', label: 'Classification', options: EVIDENCE_CLASS.map((s) => ({ v: s, l: s })) },
          { key: 'kind', label: 'Type', options: EVIDENCE_KINDS.map((s) => ({ v: s, l: s })) },
        ]}
        columns={[
          { key: 'title', label: 'Title', render: (e) => <b>{e.title}</b> },
          { key: 'kind', label: 'Type', render: (e) => <Badge value={e.kind} /> },
          { key: 'classification', label: 'Classification', render: (e) => <Badge value={e.classification} /> },
          { key: 'verification', label: 'Integrity', render: (e) => <Badge value={e.verification} /> },
          { key: 'size', label: 'Size', render: (e) => `${Math.max(1, Math.round(e.size / 1024))} KB` },
          { key: 'createdAt', label: 'Sealed', sortable: true, render: (e) => fmt(e.createdAt) },
        ]}
        actions={(e) => [
          { label: 'View', onClick: () => setView(e) },
          ...(perms('evidence.view') ? [{ label: 'Verify', onClick: () => flash.run(async () => { const r = await verifyEvidenceRecord(e); return r.ok ? 'Evidence verified.' : 'TAMPERED — hash mismatch.'; }) }] : []),
          ...(perms('evidence.manage') && !e.releaseId ? [{ label: 'Retire', danger: true, onClick: () => setAct({ type: 'retire', row: e }) }] : []),
        ]}
      />
      {act?.type === 'add' && <EvidenceModal tenantId={tenantId} onClose={() => setAct(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act?.type === 'retire' && (
        <ActionDialog title="Retire evidence" desc={`${act.row.title} will leave the active vault. The audit record remains.`} danger confirmLabel="Retire"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => deleteEvidence(user, act.row, reason))} />
      )}
      {view && (
        <Modal wide title={view.title} desc={`${view.kind} · ${view.classification}`} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={2} items={[
            ['Integrity', <Badge key="i" value={view.verification} />], ['Status', view.status],
            ['Size', `${Math.max(1, Math.round(view.size / 1024))} KB`], ['Sealed', fmt(view.createdAt)],
            ['Sealed by', view.createdBy], ['Verified', view.verifiedAt ? fmt(view.verifiedAt) : '—'],
            ['Release', view.releaseId || '—'], ['Incident', view.incidentId || '—'],
            ['SHA-256', <code key="h">{view.hash}</code>],
          ]} />
          {view.link && <Alert tone="info" title="Link"><a href={view.link} target="_blank" rel="noreferrer noopener">{view.link}</a></Alert>}
          {(view.tags || []).length > 0 && <div className="chips">{view.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>}
          {view.body && <pre className="codeblock">{view.body}</pre>}
        </Modal>
      )}
    </Page>
  );
}
