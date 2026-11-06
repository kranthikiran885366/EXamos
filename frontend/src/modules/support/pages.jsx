import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs, CopyButton,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { useLoad, usePerm } from '../../core/ui/hooks';
import { downloadJson } from '../../core/services/common';
import {
  createRequest, addMessage, assignRequest, setStatus, escalateRequest, rateRequest,
  initiateRecovery, listRequests, getRequest, listRecovery, getStats,
  CATEGORIES, PRIORITIES, STATUSES, supportStats, isOpen, isBreached, slaLeft,
  diagnostics as runDiagnostics, statusOverview,
} from './service';

const catLabel = (v) => CATEGORIES.find((c) => c.v === v)?.l || v;
const prioLabel = (v) => PRIORITIES.find((p) => p.v === v)?.l || v;

function slaText(t) {
  if (!isOpen(t)) return '—';
  if (isBreached(t)) return 'Breached';
  const ms = slaLeft(t);
  if (ms <= 0) return 'Due now';
  const h = Math.floor(ms / 3600e3), m = Math.round((ms % 3600e3) / 60000);
  return h ? `${h}h ${m}m left` : `${m}m left`;
}

/* ------------------------------------------------------------------ create */
function RequestModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ subject: '', category: 'other', priority: 'normal', description: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const t = await createRequest(user, { tenantId, ...v }); onDone?.(`${t.no} created.`); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="New support request" desc="Critical requests open an incident automatically." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="request-form" disabled={busy}>{busy ? 'Creating…' : 'Create request'}</button></>}>
      <form id="request-form" onSubmit={submit} className="formgrid">
        <Field label="Subject" required className="span2"><Input value={v.subject} onChange={(e) => setV({ ...v, subject: e.target.value })} maxLength={140} autoFocus /></Field>
        <Field label="Category"><Select value={v.category} onChange={(e) => setV({ ...v, category: e.target.value })} options={CATEGORIES} placeholder={false} /></Field>
        <Field label="Priority"><Select value={v.priority} onChange={(e) => setV({ ...v, priority: e.target.value })} options={PRIORITIES} placeholder={false} /></Field>
        <Field label="Description" required className="span2"><Textarea rows={5} value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} maxLength={4000} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ home */
export function SupportHomePage() {
  const { tenantId } = useTenant();
  const { data, loading, error, reload } = useLoad(() => listRequests(), []);
  const tickets = data || [];
  const [creating, setCreating] = useState(false);
  const flash = useFlash();
  const perms = usePerm();
  const mine = useMemo(() => tickets.filter((t) => !tenantId || t.tenantId === tenantId), [tickets, tenantId]);
  const stats = supportStats(mine);
  const open = mine.filter(isOpen).sort((a, b) => (a.slaDue || 0) - (b.slaDue || 0));

  return (
    <Page title="Support home" desc="Create and track support requests with SLA tracking."
      actions={perms('support.manage') ? <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New request</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      {error && <Alert tone="danger" title="Could not load requests">{String(error.message || error)}</Alert>}
      {loading && <Loading label="Loading support requests…" />}
      <StatGrid cols={5}>
        <Stat label="Open" value={stats.open} icon="ticket" tone="amber" to="/support/requests" />
        <Stat label="Critical" value={stats.critical} icon="warn" tone="red" />
        <Stat label="SLA breached" value={stats.breached} icon="clock" tone={stats.breached ? 'red' : 'green'} />
        <Stat label="Resolved" value={stats.resolved} icon="check" tone="green" />
        <Stat label="Satisfaction" value={stats.avgSatisfaction || '—'} unit="/5" icon="badge" />
      </StatGrid>
      <div className="two">
        <Card title="Open requests" desc="Ordered by SLA deadline.">
          {open.length ? (
            <ul className="list">
              {open.slice(0, 8).map((t) => (
                <li key={t.id}>
                  <div><Link className="strong-link" to={`/support/requests/${t.id}`}>{t.subject}</Link><div className="muted sm">{t.no} · {catLabel(t.category)}</div></div>
                  <span className="grow" />
                  <Badge value={t.priority} />
                  <Badge value={isBreached(t) ? 'breached' : 'pending'} />
                </li>
              ))}
            </ul>
          ) : <Empty icon="check" title="No open requests" >Everything is resolved.</Empty>}
        </Card>
        <Card title="How support works" desc="Support is scoped to your institution.">
          <ul className="checklist">
            <li>Critical requests target a one-hour first response.</li>
            <li>High: 4 hours · Normal: 24 hours · Low: 72 hours.</li>
            <li>Requests can be escalated into a security incident.</li>
            <li>Every message and status change is audited server-side.</li>
          </ul>
          <div className="row wrap">
            <Link className="btn" to="/support/requests">All requests</Link>
            <Link className="btn" to="/support/diagnostics">Diagnostics</Link>
            <Link className="btn" to="/support/status">Service status</Link>
            <Link className="btn" to="/support/recovery">Recovery</Link>
          </div>
        </Card>
      </div>
      {creating && <RequestModal tenantId={tenantId} onClose={() => setCreating(false)} onDone={(m) => { flash.setMsg({ ok: true, text: m }); reload(); }} />}
    </Page>
  );
}

/* ------------------------------------------------------------------ list */
export function SupportRequestsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => listRequests(), []);
  const tickets = data || [];
  const users = useCol('users', false);
  const [creating, setCreating] = useState(false);
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const rows = useMemo(() => tickets.filter((t) => !tenantId || t.tenantId === tenantId).sort((a, b) => b.createdAt - a.createdAt), [tickets, tenantId]);
  const stats = supportStats(rows);
  const assignees = users.filter((u) => !u.tenantId || u.tenantId === tenantId || !tenantId);

  return (
    <Page title="Requests" desc="Support tickets and their lifecycle."
      actions={perms('support.manage') ? <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New request</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      {error && <Alert tone="danger" title="Could not load requests">{String(error.message || error)}</Alert>}
      {loading && <Loading label="Loading requests…" />}
      <StatGrid cols={4}>
        <Stat label="Open" value={stats.open} icon="ticket" tone="amber" />
        <Stat label="Breached" value={stats.breached} icon="clock" tone={stats.breached ? 'red' : 'green'} />
        <Stat label="Resolved" value={stats.resolved} icon="check" tone="green" />
        <Stat label="Avg first response" value={stats.firstResponseMins} unit="min" icon="pulse" />
      </StatGrid>
      <DataTable
        title="Tickets" desc="Open a ticket to see the conversation and take action."
        rows={rows} search={(t) => `${t.no} ${t.subject} ${t.category} ${t.status} ${t.priority} ${t.assigneeName || t.assignee || ''}`}
        filters={[
          { key: 'status', label: 'Status', options: STATUSES.map((s) => ({ v: s, l: s })) },
          { key: 'priority', label: 'Priority', options: PRIORITIES },
          { key: 'category', label: 'Category', options: CATEGORIES },
        ]}
        defaultSort={{ key: 'createdAt', dir: 'desc' }}
        columns={[
          { key: 'no', label: 'Ref', render: (t) => <span className="mono">{t.no}</span> },
          { key: 'subject', label: 'Subject', render: (t) => <Link className="strong-link" to={`/support/requests/${t.id}`}>{t.subject}</Link> },
          { key: 'category', label: 'Category', render: (t) => catLabel(t.category) },
          { key: 'priority', label: 'Priority', render: (t) => <Badge value={t.priority} /> },
          { key: 'status', label: 'Status', render: (t) => <Badge value={t.status} /> },
          { key: 'assignee', label: 'Assignee', render: (t) => t.assigneeName || t.assignee || 'Unassigned' },
          { key: 'slaDue', label: 'SLA', sortable: true, render: (t) => <span className={isBreached(t) ? 'text-danger' : ''}>{slaText(t)}</span> },
          { key: 'createdAt', label: 'Created', sortable: true, render: (t) => ago(t.createdAt) },
        ]}
        actions={(t) => {
          const out = [{ label: 'Open', onClick: () => navigate(`/support/requests/${t.id}`) }];
          if (!perms('support.manage')) return out;
          if (isOpen(t)) {
            out.push({ label: 'Assign', onClick: () => setAct({ type: 'assign', row: t }) });
            out.push({ label: 'Set status', onClick: () => setAct({ type: 'status', row: t }) });
            out.push({ label: 'Escalate', danger: true, onClick: () => setAct({ type: 'escalate', row: t }) });
          }
          return out;
        }}
      />
      {creating && <RequestModal tenantId={tenantId} onClose={() => setCreating(false)} onDone={(m) => { flash.setMsg({ ok: true, text: m }); reload(); }} />}
      {act?.type === 'assign' && (
        <ActionDialog title="Assign request" desc={act.row.subject} confirmLabel="Assign" requireReason={false}
          field={{ label: 'Assignee', options: assignees.map((u) => ({ v: u.id, l: `${u.name || u.full_name || u.id} (${u.role})` })) }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(async () => { const m = await assignRequest(user, act.row, val); reload(); return m; })} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title="Set status" desc={act.row.subject} confirmLabel="Update" reasonLabel="Note (required to resolve)"
          field={{ label: 'Status', options: STATUSES, default: act.row.status }}
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(async () => { const m = await setStatus(user, act.row, val, reason); reload(); return m; })} />
      )}
      {act?.type === 'escalate' && (
        <ActionDialog title="Escalate to incident" desc={act.row.subject} danger confirmLabel="Escalate"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(async () => { const m = await escalateRequest(user, act.row, reason); reload(); return m; })} />
      )}
    </Page>
  );
}
/* ------------------------------------------------------------------ detail */
export function SupportRequestDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const { data: t, loading, error, reload } = useLoad(() => getRequest(id), [id]);
  const users = useCol('users', false);
  const [msgText, setMsgText] = useState('');
  const [internal, setInternal] = useState(false);
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const assignees = users.filter((u) => !t || !u.tenantId || u.tenantId === t.tenantId || t.tenantId === tenantId);

  if (error) return <Page title="Request"><Alert tone="danger" title="Could not load request">{String(error.message || error)}</Alert><Link className="btn" to="/support/requests">Back to requests</Link></Page>;
  if (loading || !t) return <Page title="Request"><Loading label="Loading request…" /></Page>;

  const send = async (e) => {
    e.preventDefault();
    if (msgText.trim().length < 2) return;
    await flash.run(async () => { await addMessage(user, t, msgText, internal); setMsgText(''); setInternal(false); reload(); return 'Message added.'; });
  };

  return (
    <Page title={t.subject} desc={`${t.no} · ${prioLabel(t.priority)} · ${t.status}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/support/requests">Requests</Link><Icon name="arrow" size={12} /><span>{t.no}</span></div>}
      actions={perms('support.manage') ? <>
        {isOpen(t) && <button className="btn" onClick={() => setAct({ type: 'assign' })}>Assign</button>}
        {isOpen(t) && <button className="btn" onClick={() => setAct({ type: 'status' })}>Set status</button>}
        {isOpen(t) && <button className="btn danger" onClick={() => setAct({ type: 'escalate' })}>Escalate</button>}
      </> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Status" value={t.status} icon="ticket" tone={isOpen(t) ? 'amber' : 'green'} />
        <Stat label="Priority" value={t.priority} icon="alert" tone={t.priority === 'critical' ? 'red' : 'blue'} />
        <Stat label="SLA" value={slaText(t)} icon="clock" tone={isBreached(t) ? 'red' : 'green'} />
        <Stat label="Satisfaction" value={t.satisfactionScore ? `${t.satisfactionScore}/5` : '—'} icon="badge" />
      </StatGrid>
      {isBreached(t) && <Alert tone="danger" title="SLA breached">No first response was recorded before the deadline.</Alert>}
      <div className="two">
        <Card title="Request details">
          <KeyValue cols={2} items={[
            ['Reference', <code key="r">{t.no}</code>],
            ['Category', catLabel(t.category)],
            ['Requester', t.requesterName],
            ['Assignee', t.assigneeName || t.assignee || 'Unassigned'],
            ['Created', fmt(t.createdAt)],
            ['SLA due', fmt(t.slaDue)],
            ['First response', t.firstResponseAt ? fmt(t.firstResponseAt) : 'Pending'],
            ['Resolved', t.resolvedAt ? fmt(t.resolvedAt) : '—'],
            ['Incident', t.incidentId || '—'],
            ['Device', t.linkedDeviceId || '—'],
          ]} />
        </Card>
        <Card title="Description" pad>
          <p className="preserve">{t.description}</p>
          {t.resolution && <Alert tone="success" title="Resolution">{t.resolution}</Alert>}
          {t.escalationReason && <Alert tone="warn" title="Escalation">{t.escalationReason}</Alert>}
          {t.recovery && <Alert tone="info" title={`Recovery · ${t.recovery.kind}`}>{`Target: ${t.recovery.target} · State: ${t.recovery.state}${t.recovery.approvalId ? ` · Approval: ${t.recovery.approvalId}` : ''}`}</Alert>}
        </Card>
      </div>
      <Card title="Conversation" desc="Internal notes are visible only to support staff (enforced server-side).">
        {t.messages?.length ? (
          <Timeline items={t.messages.map((m) => ({
            id: m.id, title: `${m.authorName || m.by}${m.internal ? ' · internal' : ''}`, meta: fmt(m.at), body: m.text,
            tone: m.internal ? 'a' : '',
          }))} />
        ) : <Empty icon="ticket" title="No messages yet" />}
        {perms('support.manage') && (
          <form onSubmit={send} className="message-form">
            <Field label="Reply"><Textarea rows={3} value={msgText} onChange={(e) => setMsgText(e.target.value)} maxLength={4000} placeholder="Write a reply…" /></Field>
            <div className="row">
              <label className="check"><input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} /><span>Internal note</span></label>
              <span className="grow" />
              <button className="btn primary" disabled={flash.busy || msgText.trim().length < 2}>{flash.busy ? 'Sending…' : 'Send'}</button>
            </div>
          </form>
        )}
      </Card>
      {t.events?.length > 0 && (
        <Card title="Audit timeline" desc="Append-only server-side event history.">
          <Timeline items={t.events.map((e) => ({ id: e.at, title: e.event, meta: fmt(e.at), body: e.detail }))} />
        </Card>
      )}
      {t.status === 'resolved' && !t.satisfactionScore && (
        <Card title="Rate support" desc="Your feedback helps improve response quality.">
          <button className="btn" onClick={() => setAct({ type: 'rate' })}>Rate this request</button>
        </Card>
      )}

      {act?.type === 'assign' && (
        <ActionDialog title="Assign request" desc={t.no} confirmLabel="Assign" requireReason={false}
          field={{ label: 'Assignee', options: assignees.map((u) => ({ v: u.id, l: `${u.name || u.full_name || u.id} (${u.role})` })) }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(async () => { const m = await assignRequest(user, t, val); reload(); return m; })} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title="Set status" desc={t.no} confirmLabel="Update" reasonLabel="Note (required to resolve)"
          field={{ label: 'Status', options: STATUSES, default: t.status }}
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(async () => { const m = await setStatus(user, t, val, reason); reload(); return m; })} />
      )}
      {act?.type === 'escalate' && (
        <ActionDialog title="Escalate to incident" desc={t.no} danger confirmLabel="Escalate"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(async () => { const m = await escalateRequest(user, t, reason); reload(); return m; })} />
      )}
      {act?.type === 'rate' && (
        <ActionDialog title="Rate support" desc={t.no} confirmLabel="Submit rating" requireReason={false}
          field={{ label: 'Score (1–5)', type: 'number', default: '5' }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(async () => { const m = await rateRequest(user, t, val); reload(); return m; })} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ diagnostics */
export function DiagnosticsPage() {
  const { data: diag, loading, error, reload } = useLoad(() => runDiagnostics(), []);

  const checks = diag?.checks || [];
  const warn = checks.filter((c) => c.status === 'WARN').length;
  const fail = checks.filter((c) => c.status === 'FAIL').length;

  return (
    <Page title="Diagnostics" desc="Live, read-only health checks executed against PostgreSQL by the backend."
      actions={<>
        {diag && <button className="btn" onClick={() => downloadJson(`examos-diagnostics-${Date.now()}.json`, diag)}><Icon name="download" size={15} /> Download JSON</button>}
        <button className="btn primary" onClick={reload} disabled={loading}><Icon name="refresh" size={15} /> Re-run</button>
      </>}>
      {error && <Alert tone="danger" title="Diagnostics failed">{String(error.message || error)}</Alert>}
      {loading || !diag ? <Loading label="Collecting diagnostics…" /> : (
        <>
          <StatGrid cols={5}>
            <Stat label="Database" value={diag.database ? 'Healthy' : 'Unavailable'} icon="server" tone={diag.database ? 'green' : 'red'} />
            <Stat label="Checks" value={checks.length} icon="check" />
            <Stat label="Warnings" value={warn} icon="alert" tone={warn ? 'amber' : 'green'} />
            <Stat label="Failures" value={fail} icon="warn" tone={fail ? 'red' : 'green'} />
            <Stat label="Mode" value="Read-only" icon="shield" tone="blue" />
          </StatGrid>
          <Card title="Checks" desc={diag.note || ''}>
            <DataTable rows={checks} dense search={(c) => `${c.key} ${c.label} ${c.status} ${c.detail}`} columns={[
              { key: 'label', label: 'Check' },
              { key: 'status', label: 'Result', render: (c) => <Badge value={c.status} /> },
              { key: 'detail', label: 'Detail' },
            ]} empty={<Empty icon="check" title="No checks available" />} />
          </Card>
        </>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ status */
export function StatusPage() {
  const services = useCol('services', false);
  const { data: overview, loading, error, reload } = useLoad(() => statusOverview(), [services.length]);

  return (
    <Page title="Service status" desc="Current status of platform services and recent alerts."
      actions={<button className="btn" onClick={reload} disabled={loading}><Icon name="refresh" size={15} /> Refresh</button>}>
      {error && <Alert tone="danger" title="Could not load status">{String(error.message || error)}</Alert>}
      {loading || !overview ? <Loading label="Loading status…" /> : (
        <>
          <Alert tone={overview.overall === 'operational' ? 'success' : overview.overall === 'outage' ? 'danger' : 'warn'}
            title={`Overall: ${overview.overall}`}>
            {overview.services} services · {overview.down} down · {overview.degraded} degraded · {overview.alerts} open alerts
            {` · database ${overview.database || 'unknown'}`}
          </Alert>
          <StatGrid cols={4}>
            <Stat label="Services" value={overview.services} icon="server" />
            <Stat label="Down" value={overview.down} icon="warn" tone={overview.down ? 'red' : 'green'} />
            <Stat label="Degraded" value={overview.degraded} icon="alert" tone={overview.degraded ? 'amber' : 'green'} />
            <Stat label="Uptime" value={overview.uptime === 'insufficient-data' ? 'N/A' : overview.uptime} icon="clock" tone="blue" />
          </StatGrid>
          {overview.uptime === 'insufficient-data' && <Alert tone="info" title="Uptime unavailable">No monitoring history is configured, so uptime cannot be reported. Current status reflects live service records and a database health check only — no figure is fabricated.</Alert>}
          <DataTable
            title="Services" desc={overview.regions?.length ? `Regions: ${overview.regions.join(', ')}` : 'Platform services'}
            rows={services} search={(s) => `${s.name} ${s.status} ${s.region || ''}`}
            filters={[{ key: 'status', label: 'Status', options: ['healthy', 'degraded', 'down', 'maintenance'].map((s) => ({ v: s, l: s })) }]}
            columns={[
              { key: 'name', label: 'Service', render: (s) => <b>{s.name}</b> },
              { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} /> },
              { key: 'region', label: 'Region', render: (s) => s.region || '—' },
              { key: 'latencyMs', label: 'Latency', render: (s) => (s.latencyMs ? `${s.latencyMs} ms` : '—') },
              { key: 'uptime', label: 'Uptime', render: (s) => (s.uptime ? `${s.uptime}%` : '—') },
              { key: 'lastCheck', label: 'Last check', sortable: true, render: (s) => (s.lastCheck ? ago(s.lastCheck) : '—') },
            ]}
            empty={<Empty icon="server" title="No services reported" />}
          />
        </>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ recovery */
export function RecoveryPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const { data, loading, error, reload } = useLoad(() => listRecovery(), []);
  const recovery = data || [];
  const [v, setV] = useState({ kind: 'account-access', target: '', reason: '' });
  const flash = useFlash();
  const perms = usePerm();

  const submit = async (e) => {
    e.preventDefault();
    await flash.run(async () => { const m = await initiateRecovery(user, { tenantId, ...v }); setV({ kind: 'account-access', target: '', reason: '' }); reload(); return m; });
  };

  return (
    <Page title="Recovery" desc="Gated account, device, USB and exam-session recovery. High-risk cases require centralized approval.">
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <div className="two">
        <Card title="Initiate recovery" desc="Recovery opens a support case and creates an approval request.">
          {perms('support.manage') ? (
            <form onSubmit={submit} className="formgrid">
              <Field label="Scenario" required className="span2">
                <Select value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })} options={[
                  { v: 'account-access', l: 'Account access (lost MFA / lockout)' },
                  { v: 'device-trust', l: 'Device trust (re-attest / reauthorise)' },
                  { v: 'usb-custody', l: 'USB custody (lost / damaged media)' },
                  { v: 'exam-session', l: 'Exam session (interrupted delivery)' },
                  { v: 'data-restore', l: 'Data restore (retention / backup)' },
                ]} placeholder={false} />
              </Field>
              <Field label="Target" required className="span2" help="Username, email, device id or USB asset id.">
                <Input value={v.target} onChange={(e) => setV({ ...v, target: e.target.value })} maxLength={80} />
              </Field>
              <Field label="Reason" required className="span2"><Textarea rows={3} value={v.reason} onChange={(e) => setV({ ...v, reason: e.target.value })} maxLength={300} /></Field>
              <div className="span2"><button className="btn primary" disabled={flash.busy || !v.target.trim() || v.reason.trim().length < 10}>{flash.busy ? 'Opening…' : 'Open recovery case'}</button></div>
            </form>
          ) : <Alert tone="info" title="No permission">Your role cannot open recovery cases. Ask support staff for help.</Alert>}
        </Card>
        <Card title="Recovery safeguards" desc="What protects these operations.">
          <ul className="checklist">
            <li>Every recovery case is linked to a support ticket and audited server-side.</li>
            <li>High-risk recovery creates a centralized approval request (policy: support-recovery).</li>
            <li>Requester and approver are separate; the approver is not the requester.</li>
            <li>Execution requires the approval to be granted and re-validates authorization.</li>
            <li>Device recovery never modifies disk, EFI, firmware, TPM or Secure Boot.</li>
          </ul>
        </Card>
      </div>
      {error && <Alert tone="danger" title="Could not load recovery cases">{String(error.message || error)}</Alert>}
      {loading && <Loading label="Loading recovery cases…" />}
      <DataTable
        title="Recovery cases" desc="Newest first."
        rows={recovery} search={(t) => `${t.no} ${t.subject} ${t.recovery?.kind} ${t.recovery?.state}`}
        columns={[
          { key: 'no', label: 'Ref', render: (t) => <Link className="mono strong-link" to={`/support/requests/${t.id}`}>{t.no}</Link> },
          { key: 'kind', label: 'Scenario', render: (t) => <Badge value={t.recovery?.kind} /> },
          { key: 'target', label: 'Target', render: (t) => <span className="mono sm">{t.recovery?.target}</span> },
          { key: 'state', label: 'State', render: (t) => <Badge value={t.recovery?.state} /> },
          { key: 'status', label: 'Ticket', render: (t) => <Badge value={t.status} /> },
          { key: 'createdAt', label: 'Opened', sortable: true, render: (t) => fmt(t.createdAt) },
        ]}
        empty={<Empty icon="recover" title="No recovery cases" />}
      />
    </Page>
  );
}
