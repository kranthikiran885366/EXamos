import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { usePerm } from '../../core/ui/hooks';
import { downloadJson } from '../../core/services/common';
import {
  REQUEST_TYPES, SUBJECT_TYPES, REQUEST_STATUSES, DATA_TYPES, RETENTION_ACTIONS, DATA_MAP,
  createPrivacyRequest, verifySubject, assignPrivacy, setPrivacyStatus, requestErasure,
  saveRetention, runRetention, deleteRetention, privacyStats, dataSubjectExport,
} from './service';

const typeLabel = (v) => REQUEST_TYPES.find((t) => t.v === v)?.l || v;
const subjectLabel = (v) => SUBJECT_TYPES.find((t) => t.v === v)?.l || v;
const dataLabel = (v) => DATA_TYPES.find((t) => t.v === v)?.l || v;

/* ------------------------------------------------------------------ request create */
function RequestModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ type: 'access', subjectType: 'candidate', subjectId: '', subjectName: '', details: '', dueDays: '30' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const r = await createPrivacyRequest(user, { tenantId, ...v }); onDone?.(`Request ${r.id} created.`); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal wide title="New data subject request" desc="Identity must be verified before any decision or data action." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="dsr-form" disabled={busy}>{busy ? 'Creating…' : 'Create request'}</button></>}>
      <form id="dsr-form" onSubmit={submit} className="formgrid">
        <Field label="Request type" required><Select value={v.type} onChange={(e) => setV({ ...v, type: e.target.value })} options={REQUEST_TYPES} placeholder={false} /></Field>
        <Field label="Subject type" required><Select value={v.subjectType} onChange={(e) => setV({ ...v, subjectType: e.target.value })} options={SUBJECT_TYPES} placeholder={false} /></Field>
        <Field label="Subject id" help="Candidate id, user id or device id."><Input value={v.subjectId} onChange={(e) => setV({ ...v, subjectId: e.target.value })} maxLength={60} /></Field>
        <Field label="Subject name" required><Input value={v.subjectName} onChange={(e) => setV({ ...v, subjectName: e.target.value })} maxLength={80} /></Field>
        <Field label="Details" required className="span2"><Textarea rows={4} value={v.details} onChange={(e) => setV({ ...v, details: e.target.value })} maxLength={2000} /></Field>
        <Field label="Respond within (days)" help="1–90 days. Default 30."><Input type="number" min="1" max="90" value={v.dueDays} onChange={(e) => setV({ ...v, dueDays: e.target.value })} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ privacy */
export function PrivacyPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const requests = useCol('privacy', false);
  const retention = useCol('retention', false);
  const users = useCol('users', false);
  const [tab, setTab] = useState('requests');
  const [creating, setCreating] = useState(false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => requests.filter((r) => r.tenantId === tenantId).sort((a, b) => b.receivedAt - a.receivedAt), [requests, tenantId]);
  const policies = retention.filter((r) => r.tenantId === tenantId);
  const stats = privacyStats(rows, policies);
  const assignees = users.filter((u) => u.tenantId === tenantId || !u.tenantId);

  const exportData = async (r) => {
    await flash.run(async () => {
      const data = await dataSubjectExport(user, r);
      downloadJson(`dsr-${r.id}.json`, data);
      return 'Export generated and downloaded.';
    });
  };

  return (
    <Page title="Privacy & governance" desc="Privacy notices, data subject requests and retention."
      actions={perms('privacy.manage') ? <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New request</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={5}>
        <Stat label="Requests" value={stats.total} icon="lock" />
        <Stat label="Open" value={stats.open} icon="clock" tone="amber" />
        <Stat label="Overdue" value={stats.overdue} icon="warn" tone={stats.overdue ? 'red' : 'green'} />
        <Stat label="Erasure" value={stats.erasure} icon="recover" tone="violet" />
        <Stat label="Retention policies" value={stats.policies} icon="policy" sub={stats.nextRun ? `next ${fmt(stats.nextRun)}` : 'none scheduled'} />
      </StatGrid>
      {stats.overdue > 0 && <Alert tone="danger" title={`${stats.overdue} request(s) are past their statutory due date`}>Escalate or complete them promptly; overdue requests are reported.</Alert>}
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'requests', label: 'Requests', count: rows.length },
        { key: 'map', label: 'Data map', count: DATA_MAP.length },
        { key: 'notices', label: 'Notices' },
      ]} />

      {tab === 'requests' && (
        <DataTable
          title="Data subject requests" desc="Verify identity before approving, rejecting or exporting."
          rows={rows} search={(r) => `${r.id} ${r.type} ${r.subjectType} ${r.subjectName} ${r.status}`}
          filters={[
            { key: 'status', label: 'Status', options: REQUEST_STATUSES.map((s) => ({ v: s, l: s })) },
            { key: 'type', label: 'Type', options: REQUEST_TYPES },
          ]}
          columns={[
            { key: 'id', label: 'Ref', render: (r) => <span className="mono sm">{r.id}</span> },
            { key: 'type', label: 'Type', render: (r) => <Badge value={typeLabel(r.type)} /> },
            { key: 'subjectName', label: 'Subject', render: (r) => <><b>{r.subjectName}</b><div className="muted sm">{subjectLabel(r.subjectType)}</div></> },
            { key: 'identityVerified', label: 'Identity', render: (r) => <Badge value={r.identityVerified ? 'verified' : 'pending'} /> },
            { key: 'status', label: 'Status', render: (r) => <Badge value={r.status} /> },
            { key: 'dueAt', label: 'Due', sortable: true, render: (r) => <span className={r.dueAt < Date.now() && !['fulfilled', 'closed', 'rejected'].includes(r.status) ? 'text-danger' : ''}>{fmt(r.dueAt)}</span> },
            { key: 'receivedAt', label: 'Received', sortable: true, render: (r) => ago(r.receivedAt) },
          ]}
          actions={(r) => {
            const out = [{ label: 'View', onClick: () => setView(r) }];
            if (!perms('privacy.manage')) return out;
            if (!r.identityVerified) out.push({ label: 'Verify subject', onClick: () => setAct({ type: 'verify', row: r }) });
            out.push({ label: 'Assign', onClick: () => setAct({ type: 'assign', row: r }) });
            out.push({ label: 'Set status', onClick: () => setAct({ type: 'status', row: r }) });
            if (['erasure', 'rectification', 'restriction'].includes(r.type) && r.identityVerified && !r.approvalId) {
              out.push({ label: 'Request action', danger: true, onClick: () => setAct({ type: 'erasure', row: r }) });
            }
            if (['access', 'portability'].includes(r.type)) out.push({ label: 'Export', onClick: () => exportData(r) });
            return out;
          }}
        />
      )}

      {tab === 'map' && (
        <DataTable
          title="Data map" desc="What personal data is processed, why, and for how long."
          rows={DATA_MAP.map((d, i) => ({ id: `dm-${i}`, ...d }))}
          search={(d) => `${d.category} ${d.fields} ${d.purpose} ${d.basis}`}
          columns={[
            { key: 'category', label: 'Category', render: (d) => <b>{d.category}</b> },
            { key: 'fields', label: 'Fields', render: (d) => <span className="muted sm">{d.fields}</span> },
            { key: 'purpose', label: 'Purpose', render: (d) => <span className="muted sm">{d.purpose}</span> },
            { key: 'basis', label: 'Lawful basis' },
            { key: 'retention', label: 'Retention' },
          ]}
        />
      )}

      {tab === 'notices' && (
        <div className="two">
          <Card title="Privacy notice" pad>
            <p>ExamOS processes candidate identity, exam delivery, device trust, security, support and billing data to deliver examinations securely. Data is retained according to the retention policies below and is never sold.</p>
            <p>Data subjects may request access, correction, portability, restriction, objection or erasure. Identity is verified before any action. Erasure is approval-gated and cannot override statutory retention for audit records.</p>
            <p className="muted sm">This notice is a template. Your institution must publish its own notice with local legal details.</p>
          </Card>
          <Card title="Governance controls" pad>
            <ul className="checklist">
              <li>Two-person approval for erasure and restriction actions.</li>
              <li>Audit trail is immutable and excluded from retention deletion.</li>
              <li>Exports are logged and downloaded as JSON.</li>
              <li>Retention runs support dry-run before applying.</li>
              <li>Overdue requests are surfaced on this page.</li>
            </ul>
            <Link className="btn" to="/admin/retention">Manage retention</Link>
          </Card>
        </div>
      )}

      {creating && <RequestModal tenantId={tenantId} onClose={() => setCreating(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {view && (
        <Modal wide title={`${typeLabel(view.type)} · ${view.subjectName}`} desc={view.id} onClose={() => setView(null)}
          footer={<>
            {['access', 'portability'].includes(view.type) && perms('privacy.manage') && <button className="btn" onClick={() => exportData(view)}>Export data</button>}
            <button className="btn primary" onClick={() => setView(null)}>Close</button>
          </>}>
          <KeyValue cols={2} items={[
            ['Type', typeLabel(view.type)], ['Subject', `${view.subjectName} (${subjectLabel(view.subjectType)})`],
            ['Status', <Badge key="s" value={view.status} />], ['Identity', <Badge key="i" value={view.identityVerified ? 'verified' : 'pending'} />],
            ['Received', fmt(view.receivedAt)], ['Due', fmt(view.dueAt)],
            ['Assigned to', view.assignedTo || 'Unassigned'], ['Approval', view.approvalId || '—'],
            ['Completed', view.completedAt ? fmt(view.completedAt) : '—'],
          ]} />
          <Field label="Details"><p className="preserve">{view.details}</p></Field>
          {view.decisionNote && <Alert tone="info" title="Decision note">{view.decisionNote}</Alert>}
          <h4>History</h4>
          {view.history?.length ? <Timeline items={view.history.map((h) => ({ id: String(h.at), title: h.action, meta: `${h.by} · ${fmt(h.at)}`, body: h.note }))} /> : <Empty icon="history" title="No history" />}
        </Modal>
      )}

      {act?.type === 'verify' && (
        <ActionDialog title="Verify data subject identity" desc={act.row.subjectName} confirmLabel="Verify" requireReason={false}
          field={{ label: 'Verification note', type: 'textarea' }} onClose={() => setAct(null)}
          onConfirm={(_r, val) => flash.run(() => verifySubject(user, act.row, val))} />
      )}
      {act?.type === 'assign' && (
        <ActionDialog title="Assign request" desc={act.row.subjectName} confirmLabel="Assign" requireReason={false}
          field={{ label: 'Assignee', options: assignees.map((u) => ({ v: u.id, l: `${u.name} (${u.role})` })) }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(() => assignPrivacy(user, act.row, val))} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title="Set request status" desc={act.row.subjectName} confirmLabel="Update" reasonLabel="Decision note (required to reject)"
          field={{ label: 'Status', options: REQUEST_STATUSES.map((s) => ({ v: s, l: s })), default: act.row.status }}
          onClose={() => setAct(null)} onConfirm={(note, val) => flash.run(() => setPrivacyStatus(user, act.row, val, note))} />
      )}
      {act?.type === 'erasure' && (
        <ActionDialog title="Request data action" desc="Erasure, rectification and restriction require a second approver." danger confirmLabel="Request approval"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => requestErasure(user, act.row, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ retention */
function RetentionModal({ tenantId, policy, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({
    dataType: policy?.dataType || 'candidates', retentionDays: String(policy?.retentionDays || 365),
    action: policy?.action || 'delete', legalBasis: policy?.legalBasis || '',
  });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const m = await saveRetention(user, { id: policy?.id, tenantId, ...v }); onDone?.(m); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title={policy ? 'Edit retention policy' : 'Set retention policy'} desc="Audit records are immutable and cannot be targeted." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="retention-form" disabled={busy}>{busy ? 'Saving…' : 'Save policy'}</button></>}>
      <form id="retention-form" onSubmit={submit} className="formgrid">
        <Field label="Data type" required>
          <Select value={v.dataType} onChange={(e) => setV({ ...v, dataType: e.target.value })} options={DATA_TYPES.filter((d) => d.v !== 'audit')} placeholder={false} />
        </Field>
        <Field label="Retention (days)" required help="30–3,650 days."><Input type="number" min="30" max="3650" value={v.retentionDays} onChange={(e) => setV({ ...v, retentionDays: e.target.value })} /></Field>
        <Field label="Action" required><Select value={v.action} onChange={(e) => setV({ ...v, action: e.target.value })} options={RETENTION_ACTIONS.map((a) => ({ v: a, l: a }))} placeholder={false} /></Field>
        <Field label="Legal basis" className="span2"><Input value={v.legalBasis} onChange={(e) => setV({ ...v, legalBasis: e.target.value })} maxLength={200} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function RetentionPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const retention = useCol('retention', false);
  const [modal, setModal] = useState(null); // { policy } | 'new'
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const rows = retention.filter((r) => r.tenantId === tenantId);
  const active = rows.filter((r) => r.status === 'active');
  const next = active.sort((a, b) => (a.nextRunAt || 0) - (b.nextRunAt || 0))[0];

  return (
    <Page title="Retention" desc="Data retention periods and deletion workflows, with dry-run before applying."
      actions={perms('privacy.manage') ? <button className="btn primary" onClick={() => setModal('new')}><Icon name="plus" size={15} /> Set retention</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Policies" value={rows.length} icon="policy" />
        <Stat label="Active" value={active.length} icon="check" tone="green" />
        <Stat label="Retired" value={rows.filter((r) => r.status === 'retired').length} icon="history" />
        <Stat label="Next run" value={next ? fmt(next.nextRunAt) : '—'} icon="clock" sub={next?.dataType} />
      </StatGrid>
      <DataTable
        title="Retention policies" desc="Run a dry run first; applying is audited."
        rows={rows} search={(r) => `${r.dataType} ${r.status} ${r.retentionDays} ${r.action}`}
        filters={[{ key: 'status', label: 'Status', options: ['active', 'retired'].map((s) => ({ v: s, l: s })) }]}
        columns={[
          { key: 'dataType', label: 'Data type', render: (r) => <b>{dataLabel(r.dataType)}</b> },
          { key: 'retentionDays', label: 'Retention', sortable: true, render: (r) => `${r.retentionDays} days` },
          { key: 'action', label: 'Action', render: (r) => <Badge value={r.action} /> },
          { key: 'legalBasis', label: 'Legal basis', render: (r) => <span className="muted sm">{r.legalBasis || '—'}</span> },
          { key: 'status', label: 'Status', render: (r) => <Badge value={r.status} /> },
          { key: 'lastRunAt', label: 'Last run', render: (r) => (r.lastRunAt ? `${fmt(r.lastRunAt)} (${r.lastCount ?? 0})` : 'Never') },
          { key: 'nextRunAt', label: 'Next run', sortable: true, render: (r) => fmt(r.nextRunAt) },
        ]}
        actions={(r) => [
          ...(perms('privacy.manage') && r.status === 'active' ? [
            { label: 'Dry run', onClick: () => flash.run(() => runRetention(user, r, true)) },
            { label: 'Run now', danger: true, onClick: () => setAct({ type: 'run', row: r }) },
            { label: 'Edit', onClick: () => setModal(r) },
            { label: 'Retire', danger: true, onClick: () => setAct({ type: 'retire', row: r }) },
          ] : []),
        ]}
      />
      {modal && <RetentionModal tenantId={tenantId} policy={modal === 'new' ? null : modal} onClose={() => setModal(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act?.type === 'run' && (
        <ActionDialog title="Apply retention now" desc={`${dataLabel(act.row.dataType)} · ${act.row.action} records older than ${act.row.retentionDays} days.`} danger
          confirmLabel="Apply retention" typed="APPLY"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => runRetention(user, { ...act.row, ...{} }, false))} />
      )}
      {act?.type === 'retire' && (
        <ActionDialog title="Retire retention policy" desc={dataLabel(act.row.dataType)} danger confirmLabel="Retire"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => deleteRetention(user, act.row, reason))} />
      )}
    </Page>
  );
}
