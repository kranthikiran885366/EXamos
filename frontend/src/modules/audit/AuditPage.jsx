import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { can } from '../../core/security/rbac';
import { csvCell } from '../../core/security/sanitize';
import { record, verifyChain } from '../../core/security/auditChain';
import { fmt, ago } from '../../core/ui/format';
import { normalizeAuditEvents } from '../../core/ui/normalizers';
import * as Api from '../../core/api/services';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, Flash, useFlash,
  KeyValue, Modal, Icon,
} from '../../core/ui/kit';

const eventLabel = (e) => String(e || '').replace(/_/g, ' ');
const EVENT_TONE = (e) => {
  const s = String(e || '').toUpperCase();
  if (/(FAIL|DENY|DENIED|BREACH|TAMPER|REVOKE|DELETE|TERMINATE|LOCK)/.test(s)) return 'r';
  if (/(WARN|REVIEW|PENDING|REQUEST|ROLLBACK|ROTATE|RESET)/.test(s)) return 'a';
  if (/(LOGIN|SUCCESS|CREATE|PUBLISH|APPROVE|SUBMIT|PAID|VERIFY|SEAL)/.test(s)) return 'g';
  return 'n';
};

export default function AuditPage() {
  const { user } = useAuth();
  const canReadPlatformAudit = ['superadmin', 'auditor'].includes(user.role);
  const flash = useFlash();
  const [check, setCheck] = useState(null);
  const [checking, setChecking] = useState(true);
  const [view, setView] = useState(null);
  const [serverEvents, setServerEvents] = useState([]);
  const [serverError, setServerError] = useState('');

  useEffect(() => {
    let live = true;
    if (!canReadPlatformAudit) {
      setChecking(false);
      setServerError('Platform-wide audit events are not available to this role.');
      return () => { live = false; };
    }
    verifyChain().then((r) => { if (live) { setCheck(r); setChecking(false); } }).catch((e) => { if (live) { setCheck({ ok: false, error: e.message }); setChecking(false); } });
    Api.listAuditTrail({ limit: 500 }).then((res) => {
      if (!live) return;
      setServerEvents(normalizeAuditEvents(res));
    }).catch((error) => { if (live) setServerError(error?.message || 'Could not load server audit events.'); });
    return () => { live = false; };
  }, [canReadPlatformAudit, user.role]);

  // A browser-side audit queue is not evidence. This page reports only the
  // server event API; ledger verification remains a separately labelled scope.
  const rows = serverEvents;

  const sorted = useMemo(() => [...rows].sort((a, b) => Date.parse(b.recordedAt) - Date.parse(a.recordedAt)), [rows]);
  const actors = useMemo(() => [...new Set(rows.map((e) => e.actor).filter(Boolean))].sort(), [rows]);
  const events = useMemo(() => [...new Set(rows.map((e) => e.event).filter(Boolean))].sort(), [rows]);
  const last = sorted[0];

  const verify = () => flash.run(async () => {
    const r = await verifyChain();
    setCheck(r);
    if (!r.ok) throw new Error(r.status === 'TAMPERED'
      ? 'The global server ledger reports an integrity failure.'
      : 'The global server ledger could not be verified.');
    return `Global server ledger intact — ${r.count} blocks verified.`;
  }, 'Chain verified.');

  const exportCsv = () => {
    const cols = ['recordedAt', 'actor', 'event', 'subjectType', 'subjectId', 'detail'];
    const csv = [cols, ...sorted.map((e) => cols.map((c) => e[c]))]
      .map((r) => r.map(csvCell).join(',')).join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url; a.download = `examos-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    record(user.id, 'EXPORT_AUDIT', `rows=${sorted.length}`);
    flash.setMsg({ ok: true, text: `Exported ${sorted.length} returned audit records to CSV.` });
  };

  return <Page
    title="Audit trail"
    desc="Platform-wide administrative events and the global server ledger are separate evidence scopes; ledger verification does not certify the event list."
    wide
    actions={<>
      <button className="btn" onClick={exportCsv} disabled={!canReadPlatformAudit || !can(user.role, 'export') || !sorted.length} title={can(user.role, 'export') ? '' : 'Your role cannot export audit data'}><Icon name="download" size={14} /> Export CSV</button>
      <button className="btn primary" onClick={verify} disabled={!canReadPlatformAudit || flash.busy || checking}><Icon name="shield" size={14} /> {flash.busy ? 'Verifying…' : 'Verify chain'}</button>
    </>}
  >
    <StatGrid cols={4}>
      <Stat label="Audit records returned" value={rows.length} icon="history" tone="blue" sub="Platform-wide event source; maximum 500" />
      <Stat label="Global ledger state" value={checking ? 'Checking…' : check?.ok ? 'Intact' : check?.status === 'TAMPERED' ? 'Tampered' : 'Unavailable'} icon={check?.status === 'TAMPERED' ? 'warn' : 'shield'} tone={checking ? 'blue' : check?.ok ? 'green' : 'red'} sub={check?.ok ? `${check.count} ledger blocks verified` : check?.error || 'Verification unavailable'} />
      <Stat label="Actors" value={actors.length} icon="users" tone="violet" sub="Distinct identities" />
      <Stat label="Last returned event" value={last ? ago(Date.parse(last.recordedAt)) : '—'} icon="clock" tone="amber" sub={last ? eventLabel(last.event) : 'No events returned'} />
    </StatGrid>

    <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />

    <Alert tone="info" title="Evidence scope">Event count, export, and rows are from the platform administrative-event endpoint. The independently verified ledger is a separate platform-wide store; no event-list row is represented as a ledger block.</Alert>
    {serverError && <Alert tone="danger" title="Server audit events unavailable">{serverError}</Alert>}

    {check?.status === 'TAMPERED' && <Alert tone="danger" title="Global ledger integrity failure">
      The server verifier reports that the global ledger is tampered. Preserve the evidence and investigate before relying on its contents.
    </Alert>}
    {check?.error && <Alert tone="warn" title="Verification could not complete">{check.error}</Alert>}

    <Card title="Global ledger verification" desc="This result comes from the ledger verifier and is not derived from the event-list rows.">
      <div className="two">
        <KeyValue cols={2} items={[
          ['Verification status', checking ? 'Checking' : check?.ok ? 'INTACT' : check?.status === 'TAMPERED' ? 'TAMPERED' : 'Unavailable'],
          ['Verified ledger blocks', check?.ok ? check.count : '—'],
          ['Event rows returned', rows.length],
          ['Event-list scope', 'Platform-wide administrative events; maximum 500 rows'],
        ]} />
        <div className="stack">
          <Alert tone={checking ? 'info' : check?.ok ? 'success' : check?.status === 'TAMPERED' ? 'danger' : 'warn'} title={checking ? 'Verifying global ledger' : check?.ok ? 'Ledger intact' : check?.status === 'TAMPERED' ? 'Ledger tampered' : 'Verification unavailable'}>
            {checking ? 'The server is checking the global ledger.' : check?.ok ? `${check.count} ledger blocks passed server verification.` : check?.error || 'The server did not confirm ledger integrity.'}
          </Alert>
          <p className="muted sm">The event endpoint does not return cryptographic chain fields. The CSV therefore contains only fields supplied by that event source.</p>
        </div>
      </div>
    </Card>

    <DataTable
      title="Event log"
      desc="Newest first from the authorized server audit endpoint. Select an entry to inspect the fields returned by that source."
      rows={sorted}
      search={(r) => `${r.actor} ${r.event} ${r.subjectType} ${r.subjectId} ${r.detail}`}
      onRow={setView}
      defaultSort={{ key: 'recordedAt', dir: 'desc' }}
      filters={[
        { key: 'actor', label: 'Actor', options: actors.map((a) => ({ v: a, l: a })) },
        { key: 'event', label: 'Event', options: events.slice(0, 80).map((e) => ({ v: e, l: e })) },
      ]}
      columns={[
        { key: 'recordedAt', label: 'Time', sortable: true, render: (e) => <span title={e.recordedAt}>{fmt(Date.parse(e.recordedAt))}</span> },
        { key: 'actor', label: 'Actor', mono: true, render: (e) => <span className="mono">{e.actor}</span> },
        { key: 'event', label: 'Event', render: (e) => <Badge value={eventLabel(e.event)} className={EVENT_TONE(e.event)} /> },
        { key: 'subjectType', label: 'Subject', render: (e) => <span>{e.subjectType || '—'}{e.subjectId ? ` · ${e.subjectId}` : ''}</span> },
        { key: 'detail', label: 'Detail', render: (e) => <span className="muted">{e.detail || '—'}</span> },
      ]}
      empty={<div className="empty"><b>No administrative events returned</b><p className="muted">This is an empty result from the authorized platform audit endpoint, not proof that other audit stores are empty.</p></div>}
    />

    {view && <Modal title={eventLabel(view.event)} desc="Platform administrative event. Its fields are not treated as a ledger block." onClose={() => setView(null)} wide
      footer={<button className="btn" onClick={() => setView(null)}>Close</button>}>
      <div className="stack">
        <div className="row"><Badge value={eventLabel(view.event)} className={EVENT_TONE(view.event)} /><span className="muted sm">{fmt(Date.parse(view.recordedAt))}</span></div>
        <KeyValue cols={2} items={[
          ['Timestamp', view.recordedAt],
          ['Actor', <code key="a" className="mono">{view.actor}</code>],
          ['Event', eventLabel(view.event)],
          ['Subject type', view.subjectType || '—'],
          ['Subject ID', view.subjectId || '—'],
          ['Detail', view.detail || '—'],
        ]} />
      </div>
    </Modal>}
  </Page>;
}
