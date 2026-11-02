import { useEffect, useMemo, useState } from 'react';
import { useCol } from '../../core/db/tenant';
import { useAuth } from '../../core/auth/AuthContext';
import { can } from '../../core/security/rbac';
import { csvCell } from '../../core/security/sanitize';
import { record, verifyChain } from '../../core/security/auditChain';
import { fmt, ago } from '../../core/ui/format';
import * as Api from '../../core/api/services';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, Flash, useFlash,
  KeyValue, Modal, CopyField, Icon,
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
  const rows = useCol('audit', false);
  const flash = useFlash();
  const [check, setCheck] = useState(null);
  const [checking, setChecking] = useState(true);
  const [view, setView] = useState(null);
  const [serverLedger, setServerLedger] = useState(null);

  useEffect(() => {
    let live = true;
    verifyChain().then((r) => { if (live) { setCheck(r); setChecking(false); } }).catch((e) => { if (live) { setCheck({ ok: false, error: e.message }); setChecking(false); } });
    Api.getLedger().then(setServerLedger).catch(() => {});
    return () => { live = false; };
  }, []);

  const sorted = useMemo(() => [...rows].sort((a, b) => b.seq - a.seq), [rows]);
  const actors = useMemo(() => [...new Set(rows.map((e) => e.actor).filter(Boolean))].sort(), [rows]);
  const events = useMemo(() => [...new Set(rows.map((e) => e.event).filter(Boolean))].sort(), [rows]);
  const last = sorted[0];

  const verify = () => flash.run(async () => {
    const r = await verifyChain();
    setCheck(r);
    if (!r.ok) throw new Error(`Tampering detected at entry #${r.at}. The stored chain no longer matches its hashes.`);
    return `Chain intact — ${r.count} entries verified against SHA-256 hashes.`;
  }, 'Chain verified.');

  const exportCsv = () => {
    const cols = ['seq', 'ts', 'actor', 'event', 'detail', 'prev', 'hash'];
    const csv = [cols, ...sorted.map((e) => cols.map((c) => e[c]))]
      .map((r) => r.map(csvCell).join(',')).join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url; a.download = `examos-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    record(user.id, 'EXPORT_AUDIT', `rows=${sorted.length}`);
    flash.setMsg({ ok: true, text: `Exported ${sorted.length} audit events to CSV. The export was itself audited.` });
  };

  return <Page
    title="Audit trail"
    desc="Every write is persisted in a SHA-256 hash chain. Verification re-reads the stored rows and recomputes each hash."
    wide
    actions={<>
      <button className="btn" onClick={exportCsv} disabled={!can(user.role, 'export') || !sorted.length} title={can(user.role, 'export') ? '' : 'Your role cannot export audit data'}><Icon name="download" size={14} /> Export CSV</button>
      <button className="btn primary" onClick={verify} disabled={flash.busy || checking}><Icon name="shield" size={14} /> {flash.busy ? 'Verifying…' : 'Verify chain'}</button>
    </>}
  >
    <StatGrid cols={4}>
      <Stat label="Audit events" value={rows.length} icon="history" tone="blue" sub="Persisted in IndexedDB" />
      <Stat label="Chain state" value={checking ? 'Checking…' : check?.ok ? 'Intact' : 'Broken'} icon={check?.ok === false ? 'warn' : 'shield'} tone={checking ? 'blue' : check?.ok ? 'green' : 'red'} sub={check?.ok ? `${check.count} entries verified` : check?.at ? `First mismatch at #${check.at}` : 'Not yet verified'} />
      <Stat label="Actors" value={actors.length} icon="users" tone="violet" sub="Distinct identities" />
      <Stat label="Last event" value={last ? ago(Date.parse(last.ts)) : '—'} icon="clock" tone="amber" sub={last ? eventLabel(last.event) : 'No events recorded'} />
    </StatGrid>

    <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />

    {check && !check.ok && !check.error && <Alert tone="danger" title="Audit chain integrity failure">
      Entry #{check.at} does not match its recorded hash. Treat the workspace as compromised and preserve a copy before making further changes.
    </Alert>}
    {check?.error && <Alert tone="warn" title="Verification could not complete">{check.error}</Alert>}

    <Card title="Chain details" desc="The head hash commits to every preceding entry.">
      <div className="two">
        <KeyValue cols={2} items={[
          ['Algorithm', 'SHA-256'],
          ['Genesis', 'GENESIS'],
          ['Entries', rows.length],
          ['Head sequence', last ? `#${last.seq}` : '—'],
          ['Head hash', last ? <code key="h" className="mono">{last.hash?.slice(0, 24)}…</code> : '—'],
          ['Last write', last ? fmt(Date.parse(last.ts)) : '—'],
        ]} />
        <div className="stack">
          <Alert tone={check?.ok ? 'success' : check?.ok === false ? 'danger' : 'info'} title={checking ? 'Verifying stored chain' : check?.ok ? 'Chain intact' : 'Verification failed'}>
            {checking ? 'Recomputing hashes from the persisted audit rows…' : check?.ok ? `All ${check.count} entries are linked correctly.` : check?.at ? `The chain diverges at entry #${check.at}.` : 'Run a verification to confirm integrity.'}
          </Alert>
          {last && <CopyField label="Latest hash" value={last.hash} />}
          <p className="muted sm">Exports include the previous hash for every row so an independent reviewer can recompute the chain.</p>
        </div>
      </div>
    </Card>

    <DataTable
      title="Event log"
      desc="Newest first. Select an entry to inspect its full hash and link."
      rows={sorted}
      search={(r) => `${r.seq} ${r.actor} ${r.event} ${r.detail} ${r.hash}`}
      onRow={setView}
      defaultSort={{ key: 'seq', dir: 'desc' }}
      filters={[
        { key: 'actor', label: 'Actor', options: actors.map((a) => ({ v: a, l: a })) },
        { key: 'event', label: 'Event', options: events.slice(0, 80).map((e) => ({ v: e, l: e })) },
      ]}
      columns={[
        { key: 'seq', label: '#', width: 72, sortable: true, mono: true },
        { key: 'ts', label: 'Time', sortable: true, render: (e) => <span title={e.ts}>{fmt(Date.parse(e.ts))}</span> },
        { key: 'actor', label: 'Actor', mono: true, render: (e) => <span className="mono">{e.actor}</span> },
        { key: 'event', label: 'Event', render: (e) => <Badge value={eventLabel(e.event)} className={EVENT_TONE(e.event)} /> },
        { key: 'detail', label: 'Detail', render: (e) => <span className="muted">{e.detail || '—'}</span> },
        { key: 'hash', label: 'Hash', render: (e) => <span className="mono muted" title={e.hash}>{e.hash ? `${e.hash.slice(0, 14)}…` : '—'}</span> },
      ]}
      empty={<div className="empty"><b>No audit events yet</b><p className="muted">Sign-in, configuration and lifecycle actions will appear here.</p></div>}
    />

    {view && <Modal title={`Audit entry #${view.seq}`} desc="Immutable record from the local hash chain." onClose={() => setView(null)} wide
      footer={<button className="btn" onClick={() => setView(null)}>Close</button>}>
      <div className="stack">
        <div className="row"><Badge value={eventLabel(view.event)} className={EVENT_TONE(view.event)} /><span className="muted sm">{fmt(Date.parse(view.ts))}</span></div>
        <KeyValue cols={2} items={[
          ['Sequence', `#${view.seq}`],
          ['Timestamp (UTC)', view.ts],
          ['Actor', <code key="a" className="mono">{view.actor}</code>],
          ['Event', eventLabel(view.event)],
          ['Detail', view.detail || '—'],
        ]} />
        <CopyField label="Previous hash" value={view.prev} />
        <CopyField label="Entry hash" value={view.hash} />
        <Alert tone="info">Altering any field changes the entry hash and breaks every later link, which is why the verifier reports the first divergence.</Alert>
      </div>
    </Modal>}
  </Page>;
}
