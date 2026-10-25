import { useMemo, useState } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { usePerm } from '../../core/ui/hooks';
import { useCol } from '../../core/db/tenant';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, KeyValue, Tabs, Progress, Modal, Field, Input, Select, Textarea,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import {
  acknowledgeAlert, resolveAlert, silenceAlert, raiseAlert, setServiceStatus, runJob,
  triggerBackup, testRestore, checkHealth, monitoringStats, SERVICE_STATUSES, ALERT_SEVERITIES,
  ALERT_STATUSES, JOB_SCHEDULES,
} from './service';

const SEV_TONE = { critical: 'red', high: 'amber', medium: 'blue', low: 'green' };

function RaiseAlertModal({ onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ title: '', severity: 'medium', source: 'console', detail: '', runbook: '' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => raiseAlert(user, v), 'Alert raised.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Raise alert" desc="Alerts appear in the operations feed and count against system health." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="alert-form" disabled={busy}>{busy ? 'Raising…' : 'Raise alert'}</button></>}>
      <form id="alert-form" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="Title" required><Input value={v.title} onChange={(e) => set('title', e.target.value)} maxLength={140} autoFocus /></Field>
        <div className="formgrid">
          <Field label="Severity"><Select value={v.severity} onChange={(e) => set('severity', e.target.value)} options={ALERT_SEVERITIES.map((s) => ({ v: s, l: s }))} placeholder={false} /></Field>
          <Field label="Source"><Input value={v.source} onChange={(e) => set('source', e.target.value)} maxLength={40} /></Field>
        </div>
        <Field label="Detail"><Textarea rows={3} value={v.detail} onChange={(e) => set('detail', e.target.value)} maxLength={500} /></Field>
        <Field label="Runbook"><Input value={v.runbook} onChange={(e) => set('runbook', e.target.value)} maxLength={300} placeholder="Link or short remediation steps" /></Field>
      </form>
    </Modal>
  );
}

export function MonitoringOverviewPage() {
  const { user } = useAuth();
  const may = usePerm();
  const services = useCol('services', false);
  const alerts = useCol('alerts', false);
  const jobs = useCol('jobs', false);
  const backups = useCol('backups', false);
  const { msg, setMsg, run, busy } = useFlash();
  const [tab, setTab] = useState('services');
  const [alertOpen, setAlertOpen] = useState(false);
  const stats = useMemo(() => monitoringStats(services, alerts, jobs, backups), [services, alerts, jobs, backups]);
  const openAlerts = alerts.filter((a) => a.status === 'open').sort((a, b) => b.at - a.at);
  const recentBackups = [...backups].sort((a, b) => b.at - a.at);

  return (
    <Page
      title="Platform monitoring"
      desc="Service health, heartbeats, scheduled jobs and recovery readiness across the workspace."
      actions={<>
        <button className="btn" disabled={busy || !may('monitor.view')} onClick={() => run(() => checkHealth(user), 'Health check complete.')}><Icon name="refresh" size={14} /> Run health check</button>
        <button className="btn primary" disabled={!may('monitor.view')} onClick={() => setAlertOpen(true)}><Icon name="bell" size={14} /> Raise alert</button>
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Services healthy" value={`${stats.healthy}/${stats.services}`} icon="server" tone={stats.down ? 'red' : stats.degraded ? 'amber' : 'green'} sub={`${stats.degraded} degraded · ${stats.down} down`} />
        <Stat label="Open alerts" value={stats.openAlerts} icon="bell" tone={stats.criticalAlerts ? 'red' : stats.openAlerts ? 'amber' : 'green'} sub={`${stats.criticalAlerts} critical`} />
        <Stat label="Average latency" value={stats.avgLatency} unit="ms" icon="pulse" sub={`p95 ${stats.p95} ms`} />
        <Stat label="Last backup" value={stats.lastBackup ? ago(stats.lastBackup.at) : 'Never'} icon="history" tone={stats.lastBackup ? 'green' : 'red'} sub={stats.lastBackup ? `${stats.lastBackup.sizeMb} MB` : 'No backup recorded'} />
      </StatGrid>

      {stats.criticalAlerts > 0 && <Alert tone="danger" title={`${stats.criticalAlerts} critical alert(s) open`}>Acknowledge or resolve critical alerts before the next exam window.</Alert>}
      {!stats.lastBackup && <Alert tone="warn" title="No backup has been taken">Trigger an encrypted backup and record a restore test.</Alert>}

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'services', label: 'Services', count: services.length },
        { key: 'alerts', label: 'Alerts', count: openAlerts.length },
        { key: 'jobs', label: 'Jobs', count: jobs.length },
        { key: 'backups', label: 'Backups', count: backups.length },
      ]} />

      {tab === 'services' && <Card title="Service health" actions={<a className="btn" href="/monitoring/services">Manage services</a>}>
        <DataTable rows={services} search={['name', 'status', 'version']} columns={[
          { label: 'Service', key: 'name' }, { label: 'Kind', key: 'kind' },
          { label: 'Status', key: 'status', badge: true },
          { label: 'Latency', render: (s) => `${s.latencyMs || 0} ms` },
          { label: 'Uptime', render: (s) => s.uptime || '—' },
          { label: 'Last heartbeat', render: (s) => <span title={fmt(s.lastHeartbeat || s.lastCheckAt)}>{ago(s.lastHeartbeat || s.lastCheckAt)}</span> },
        ]} empty={<Empty icon="server" title="No services registered" />} />
      </Card>}

      {tab === 'alerts' && <Card title="Open alerts" actions={<a className="btn" href="/monitoring/alerts">Alert queue</a>}>
        <DataTable rows={openAlerts} columns={[
          { label: 'Severity', key: 'severity', badge: true },
          { label: 'Alert', render: (a) => <><b>{a.title}</b><br /><small className="muted">{a.detail || a.runbook || a.source}</small></> },
          { label: 'Source', key: 'source' },
          { label: 'Raised', render: (a) => <span title={fmt(a.at)}>{ago(a.at)}</span> },
          { label: 'Status', key: 'status', badge: true },
        ]} actions={(a) => [
          { label: 'Acknowledge', disabled: !may('monitor.view'), onClick: () => run(() => acknowledgeAlert(user, a), 'Alert acknowledged.') },
          { label: 'Resolve', disabled: !may('monitor.view'), onClick: () => run(() => resolveAlert(user, a, 'Resolved from monitoring overview'), 'Alert resolved.') },
        ]} empty={<Empty icon="bell" title="No open alerts" />} />
      </Card>}

      {tab === 'jobs' && <Card title="Scheduled jobs">
        <DataTable rows={jobs} columns={[
          { label: 'Job', key: 'name' }, { label: 'Schedule', key: 'schedule' },
          { label: 'Status', key: 'status', badge: true },
          { label: 'Last run', render: (j) => j.lastRun ? <span title={fmt(j.lastRun)}>{ago(j.lastRun)}</span> : 'Never' },
          { label: 'Duration', render: (j) => j.lastDurationMs ? `${j.lastDurationMs} ms` : '—' },
          { label: 'Result', render: (j) => j.result || '—' },
        ]} actions={(j) => [
          { label: 'Run now', disabled: !may('monitor.view') || j.status === 'running', onClick: () => run(() => runJob(user, j), 'Job completed.') },
        ]} empty={<Empty icon="clock" title="No scheduled jobs" />} />
      </Card>}

      {tab === 'backups' && <Card title="Backups & restore tests" actions={<button className="btn primary" disabled={busy || !may('monitor.view')} onClick={() => run(() => triggerBackup(user, { scope: 'full', note: 'Manual backup from monitoring' }), 'Backup complete.')}>Take backup</button>}>
        <DataTable rows={recentBackups} columns={[
          { label: 'Taken', render: (b) => <span title={fmt(b.at)}>{ago(b.at)}</span> },
          { label: 'Scope', key: 'scope' }, { label: 'Status', key: 'status', badge: true },
          { label: 'Size', render: (b) => `${b.sizeMb} MB` },
          { label: 'Hash', render: (b) => <code title={b.hash}>{b.hash?.slice(0, 12)}…</code> },
          { label: 'Restore tested', render: (b) => b.restoreTestedAt ? <span title={fmt(b.restoreTestedAt)}>{ago(b.restoreTestedAt)}</span> : <Badge value="not run" /> },
        ]} actions={(b) => [
          { label: 'Test restore', disabled: !may('monitor.view'), onClick: () => run(() => testRestore(user, b), 'Restore test complete.') },
        ]} empty={<Empty icon="history" title="No backups yet">Take an encrypted backup to make restore testing possible.</Empty>} />
      </Card>}

      {alertOpen && <RaiseAlertModal onClose={() => setAlertOpen(false)} onDone={() => {}} />}
    </Page>
  );
}

export function ServicesPage() {
  const { user } = useAuth();
  const may = usePerm();
  const services = useCol('services', false);
  const { msg, setMsg, run, busy } = useFlash();
  const [pending, setPending] = useState(null);
  const [raise, setRaise] = useState(false);

  return (
    <Page title="Services" desc="Individual platform components, their health and operator overrides." actions={<>
      <button className="btn" disabled={busy || !may('monitor.view')} onClick={() => run(() => checkHealth(user), 'Health check complete.')}><Icon name="refresh" size={14} /> Run health check</button>
      <button className="btn primary" disabled={!may('monitor.view')} onClick={() => setRaise(true)}>Raise alert</button>
    </>}>
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <Card title="Components">
        <DataTable rows={services} search={(s) => `${s.name} ${s.kind} ${s.status} ${s.version}`} columns={[
          { label: 'Service', render: (s) => <><b>{s.name}</b><br /><small className="muted">{s.kind || 'component'}</small></> },
          { label: 'Status', key: 'status', badge: true },
          { label: 'Version', key: 'version' },
          { label: 'Latency', render: (s) => `${s.latencyMs || 0} ms` },
          { label: 'Uptime', render: (s) => s.uptime || '—' },
          { label: 'Last heartbeat', render: (s) => <span title={fmt(s.lastHeartbeat || s.lastCheckAt)}>{ago(s.lastHeartbeat || s.lastCheckAt)}</span> },
          { label: 'Reason', render: (s) => s.statusReason || '—' },
        ]} actions={(s) => [
          { label: 'Set status', disabled: !may('monitor.view'), onClick: () => setPending(s) },
          { label: 'Raise alert', disabled: !may('monitor.view'), onClick: () => setRaise(s) },
        ]} empty={<Empty icon="server" title="No services registered" />} />
      </Card>

      {pending && <ActionDialog
        title={`Set status · ${pending.name}`}
        desc="Moving a service away from healthy needs a reason. The change is written to the audit trail."
        confirmLabel="Update status"
        field={{ label: 'New status', type: 'select', options: SERVICE_STATUSES.map((s) => ({ v: s, l: s })) }}
        requireReason={pending.status !== 'healthy'}
        onClose={() => setPending(null)}
        onConfirm={async (reason, status) => { await run(() => setServiceStatus(user, pending, status, reason)); setPending(null); }}
      />}
      {raise && <RaiseAlertModal onClose={() => setRaise(false)} onDone={() => {}} />}
    </Page>
  );
}

export function AlertsPage() {
  const { user } = useAuth();
  const may = usePerm();
  const alerts = useCol('alerts', false);
  const services = useCol('services', false);
  const { msg, setMsg, run, busy } = useFlash();
  const [tab, setTab] = useState('open');
  const [raise, setRaise] = useState(false);
  const [pending, setPending] = useState(null);
  const sorted = [...alerts].sort((a, b) => b.at - a.at);
  const rows = tab === 'all' ? sorted : sorted.filter((a) => a.status === tab);
  const serviceName = (id) => services.find((s) => s.id === id)?.name || '—';

  return (
    <Page title="Alerts" desc="Triage platform alerts: acknowledge, resolve or silence with a recorded reason." actions={<button className="btn primary" disabled={!may('monitor.view')} onClick={() => setRaise(true)}>Raise alert</button>}>
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Open" value={alerts.filter((a) => a.status === 'open').length} icon="bell" tone="amber" />
        <Stat label="Critical open" value={alerts.filter((a) => a.status === 'open' && a.severity === 'critical').length} icon="warn" tone="red" />
        <Stat label="Acknowledged" value={alerts.filter((a) => a.status === 'acknowledged').length} icon="check" />
        <Stat label="Resolved" value={alerts.filter((a) => a.status === 'resolved').length} icon="check" tone="green" />
      </StatGrid>
      <Card pad>
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: 'open', label: 'Open', count: alerts.filter((a) => a.status === 'open').length },
          { key: 'acknowledged', label: 'Acknowledged', count: alerts.filter((a) => a.status === 'acknowledged').length },
          { key: 'resolved', label: 'Resolved', count: alerts.filter((a) => a.status === 'resolved').length },
          { key: 'silenced', label: 'Silenced', count: alerts.filter((a) => a.status === 'silenced').length },
          { key: 'all', label: 'All', count: alerts.length },
        ]} />
        <DataTable rows={rows} search={(a) => `${a.title} ${a.detail || ''} ${a.source} ${a.severity} ${a.status}`} filters={[
          { key: 'severity', label: 'Any severity', options: ALERT_SEVERITIES.map((s) => ({ v: s, l: s })) },
          { key: 'status', label: 'Any status', options: ALERT_STATUSES.map((s) => ({ v: s, l: s })) },
        ]} columns={[
          { label: 'Severity', key: 'severity', badge: true },
          { label: 'Alert', render: (a) => <><b>{a.title}</b><br /><small className="muted">{a.detail || a.runbook || '—'}</small></> },
          { label: 'Service', render: (a) => serviceName(a.serviceId) },
          { label: 'Source', key: 'source' },
          { label: 'Raised', render: (a) => <span title={fmt(a.at)}>{ago(a.at)}</span> },
          { label: 'Status', key: 'status', badge: true },
        ]} actions={(a) => [
          { label: 'Acknowledge', disabled: !may('monitor.view') || a.status !== 'open', onClick: () => run(() => acknowledgeAlert(user, a), 'Alert acknowledged.') },
          { label: 'Resolve', disabled: !may('monitor.view') || a.status === 'resolved', onClick: () => setPending({ a, kind: 'resolve' }) },
          { label: 'Silence', disabled: !may('monitor.view'), onClick: () => setPending({ a, kind: 'silence' }) },
        ]} empty={<Empty icon="bell" title="No alerts in this view" />} />
      </Card>

      {raise && <RaiseAlertModal onClose={() => setRaise(false)} onDone={() => {}} />}
      {pending?.kind === 'resolve' && <ActionDialog
        title={`Resolve · ${pending.a.title}`}
        desc="Record what fixed the condition so the alert history is actionable."
        confirmLabel="Resolve alert"
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason) => { await run(() => resolveAlert(user, pending.a, reason)); setPending(null); }}
      />}
      {pending?.kind === 'silence' && <ActionDialog
        title={`Silence · ${pending.a.title}`}
        desc="Silenced alerts stop counting against health until the window expires."
        confirmLabel="Silence alert"
        field={{ label: 'Minutes', type: 'number', default: 60 }}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason, minutes) => { await run(() => silenceAlert(user, pending.a, Number(minutes), reason)); setPending(null); }}
      />}
    </Page>
  );
}
