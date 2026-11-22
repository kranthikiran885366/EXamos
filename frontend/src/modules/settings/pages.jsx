import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Stat, StatGrid, Alert, Flash, useFlash, Modal, Field,
  Input, Select, Textarea, Checkbox, ActionDialog, KeyValue, Progress, Empty, Icon, Tabs, Loading,
} from '../../core/ui/kit';
import { useLoad, usePerm } from '../../core/ui/hooks';
import { fmt, ago } from '../../core/ui/format';
import {
  getPlatform, saveConfig, FEATURES, INTEGRATION_KINDS, saveIntegration, testIntegration,
  deleteIntegration, toggleFeature, setFeatureRollout, featureFlags, systemHealth, healthTone,
} from './service';
import { checkHealth, triggerBackup, testRestore, runJob } from '../monitoring/service';

const SENSITIVE = ['sessionIdleMin', 'maxSessionHours', 'mfaRequired', 'passwordMinLength', 'maintenance', 'telemetry', 'releaseChannel', 'requireReleaseEvidence'];

export function SettingsPage() {
  const { user } = useAuth();
  const may = usePerm();
  const { data, loading, error, reload } = useLoad(() => getPlatform());
  const [cfg, setCfg] = useState(null);
  const [reason, setReason] = useState('');
  const [tab, setTab] = useState('general');
  const { msg, setMsg, run, busy } = useFlash();
  useEffect(() => { if (data) setCfg(data); }, [data]);
  const features = useCol('features', false);

  const save = async () => {
    const r = await run(() => saveConfig(user, cfg, reason || 'Platform settings updated'), 'Configuration saved.');
    if (r) { setReason(''); reload(); }
  };
  const initialize = async () => {
    const r = await run(() => saveConfig(user, cfg, reason || 'Initialize platform configuration defaults', true), 'Platform defaults saved.');
    if (r) { setReason(''); reload(); }
  };
  if (loading && !cfg) return <Page title="Platform settings"><Card><Loading label="Loading platform configuration…" /></Card></Page>;
  if (error) return <Page title="Platform settings"><Alert tone="danger">{error.message}</Alert></Page>;
  if (!cfg) return <Page title="Platform settings"><Card><Loading label="Preparing configuration…" /></Card></Page>;

  const set = (k, v) => setCfg((c) => ({ ...c, [k]: v }));
  const changed = data ? Object.keys(cfg || {}).filter((k) => JSON.stringify(cfg[k]) !== JSON.stringify(data[k])) : [];
  const sensitive = changed.filter((k) => SENSITIVE.includes(k));

  return (
    <Page title="Platform settings" desc="Environment, session, security and operational defaults. Sensitive changes need platform approval unless you are a super administrator.">
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {cfg.configurationState === 'not-configured' && <Alert
        tone="warn"
        title="Platform configuration has not been saved yet"
        action={<button className="btn" disabled={busy || !may('settings.manage')} onClick={initialize}>Initialize defaults</button>}
      >
        Safe defaults are shown below. Initialize them before relying on this environment; authorization and transport failures are reported separately.
      </Alert>}
      <StatGrid cols={4}>
        <Stat label="Environment" value={cfg.environment} icon="settings" />
        <Stat label="Idle timeout" value={cfg.sessionIdleMin} unit="min" icon="clock" />
        <Stat label="Max session" value={cfg.maxSessionHours} unit="h" icon="clock" />
        <Stat label="MFA required" value={cfg.mfaRequired ? 'Yes' : 'No'} icon="shield" tone={cfg.mfaRequired ? 'green' : 'amber'} />
      </StatGrid>

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'general', label: 'General' },
        { key: 'security', label: 'Security & sessions' },
        { key: 'operations', label: 'Operations' },
        { key: 'features', label: 'Feature flags', count: FEATURES.length },
      ]} />

      {tab === 'general' && <Card title="Environment & identity">
        <div className="formgrid">
          <Field label="Environment"><Select value={cfg.environment} onChange={(e) => set('environment', e.target.value)} options={['development', 'staging', 'production']} placeholder={false} /></Field>
          <Field label="Release channel"><Select value={cfg.releaseChannel} onChange={(e) => set('releaseChannel', e.target.value)} options={['stable', 'canary', 'pilot']} placeholder={false} /></Field>
          <Field label="Support email"><Input type="email" value={cfg.supportEmail} onChange={(e) => set('supportEmail', e.target.value)} /></Field>
          <Field label="Allowed origins" help="Comma-separated https origins"><Input value={(cfg.allowedOrigins || []).join(', ')} onChange={(e) => set('allowedOrigins', e.target.value)} /></Field>
        </div>
      </Card>}

      {tab === 'security' && <Card title="Security & sessions" desc="Session and password policy changes are sensitive and need approval unless made by a super administrator.">
        <div className="formgrid">
          <Field label="Idle timeout (minutes)" help="2–60"><Input type="number" min={2} max={60} value={cfg.sessionIdleMin} onChange={(e) => set('sessionIdleMin', Number(e.target.value))} /></Field>
          <Field label="Maximum session (hours)" help="1–24"><Input type="number" min={1} max={24} value={cfg.maxSessionHours} onChange={(e) => set('maxSessionHours', Number(e.target.value))} /></Field>
          <Field label="Password minimum length" help="12–64"><Input type="number" min={12} max={64} value={cfg.passwordMinLength} onChange={(e) => set('passwordMinLength', Number(e.target.value))} /></Field>
          <Field label="Audit retention (days)" help="30–3,650"><Input type="number" min={30} max={3650} value={cfg.auditRetentionDays} onChange={(e) => set('auditRetentionDays', Number(e.target.value))} /></Field>
          <div className="span2 checkrow">
            <Checkbox label="MFA required for all users" checked={!!cfg.mfaRequired} onChange={(e) => set('mfaRequired', e.target.checked)} />
            <Checkbox label="Telemetry enabled" checked={!!cfg.telemetry} onChange={(e) => set('telemetry', e.target.checked)} />
          </div>
        </div>
      </Card>}

      {tab === 'operations' && <Card title="Operational defaults">
        <div className="formgrid">
          <Field label="Device heartbeat (seconds)" help="10–300"><Input type="number" min={10} max={300} value={cfg.deviceHeartbeatSeconds} onChange={(e) => set('deviceHeartbeatSeconds', Number(e.target.value))} /></Field>
          <Field label="Candidate retention (days)" help="30–3,650"><Input type="number" min={30} max={3650} value={cfg.defaultCandidateRetentionDays} onChange={(e) => set('defaultCandidateRetentionDays', Number(e.target.value))} /></Field>
          <div className="span2 checkrow">
            <Checkbox label="Require release evidence" checked={!!cfg.requireReleaseEvidence} onChange={(e) => set('requireReleaseEvidence', e.target.checked)} />
            <Checkbox label="Maintenance mode" checked={!!cfg.maintenance?.enabled} onChange={(e) => set('maintenance', { ...(cfg.maintenance || {}), enabled: e.target.checked })} />
          </div>
          {cfg.maintenance?.enabled && <Field label="Maintenance banner" className="span2"><Input value={cfg.maintenance.message || ''} maxLength={200} onChange={(e) => set('maintenance', { ...cfg.maintenance, message: e.target.value })} placeholder="Scheduled maintenance window…" /></Field>}
        </div>
        {sensitive.length > 0 && <Alert tone="warn" title="Approval required">Sensitive changes ({sensitive.join(', ')}) are submitted as a two-person approval unless you are a platform super administrator.</Alert>}
        <div className="row gap">
          <Field label="Change reason" className="grow"><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} placeholder="Why is this changing?" /></Field>
          <button className="btn primary" disabled={busy || !changed.length || (sensitive.length > 0 && !may('settings.manage'))} onClick={save}>{busy ? 'Saving…' : `Save${changed.length ? ` (${changed.length})` : ''}`}</button>
        </div>
      </Card>}

      {tab === 'features' && <Card title="Feature controls" desc="Institution-wide feature switches and staged rollouts." actions={<Link className="btn" to="/admin/feature-controls">Manage features</Link>}>
        <DataTable rows={featureFlags(features)} columns={[
          { label: 'Feature', key: 'label' }, { label: 'Group', key: 'group' },
          { label: 'Enabled', key: 'enabled', render: (f) => <Badge value={f.enabled ? 'enabled' : 'disabled'} /> },
          { label: 'Rollout', key: 'rollout', render: (f) => <Progress value={f.rollout} /> },
        ]} />
      </Card>}
    </Page>
  );
}

function IntegrationModal({ editing, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [form, setForm] = useState(editing ? {
    id: editing.id, name: editing.name, kind: editing.kind, url: editing.url || '',
    secret: '', notes: editing.notes || '', enabled: editing.enabled !== false,
  } : { name: '', kind: 'webhook', url: '', secret: '', notes: '', enabled: true });
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => saveIntegration(user, form), 'Integration saved.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title={editing ? `Edit ${editing.name}` : 'Add integration'} desc="Secrets are stored as hash references and never displayed after saving." onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="int-form" disabled={busy}>{busy ? 'Saving…' : 'Save integration'}</button></>}>
      <form id="int-form" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <div className="formgrid">
          <Field label="Name" required><Input value={form.name} onChange={(e) => set('name', e.target.value)} maxLength={60} autoFocus /></Field>
          <Field label="Type"><Select value={form.kind} onChange={(e) => set('kind', e.target.value)} options={INTEGRATION_KINDS.map((k) => ({ v: k, l: k.toUpperCase() }))} placeholder={false} /></Field>
          <Field label="Endpoint URL" className="span2" help="https URL without credentials"><Input value={form.url} onChange={(e) => set('url', e.target.value)} maxLength={300} placeholder="https://hooks.example.com/examos" /></Field>
          <Field label="Secret" className="span2" help={editing?.secretSet ? 'A secret is already configured. Enter a new value to rotate it.' : 'Stored as a hash reference; never shown again.'}><Input type="password" value={form.secret} onChange={(e) => set('secret', e.target.value)} maxLength={128} autoComplete="new-password" /></Field>
          <Field label="Notes" className="span2"><Textarea rows={3} value={form.notes} onChange={(e) => set('notes', e.target.value)} maxLength={300} /></Field>
        </div>
        <Checkbox label="Enabled" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />
      </form>
    </Modal>
  );
}

export function IntegrationsPage() {
  const { user } = useAuth();
  const may = usePerm();
  const integrations = useCol('integrations', false);
  const { msg, setMsg, run, busy } = useFlash();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [removing, setRemoving] = useState(null);
  return (
    <Page title="Integrations" desc="SMTP, webhook, SIEM, SSO, billing, storage and ticketing connectors." actions={<button className="btn primary" onClick={() => { setEditing(null); setOpen(true); }} disabled={!may('settings.manage')}><Icon name="plus" size={15} /> Add integration</button>}>
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Integrations" value={integrations.filter((i) => i.status !== 'removed').length} icon="server" />
        <Stat label="Healthy" value={integrations.filter((i) => i.status === 'healthy').length} icon="check" tone="green" />
        <Stat label="Failed" value={integrations.filter((i) => i.status === 'failed').length} icon="warn" tone="red" />
        <Stat label="Not tested" value={integrations.filter((i) => !i.lastCheckAt).length} icon="clock" tone="amber" />
      </StatGrid>
      <Card title="Connectors">
        <DataTable rows={integrations.filter((i) => i.status !== 'removed')} search={['name', 'kind', 'url', 'status']} filters={[
          { key: 'kind', label: 'Any type', options: INTEGRATION_KINDS.map((k) => ({ v: k, l: k.toUpperCase() })) },
          { key: 'status', label: 'Any status', options: [{ v: 'healthy', l: 'healthy' }, { v: 'failed', l: 'failed' }, { v: 'not-tested', l: 'not tested' }] },
        ]} columns={[
          { label: 'Name', key: 'name' }, { label: 'Type', key: 'kind', badge: true }, { label: 'Endpoint', render: (i) => i.url || '—' },
          { label: 'Status', key: 'status', badge: true }, { label: 'Secret', render: (i) => (i.secretSet ? 'Configured' : 'None') },
          { label: 'Enabled', render: (i) => <Badge value={i.enabled ? 'enabled' : 'disabled'} /> },
          { label: 'Last test', render: (i) => (i.lastCheckAt ? <span title={fmt(i.lastCheckAt)}>{ago(i.lastCheckAt)}</span> : 'Never') },
        ]} actions={(i) => [
          { label: 'Test', disabled: !may('settings.manage'), onClick: () => run(() => testIntegration(user, i)) },
          { label: 'Edit', disabled: !may('settings.manage'), onClick: () => { setEditing(i); setOpen(true); } },
          { label: i.enabled ? 'Disable' : 'Enable', disabled: !may('settings.manage'), onClick: () => run(() => saveIntegration(user, { ...i, enabled: !i.enabled }), i.enabled ? 'Integration disabled.' : 'Integration enabled.') },
          { label: 'Remove', danger: true, disabled: !may('settings.manage'), onClick: () => setRemoving(i) },
        ]} empty={<Empty icon="server" title="No integrations configured">Add an SMTP or webhook connector to start sending notifications.</Empty>} />
      </Card>
      {open && <IntegrationModal editing={editing} onClose={() => { setOpen(false); setEditing(null); }} onDone={() => {}} />}
      {removing && <ActionDialog title={`Remove ${removing.name}`} desc="The integration is disabled immediately and kept for audit." danger confirmLabel="Remove" onClose={() => setRemoving(null)} onConfirm={async (r) => { await run(() => deleteIntegration(user, removing, r)); setRemoving(null); }} />}
    </Page>
  );
}

export function FeatureControlsPage() {
  const { user } = useAuth();
  const may = usePerm();
  const features = useCol('features', false);
  const { msg, setMsg, run, busy } = useFlash();
  const [rollout, setRollout] = useState(null);
  const rows = featureFlags(features);
  const [percent, setPercent] = useState(100);
  return (
    <Page title="Feature controls" desc="Enable, disable and roll out platform features incrementally. Changes are audited.">
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <Card title="Feature flags">
        <DataTable rows={rows} search={['label', 'desc', 'group']} filters={[
          { key: 'group', label: 'Any group', options: [...new Set(FEATURES.map((f) => f.group))].map((g) => ({ v: g, l: g })) },
          { key: 'enabled', label: 'Any state', options: [{ v: 'true', l: 'enabled' }, { v: 'false', l: 'disabled' }], get: (f) => String(f.enabled) },
        ]} columns={[
          { label: 'Feature', render: (f) => <><b>{f.label}</b><br /><small className="muted">{f.desc}</small></> },
          { label: 'Group', key: 'group' },
          { label: 'Enabled', key: 'enabled', render: (f) => <Badge value={f.enabled ? 'enabled' : 'disabled'} /> },
          { label: 'Rollout', key: 'rollout', render: (f) => <Progress value={f.rollout} /> },
          { label: 'Updated', render: (f) => (f.updatedAt ? ago(f.updatedAt) : 'default') },
        ]} actions={(f) => [
          { label: f.enabled ? 'Disable' : 'Enable', disabled: !may('settings.manage') || busy, onClick: () => run(() => toggleFeature(user, f.key, !f.enabled), f.enabled ? 'Feature disabled.' : 'Feature enabled.') },
          { label: 'Set rollout', disabled: !may('settings.manage'), onClick: () => { setRollout(f); setPercent(f.rollout); } },
        ]} />
      </Card>
      {rollout && <Modal title={`Rollout · ${rollout.label}`} desc="Rollout percentages are limited to 0, 25, 50, 75 or 100%." onClose={() => setRollout(null)} footer={<><button className="btn" onClick={() => setRollout(null)}>Cancel</button><button className="btn primary" form="rollout-form" disabled={busy}>{busy ? 'Saving…' : 'Apply rollout'}</button></>}>
        <form id="rollout-form" className="stack" onSubmit={async (e) => { e.preventDefault(); const ok = await run(() => setFeatureRollout(user, rollout.key, percent)); if (ok) setRollout(null); }}>
          <Field label="Rollout percentage"><Select value={percent} onChange={(e) => setPercent(Number(e.target.value))} options={[0, 25, 50, 75, 100].map((n) => ({ v: n, l: `${n}%` }))} placeholder={false} /></Field>
          <Progress label={`${rollout.label} rollout`} value={percent} />
        </form>
      </Modal>}
    </Page>
  );
}

export function SystemHealthPage() {
  const { user } = useAuth();
  const may = usePerm();
  const { data: health, loading, error, reload } = useLoad(() => systemHealth());
  const { msg, setMsg, run, busy } = useFlash();
  const [tab, setTab] = useState('checks');
  if (loading && !health) return <Page title="System health"><Card><Loading label="Computing health checks…" /></Card></Page>;
  if (error) return <Page title="System health"><Alert tone="danger">{error.message}</Alert></Page>;
  const backups = health.backups || [];
  const lastBackup = health.lastBackup;
  return (
    <Page title="System health" desc="Service availability, audit chain, backups and platform metrics." actions={<>
      <button className="btn" disabled={busy || !may('monitor.view')} onClick={() => run(async () => { await checkHealth(user); reload(); return 'Health check complete.'; })}><Icon name="refresh" size={14} /> Run health check</button>
      <button className="btn primary" disabled={busy || !may('monitor.view')} onClick={() => run(async () => { await triggerBackup(user, { scope: 'full', note: 'Backup from system health' }); reload(); return 'Backup complete.'; })}>Take backup</button>
    </>}>
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Health score" value={health.score} unit="/ 100" icon="check" tone={healthTone(health) === 'g' ? 'green' : healthTone(health) === 'a' ? 'amber' : 'red'} />
        <Stat label="Audit chain" value={health.chain.ok ? 'Intact' : 'Broken'} icon="shield" tone={health.chain.ok ? 'green' : 'red'} sub={`${health.chain.count} entries`} />
        <Stat label="DB latency p95" value={health.p95} unit="ms" icon="server" />
        <Stat label="Critical incidents" value={health.criticalIncidents} icon={health.criticalIncidents ? 'warn' : 'check'} tone={health.criticalIncidents ? 'red' : 'green'} />
      </StatGrid>
      <Card pad>
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: 'checks', label: 'Health checks', count: health.checks.length },
          { key: 'services', label: 'Services', count: health.services.length },
          { key: 'backups', label: 'Backups', count: backups.length },
          { key: 'jobs', label: 'Jobs', count: (health.jobs || []).length },
        ]} />
        {tab === 'checks' && <DataTable rows={health.checks} columns={[
          { label: 'Check', key: 'label' }, { label: 'Status', key: 'status', badge: true }, { label: 'Detail', key: 'detail' },
        ]} />}
        {tab === 'services' && <DataTable rows={health.services} columns={[
          { label: 'Service', key: 'name' }, { label: 'Status', key: 'status', badge: true },
          { label: 'Latency', render: (s) => `${s.latencyMs || 0} ms` }, { label: 'Last heartbeat', render: (s) => ago(s.lastHeartbeat || s.lastCheckAt) },
        ]} />}
        {tab === 'backups' && <DataTable rows={[...backups].sort((a, b) => b.at - a.at)} columns={[
          { label: 'Taken', render: (b) => <span title={fmt(b.at)}>{ago(b.at)}</span> }, { label: 'Scope', key: 'scope' },
          { label: 'Status', key: 'status', badge: true }, { label: 'Size', render: (b) => `${b.sizeMb} MB` },
          { label: 'Restore tested', render: (b) => b.restoreTestedAt ? ago(b.restoreTestedAt) : <Badge value="not run" /> },
        ]} actions={(b) => [{ label: 'Test restore', disabled: !may('monitor.view'), onClick: () => run(async () => { await testRestore(user, b); reload(); return 'Restore test complete.'; }) }]} empty={<Empty icon="history" title="No backups yet" />} />}
        {tab === 'jobs' && <DataTable rows={health.jobs || []} columns={[
          { label: 'Job', key: 'name' }, { label: 'Schedule', key: 'schedule' }, { label: 'Status', key: 'status', badge: true },
          { label: 'Last run', render: (j) => j.lastRun ? ago(j.lastRun) : 'Never' }, { label: 'Result', render: (j) => j.result || '—' },
        ]} actions={(j) => [{ label: 'Run now', disabled: !may('monitor.view') || j.status === 'running', onClick: () => run(async () => { await runJob(user, j); reload(); return 'Job completed.'; }) }]} />}
      </Card>
      {lastBackup && <Alert tone={Date.now() - lastBackup.at > 2 * 864e5 ? 'warn' : 'success'} title="Latest backup">{fmt(lastBackup.at)} · {lastBackup.sizeMb} MB · {lastBackup.status}{lastBackup.restoreTestedAt ? ' · restore tested' : ' · restore not tested'}</Alert>}
    </Page>
  );
}
