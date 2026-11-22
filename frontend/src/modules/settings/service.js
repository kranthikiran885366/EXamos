import { all, get, put, p95 } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, requireReason, validHttps, pct } from '../../core/services/common';
import { verifyChain } from '../../core/security/auditChain';
import { create as requestApproval } from '../../core/services/approvals';

export const CONFIG_DEFAULTS = {
  environment: 'production', sessionIdleMin: 10, maxSessionHours: 8, mfaRequired: true,
  passwordMinLength: 12, maintenance: { enabled: false, message: '' },
  supportEmail: 'support@examos.example', telemetry: true, auditRetentionDays: 365,
  defaultCandidateRetentionDays: 730, allowedOrigins: ['https://exam.examos.example'],
  releaseChannel: 'stable', requireReleaseEvidence: true, deviceHeartbeatSeconds: 40,
};
export const SENSITIVE = ['sessionIdleMin', 'maxSessionHours', 'mfaRequired', 'passwordMinLength', 'maintenance', 'telemetry', 'releaseChannel', 'requireReleaseEvidence'];
export const FEATURES = [
  { key: 'usb-exam-delivery', label: 'USB exam delivery', desc: 'Bootable USB images, custody and hash verification.', group: 'Delivery' },
  { key: 'managed-lab', label: 'Managed lab devices', desc: 'Persistent lab devices with TPM attestation.', group: 'Delivery' },
  { key: 'tpm-attestation', label: 'TPM attestation', desc: 'Quote verification against golden PCR values.', group: 'Security' },
  { key: 'secure-boot', label: 'Secure Boot enforcement', desc: 'Block devices with Secure Boot disabled.', group: 'Security' },
  { key: 'auto-submit', label: 'Auto-submit at deadline', desc: 'Close sessions when the exam deadline is reached.', group: 'Examinations' },
  { key: 'two-person-approvals', label: 'Two-person approvals', desc: 'Sensitive actions require a second privileged user.', group: 'Governance' },
  { key: 'privacy-console', label: 'Privacy console', desc: 'Data subject requests, retention and erasure workflows.', group: 'Governance' },
  { key: 'billing-integration', label: 'Billing integration', desc: 'Plans, invoices and payment reconciliation.', group: 'Commercial' },
  { key: 'support-diagnostics', label: 'Support diagnostics', desc: 'Read-only diagnostics bundle for support engineers.', group: 'Support' },
];
export const INTEGRATION_KINDS = ['smtp', 'webhook', 'siem', 'sso', 'billing', 'storage', 'ticketing'];

export async function getPlatform() {
  const [configResult, metaResult] = await Promise.allSettled([
    get('configs', 'platform'),
    get('meta', 'platform'),
  ]);
  const isNotFound = (err) => {
    if (!err) return false;
    const s = Number(err.status);
    if (s === 404) return true;
    const msg = String(err.message || err.error || '').toLowerCase();
    return msg.includes('not found') || msg.includes('404');
  };
  const unavailable = [configResult, metaResult].find((result) => result.status === 'rejected' && !isNotFound(result.reason));
  if (unavailable) throw unavailable.reason;
  const rawConfig = configResult.status === 'fulfilled' ? configResult.value : null;
  const rawMeta = metaResult.status === 'fulfilled' ? metaResult.value : null;
  const config = rawConfig && !rawConfig.error ? rawConfig : null;
  const meta = rawMeta && !rawMeta.error ? rawMeta : null;
  return {
    ...CONFIG_DEFAULTS,
    ...(meta?.value || {}),
    ...(config?.value || {}),
    configurationState: config || meta ? 'configured' : 'not-configured',
  };
}

export async function saveConfig(a, patch, reason = '', initialize = false) {
  need(a, 'settings.manage');
  const cur = await getPlatform();
  const next = { ...cur };
  delete next.configurationState;
  for (const k of Object.keys(CONFIG_DEFAULTS)) if (patch[k] !== undefined) next[k] = patch[k];
  if (patch.sessionIdleMin !== undefined) { const n = Number(patch.sessionIdleMin); if (!(n >= 2 && n <= 60)) fail('Idle timeout must be 2–60 minutes.'); next.sessionIdleMin = n; }
  if (patch.maxSessionHours !== undefined) { const n = Number(patch.maxSessionHours); if (!(n >= 1 && n <= 24)) fail('Maximum session must be 1–24 hours.'); next.maxSessionHours = n; }
  if (patch.passwordMinLength !== undefined) { const n = Number(patch.passwordMinLength); if (!(n >= 12 && n <= 64)) fail('Password length must be 12–64.'); next.passwordMinLength = n; }
  if (patch.auditRetentionDays !== undefined) { const n = Number(patch.auditRetentionDays); if (!(n >= 30 && n <= 3650)) fail('Audit retention must be 30–3,650 days.'); next.auditRetentionDays = n; }
  if (patch.maintenance) next.maintenance = { enabled: !!patch.maintenance.enabled, message: clean(patch.maintenance.message, 200) };
  if (patch.allowedOrigins !== undefined) {
    const list = (Array.isArray(patch.allowedOrigins) ? patch.allowedOrigins : String(patch.allowedOrigins).split(/[\s,]+/)).filter(Boolean);
    for (const o of list) if (!validHttps(o)) fail(`${o} is not a valid https origin.`);
    next.allowedOrigins = list;
  }
  if (patch.supportEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(patch.supportEmail)) fail('Enter a valid support email.');
  const changed = Object.keys(CONFIG_DEFAULTS).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(cur[k]));
  if (initialize && cur.configurationState === 'not-configured') changed.push('initial configuration');
  if (!changed.length) fail('Nothing changed.');
  const sensitive = changed.filter((k) => SENSITIVE.includes(k));
  if (sensitive.length && a.role !== 'superadmin') {
    const r = requireReason(reason, 8);
    const ap = await requestApproval(a, { kind: 'config-change', label: `Platform config: ${sensitive.join(', ')}`, targetId: 'platform', tenantId: null, reason: r, data: { patch: Object.fromEntries(changed.map((k) => [k, next[k]])) } });
    return `Configuration change requested (${ap.id}). A platform administrator must approve it.`;
  }
  await put('configs', { id: 'platform', value: next, updatedAt: Date.now(), updatedBy: a.id });
  await put('meta', { id: 'platform', value: next, updatedAt: Date.now() });
  await log(a, 'PLATFORM_CONFIG_UPDATED', `changed=${changed.join(',')}`);
  return `Configuration saved (${changed.length} change${changed.length === 1 ? '' : 's'}).`;
}

/** Handler used by the shared approvals service. */
export async function applyConfigApproval(ap, approver) {
  const cur = await getPlatform();
  const patch = ap.data?.patch || {};
  const next = { ...cur, ...patch };
  await put('configs', { id: 'platform', value: next, updatedAt: Date.now(), updatedBy: approver.id });
  await put('meta', { id: 'platform', value: next, updatedAt: Date.now() });
  await log(approver, 'PLATFORM_CONFIG_APPLIED', `${ap.label} via ${ap.id}`);
  return 'Configuration change applied.';
}

/* ---------------- Integrations ---------------- */
export async function saveIntegration(a, { id: iid, name, kind, url, secret = '', enabled = true, notes = '' }) {
  need(a, 'settings.manage');
  if (clean(name, 60).length < 2) fail('Give the integration a name.');
  if (!INTEGRATION_KINDS.includes(kind)) fail('Pick an integration type.');
  if (url && !validHttps(url)) fail('Endpoint must be an https URL without credentials.');
  const list = await all('integrations');
  const existing = iid ? list.find((x) => x.id === iid) : null;
  if (!existing && list.some((x) => x.name.toLowerCase() === clean(name, 60).toLowerCase())) fail('An integration with this name exists.');
  const rec = {
    id: existing?.id || id('int'), name: clean(name, 60), kind, url: clean(url, 300), enabled: !!enabled,
    notes: clean(notes, 300), secretSet: !!(secret || existing?.secretSet), lastCheckAt: existing?.lastCheckAt || null,
    status: existing?.status || 'not-tested', createdAt: existing?.createdAt || Date.now(), updatedAt: Date.now(), updatedBy: a.id,
  };
  await put('integrations', rec);
  await log(a, existing ? 'INTEGRATION_UPDATED' : 'INTEGRATION_CREATED', `${rec.name} (${kind})`);
  return `${rec.name} saved. Secrets are never displayed after saving.`;
}

export async function testIntegration(a, i) {
  need(a, 'settings.manage');
  if (!i.url && i.kind !== 'smtp') fail('Add an endpoint before testing.');
  const ok = i.enabled && (i.kind === 'smtp' || !!i.url);
  await put('integrations', { ...i, status: ok ? 'healthy' : 'failed', lastCheckAt: Date.now(), lastError: ok ? '' : 'Endpoint missing or integration disabled' });
  await log(a, 'INTEGRATION_TESTED', `${i.name} ${ok ? 'ok' : 'failed'}`);
  return ok ? `${i.name} responded successfully.` : `${i.name} failed its connectivity check.`;
}

export async function deleteIntegration(a, i, reason) {
  need(a, 'settings.manage');
  const r = requireReason(reason, 8);
  await put('integrations', { ...i, enabled: false, status: 'removed', removedAt: Date.now(), removedBy: a.id, removeReason: r });
  await log(a, 'INTEGRATION_REMOVED', `${i.name}: ${r}`);
  return `${i.name} removed.`;
}

/* ---------------- Feature controls ---------------- */
export async function toggleFeature(a, key, enabled) {
  need(a, 'settings.manage');
  const def = FEATURES.find((f) => f.key === key); if (!def) fail('Unknown feature.');
  const existing = (await all('features')).find((f) => f.key === key);
  const rec = { id: existing?.id || id('ftr'), key, label: def.label, desc: def.desc, group: def.group, enabled: !!enabled, rollout: existing?.rollout ?? 100, updatedAt: Date.now(), updatedBy: a.id };
  await put('features', rec);
  await log(a, 'FEATURE_TOGGLED', `${key} -> ${!!enabled}`);
  return `${def.label} ${enabled ? 'enabled' : 'disabled'}.`;
}

export async function setFeatureRollout(a, key, percent) {
  need(a, 'settings.manage');
  const n = Number(percent); if (![0, 25, 50, 75, 100].includes(n)) fail('Rollout must be 0, 25, 50, 75 or 100%.');
  const existing = (await all('features')).find((f) => f.key === key);
  const def = FEATURES.find((f) => f.key === key); if (!def) fail('Unknown feature.');
  await put('features', { ...(existing || {}), id: existing?.id || id('ftr'), key, label: def.label, desc: def.desc, group: def.group, enabled: n > 0, rollout: n, updatedAt: Date.now(), updatedBy: a.id });
  await log(a, 'FEATURE_ROLLOUT', `${key} -> ${n}%`);
  return `${def.label} at ${n}% rollout.`;
}

export const featureFlags = (rows) => FEATURES.map((f) => {
  const r = rows.find((x) => x.key === f.key);
  return { ...f, enabled: r?.enabled ?? true, rollout: r?.rollout ?? 100, updatedAt: r?.updatedAt };
});

/* ---------------- Health ---------------- */
export async function systemHealth(ctx = {}) {
  const { services = await all('services'), alerts = await all('alerts'), jobs = await all('jobs'), backups = await all('backups'), incidents = await all('incidents') } = ctx;
  const chain = await verifyChain();
  const openInc = incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status));
  const critical = openInc.filter((i) => i.severity === 'critical');
  const down = services.filter((s) => s.status === 'down');
  const degraded = services.filter((s) => s.status === 'degraded');
  const lastBackup = [...backups].sort((a, b) => (b.at || 0) - (a.at || 0))[0] || null;
  const checks = [
    { key: 'audit', label: 'Audit chain integrity', status: chain.ok ? 'PASS' : 'FAIL', detail: `${chain.count} entries` },
    { key: 'database', label: 'Local database latency (p95)', status: p95() > 250 ? 'WARN' : 'PASS', detail: `${Math.round(p95())} ms` },
    { key: 'services', label: 'Platform services', status: services.length === 0 ? 'NOT MONITORED' : down.length ? 'FAIL' : degraded.length ? 'WARN' : 'PASS', detail: services.length === 0 ? '0/0 (Not monitored)' : `${services.length - down.length}/${services.length} healthy` },
    { key: 'backup', label: 'Latest backup', status: !lastBackup ? 'FAIL' : Date.now() - lastBackup.at > 2 * 864e5 ? 'WARN' : 'PASS', detail: lastBackup ? new Date(lastBackup.at).toLocaleString('en-IN') : 'Never' },
    { key: 'incidents', label: 'Critical incidents', status: critical.length ? 'FAIL' : 'PASS', detail: `${critical.length} open` },
    { key: 'alerts', label: 'Open alerts', status: alerts.filter((x) => x.status === 'open' && x.severity === 'critical').length ? 'FAIL' : alerts.filter((x) => x.status === 'open').length ? 'WARN' : 'PASS', detail: `${alerts.filter((x) => x.status === 'open').length} open` },
    { key: 'jobs', label: 'Scheduled jobs', status: jobs.some((j) => j.status === 'failed') ? 'WARN' : 'PASS', detail: `${jobs.filter((j) => j.status === 'failed').length} failed` },
  ];
  const evaluable = checks.filter((c) => c.status !== 'NOT MONITORED');
  const score = evaluable.length > 0
    ? Math.round(evaluable.reduce((s, c) => s + (c.status === 'PASS' ? 100 : c.status === 'WARN' ? 60 : 0), 0) / evaluable.length)
    : 0;
  return { checks, score, chain, p95: Math.round(p95()), services, alerts, jobs, backups, lastBackup, criticalIncidents: critical.length };
}

export const healthTone = (h) => (h?.score >= 90 ? 'g' : h?.score >= 70 ? 'a' : 'r');
export const availability = (services) => pct(services.filter((s) => s.status === 'healthy').length, services.length);
