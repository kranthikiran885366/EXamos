import { all, put, del } from '../../core/db/db';
import { clean, safeHttpsUrl } from '../../core/security/sanitize';
import { id, need, fail, log } from '../../core/services/common';
import { can } from '../../core/security/rbac';
import * as Api from '../../core/api/services';

export const hostOk = (h) => h === '*' || /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(h);
export const matchHost = (p, h) => p === '*' || p.toLowerCase() === h.toLowerCase() || (p.startsWith('*.') && h.toLowerCase().endsWith(p.slice(1).toLowerCase()));
export function evaluate(rules, host, port) {
  const sorted = rules.filter((r) => r.enabled).sort((a, b) => a.priority - b.priority);
  for (const r of sorted) if (matchHost(r.host, host) && (r.port === '*' || Number(r.port) === Number(port))) return { action: r.action, rule: r };
  return { action: 'deny', rule: null };
}
export const toNft = (rules) => ['table inet examos {', '  chain egress {', '    type filter hook output priority 0; policy drop;',
  ...rules.filter((r) => r.enabled).sort((a, b) => a.priority - b.priority).map((r) => `    # ${r.name} (${r.host})\n    tcp dport ${r.port === '*' ? '1-65535' : r.port} ${r.action === 'allow' ? 'accept' : 'drop'}`), '  }', '}'].join('\n');

async function guardPolicies(tenantId, nextRules) {
  for (const p of (await all('policies')).filter((x) => x.tenantId === tenantId && x.status === 'published'))
    for (const o of p.config.origins) { const u = new URL(o); if (evaluate(nextRules, u.hostname, Number(u.port || 443)).action !== 'allow') fail(`Published policy ${p.name} v${p.version} needs ${u.hostname}. Change blocked.`); }
}
const tenantRules = async (tenantId) => (await all('rules')).filter((r) => r.tenantId === tenantId);

export async function listRules(tenantId) {
  try {
    const res = await Api.listPolicies({ examId: '' });
    const backendRules = res?.rules || res?.firewall_rules || [];
    if (Array.isArray(backendRules) && backendRules.length) return backendRules;
  } catch { /* fall through to local */ }
  return tenantRules(tenantId);
}

export async function createRule(a, { tenantId, name, host, port, action, priority }) {
  need(a, 'firewall.manage');
  host = clean(host, 120).toLowerCase(); name = clean(name, 60); port = String(port).trim();
  if (name.length < 3) fail('Give the rule a name.');
  if (!hostOk(host)) fail('Host must be a domain, *.domain or *.');
  if (port !== '*' && !(Number.isInteger(+port) && +port >= 1 && +port <= 65535)) fail('Port must be 1–65535 or *.');
  if (!['allow', 'deny'].includes(action)) fail('Action must be allow or deny.');
  const pr = Number(priority); if (!Number.isInteger(pr) || pr < 1 || pr > 9999) fail('Priority must be 1–9999.');
  if (action === 'allow' && host === '*' && !can(a.role, 'policy.weaken')) fail('An allow-all rule needs a super admin.');
  const rules = await tenantRules(tenantId);
  if (rules.some((r) => r.name === name)) fail('A rule with this name exists.');
  const rule = { id: id('rule'), tenantId, name, host, port, action, priority: pr, enabled: true, createdBy: a.id, createdAt: Date.now() };
  await guardPolicies(tenantId, [...rules, rule]);
  await put('rules', rule);
  await log(a, 'FIREWALL_RULE_CREATED', `${name} ${action} ${host}:${port}`);
  return `Rule ${name} added.`;
}

export async function toggleRule(a, r) {
  need(a, 'firewall.manage');
  const rules = await tenantRules(r.tenantId);
  await guardPolicies(r.tenantId, rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)));
  await put('rules', { ...r, enabled: !r.enabled });
  await log(a, 'FIREWALL_RULE_TOGGLED', `${r.name} -> ${!r.enabled}`);
}

export async function deleteRule(a, r, reason) {
  need(a, 'firewall.manage');
  const rules = await tenantRules(r.tenantId);
  await guardPolicies(r.tenantId, rules.filter((x) => x.id !== r.id));
  await del('rules', r.id);
  await log(a, 'FIREWALL_RULE_DELETED', `${r.name}: ${reason}`);
}

export function testUrl(rules, url) {
  const u = safeHttpsUrl(url); if (!u) return { error: 'Only valid https:// URLs without credentials are accepted.' };
  const x = new URL(u); const d = evaluate(rules, x.hostname, Number(x.port || 443));
  return { host: x.hostname, port: x.port || '443', ...d };
}
