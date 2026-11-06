import { all, get, put } from '../../core/db/db';
import { sha256, canon, verify } from '../../core/security/crypto';
import { safeHttpsUrl, clean } from '../../core/security/sanitize';
import { id, need, fail, log, requireReason } from '../../core/services/common';
import { can } from '../../core/security/rbac';
import { evaluate } from '../firewall/service';
import { create as requestApproval } from '../../core/services/approvals';

export const ACTIONS = ['Isolate device & notify supervisor', 'Warn candidate & log', 'Terminate session'];
const bodyOf = (p) => canon({ name: p.name, version: p.version, config: p.config, tenantId: p.tenantId });
export const weakened = (prev, c) => (prev.requireTpm && !c.requireTpm) || (prev.kioskLockdown && !c.kioskLockdown) || (!prev.allowUsb && c.allowUsb);

export function validateConfig(c, rules) {
  const e = [];
  if (!ACTIONS.includes(c.onViolation)) e.push('Pick a violation action.');
  if (!c.origins?.length) e.push('Add at least one allowed origin.');
  for (const o of c.origins || []) {
    const u = safeHttpsUrl(o);
    if (!u) { e.push(`${o}: must be a valid https URL.`); continue; }
    const x = new URL(u), d = evaluate(rules, x.hostname, Number(x.port || 443));
    if (d.action !== 'allow') e.push(`${x.hostname} is blocked by the firewall (${d.rule?.name || 'default deny'}).`);
  }
  return e;
}
export async function createPolicy(a, { tenantId, name, requireTpm, kioskLockdown, allowUsb, onViolation, origins }) {
  need(a, 'policy.edit');
  name = clean(name, 60).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
  if (name.length < 3) fail('Policy name needs 3+ characters (letters, digits, -).');
  const list = Array.isArray(origins) ? origins : String(origins || '').split(/[\s,]+/).filter(Boolean);
  const same = (await all('policies')).filter((p) => p.tenantId === tenantId && p.name === name);
  const p = { id: id('pol'), tenantId, name, version: Math.max(0, ...same.map((x) => x.version)) + 1, status: 'draft', createdBy: a.id, createdAt: Date.now(),
    config: { requireTpm: !!requireTpm, kioskLockdown: !!kioskLockdown, allowUsb: !!allowUsb, onViolation, origins: list.map((o) => o.trim()) } };
  await put('policies', p); await log(a, 'POLICY_DRAFTED', `${name} v${p.version}`);
  return p;
}
export async function requestPolicyPublication(a, pid, reason) {
  if (!can(a?.role, 'policy.publish') && !can(a?.role, 'exam.policy')) {
    fail('Permission denied: your role cannot request policy publication.');
  }
  const justification = requireReason(reason, 8);
  const p = await get('policies', pid);
  if (!p || p.status !== 'draft') fail('Only drafts can be published.');
  const all_ = await all('policies');
  const rules = (await all('rules')).filter((r) => r.tenantId === p.tenantId);
  const errs = validateConfig(p.config, rules); if (errs.length) fail(errs.join(' '));
  const prev = all_.filter((x) => x.tenantId === p.tenantId && x.name === p.name && x.status === 'published')
    .sort((a, b) => b.version - a.version)[0];
  if (prev && weakened(prev.config, p.config) && !can(a.role, 'policy.weaken')) fail('Weakening TPM, kiosk lockdown or USB rules needs a super admin.');
  if (prev && p.version <= prev.version) fail('Version must increase (anti-downgrade).');
  const request = await requestApproval(a, {
    kind: 'policy-publish',
    label: `Publish ${p.name} v${p.version}`,
    targetId: p.id,
    tenantId: p.tenantId,
    reason: justification,
    data: {
      policyId: p.id,
      policyName: p.name,
      policyVersion: p.version,
      replacesPolicyId: prev?.id || null,
      config: p.config,
    },
  });
  await log(a, 'POLICY_PUBLICATION_REQUESTED', `${p.name} v${p.version}: ${request.id}`);
  return request;
}

export async function publishPolicy(a) {
  need(a, 'policy.publish');
  fail('Direct policy publication is disabled. Submit a policy-publish approval request instead.');
}
export async function verifyPolicy(p) {
  if (!p.sig || !p.hash || (await sha256(bodyOf(p))) !== p.hash) return false;
  const k = await get('keys', 'policy-signer'); return !!k && verify(k.pub, p.hash, p.sig);
}
export async function discardDraft(a, p) { need(a, 'policy.edit'); if (p.status !== 'draft') fail('Only drafts can be discarded.'); await put('policies', { ...p, status: 'discarded' }); await log(a, 'POLICY_DISCARDED', `${p.name} v${p.version}`); }

// Two-person rollback: requester != approver; the old config is re-published as a NEW higher version.
export async function requestRollback(a, target, reason) {
  need(a, 'policy.rollback');
  if (!reason || reason.length < 8) fail('Give a reason of at least 8 characters.');
  if (target.status === 'published') fail('That version is already live.');
  if (target.status === 'draft' || target.status === 'discarded') fail('Pick a previously published version.');
  await requestApproval(a, {
    kind: 'policy-rollback', label: `Roll back ${target.name} to v${target.version}`,
    targetId: target.id, tenantId: target.tenantId, reason,
  });
  await log(a, 'ROLLBACK_REQUESTED', `${target.name} v${target.version}: ${reason}`);
  return 'Rollback requested. A different approver must confirm it.';
}
export const configDiff = (a, b) => {
  const out = [];
  for (const k of ['requireTpm', 'kioskLockdown', 'allowUsb', 'onViolation']) if (JSON.stringify(a?.[k]) !== JSON.stringify(b?.[k])) out.push({ key: k, from: a?.[k], to: b?.[k] });
  if (JSON.stringify(a?.origins) !== JSON.stringify(b?.origins)) out.push({ key: 'origins', from: (a?.origins || []).join(', '), to: (b?.origins || []).join(', ') });
  return out;
};
export const latestPublished = (policies, tenantId) => policies.filter((p) => p.tenantId === tenantId && p.status === 'published').sort((x, y) => y.createdAt - x.createdAt)[0];
