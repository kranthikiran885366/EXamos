import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason } from '../../core/services/common';
import { create as requestApproval } from '../../core/services/approvals';

export const PLAN_TEMPLATES = [
  {
    id: 'plan_pilot', name: 'Pilot', pricePerCandidate: 0, pricePerCenter: 0, interval: 'month',
    limits: { centers: 2, candidates: 250, devices: 100, storageGb: 5 },
    features: ['USB exam delivery', 'Attestation', 'Standard reports', 'Email support'],
  },
  {
    id: 'plan_standard', name: 'Standard', pricePerCandidate: 18, pricePerCenter: 2500, interval: 'month',
    limits: { centers: 10, candidates: 5000, devices: 2000, storageGb: 50 },
    features: ['Everything in Pilot', 'Two-person approvals', 'Custom policies', 'Priority support', 'Scheduled reports'],
  },
  {
    id: 'plan_enterprise', name: 'Enterprise', pricePerCandidate: 12, pricePerCenter: 1800, interval: 'year',
    limits: { centers: 100, candidates: 100000, devices: 50000, storageGb: 500 },
    features: ['Everything in Standard', 'Multi-campus governance', 'Dedicated support', 'Audit exports', 'Custom retention', 'SSO-ready integrations'],
  },
];
export const INVOICE_STATUSES = ['draft', 'open', 'paid', 'overdue', 'void', 'failed'];
export const USAGE_METRICS = [
  { key: 'candidates', label: 'Registered candidates' }, { key: 'centers', label: 'Exam centres' },
  { key: 'devices', label: 'Enrolled devices' }, { key: 'exams', label: 'Exams delivered' },
  { key: 'storageMb', label: 'Evidence storage (MB)' }, { key: 'support', label: 'Support requests' },
];

export async function ensurePlans() {
  const have = await all('plans');
  if (have.length) return have;
  for (const p of PLAN_TEMPLATES) await put('plans', { ...p, status: 'active', createdAt: Date.now() });
  return all('plans');
}

export async function createPlan(a, input) {
  need(a, 'billing.manage');
  const name = clean(input.name, 60); if (name.length < 2) fail('Plan name needs 2+ characters.');
  const p = {
    id: id('plan'), name, pricePerCandidate: Number(input.pricePerCandidate) || 0,
    pricePerCenter: Number(input.pricePerCenter) || 0, interval: input.interval === 'year' ? 'year' : 'month',
    limits: {
      centers: Number(input.centers) || 1, candidates: Number(input.candidates) || 100,
      devices: Number(input.devices) || 50, storageGb: Number(input.storageGb) || 5,
    },
    features: String(input.features || '').split('\n').map((f) => clean(f, 120)).filter(Boolean),
    status: 'active', createdAt: Date.now(), createdBy: a.id,
  };
  await put('plans', p); await log(a, 'PLAN_CREATED', p.name);
  return p;
}

export async function subscriptionFor(tenantId) {
  return (await all('subscriptions')).find((s) => s.tenantId === tenantId && ['active', 'trialing', 'past_due'].includes(s.status)) || null;
}

export async function startSubscription(a, { tenantId, planId, seats = 0, autoRenew = true, paymentMethod = 'invoice' }) {
  need(a, 'billing.manage'); assertScope(a, tenantId);
  const plan = await get('plans', planId); if (!plan || plan.status !== 'active') fail('Pick an active plan.');
  if (await subscriptionFor(tenantId)) fail('This institution already has an active subscription. Change the plan instead.');
  const sub = {
    id: id('sub'), tenantId, planId, status: 'active', seats: Number(seats) || 0, autoRenew: !!autoRenew,
    paymentMethod: clean(paymentMethod, 40), startedAt: Date.now(), renewsAt: Date.now() + (plan.interval === 'year' ? 365 : 30) * 864e5,
    history: [{ at: Date.now(), by: a.id, action: `Subscribed to ${plan.name}` }],
  };
  await put('subscriptions', sub); await log(a, 'SUBSCRIPTION_STARTED', `${tenantId} -> ${plan.name}`);
  return `Subscription started on ${plan.name}.`;
}

export async function changePlan(a, tenantId, planId, reason) {
  need(a, 'billing.manage'); assertScope(a, tenantId);
  const plan = await get('plans', planId); if (!plan || plan.status !== 'active') fail('Pick an active plan.');
  const sub = await subscriptionFor(tenantId); if (!sub) fail('There is no active subscription to change.');
  if (sub.planId === planId) fail('That is already the current plan.');
  const r = requireReason(reason, 8);
  if (a.role === 'superadmin') {
    await put('subscriptions', { ...sub, planId, history: [...(sub.history || []), { at: Date.now(), by: a.id, action: `Plan changed to ${plan.name}`, reason: r }] });
    await log(a, 'SUBSCRIPTION_PLAN_CHANGED', `${tenantId} -> ${plan.name}: ${r}`);
    return `Plan changed to ${plan.name}.`;
  }
  const ap = await requestApproval(a, { kind: 'billing-change', label: `${tenantId} → ${plan.name}`, targetId: sub.id, tenantId, reason: r, data: { planId } });
  return `Plan change requested (${ap.id}). A platform administrator must approve it.`;
}

export async function applyBillingChange(ap, approver) {
  const sub = await get('subscriptions', ap.targetId); if (!sub) fail('Subscription not found.');
  const plan = await get('plans', ap.data?.planId); if (!plan) fail('The requested plan no longer exists.');
  await put('subscriptions', { ...sub, planId: plan.id, history: [...(sub.history || []), { at: Date.now(), by: approver.id, action: `Plan changed to ${plan.name} by approval ${ap.id}` }] });
  await log(approver, 'SUBSCRIPTION_PLAN_CHANGED', `${sub.tenantId} -> ${plan.name} via ${ap.id}`);
  return `Subscription moved to ${plan.name}.`;
}

export async function setAutoRenew(a, sub, enabled) {
  need(a, 'billing.manage'); assertScope(a, sub.tenantId);
  await put('subscriptions', { ...sub, autoRenew: !!enabled });
  await log(a, 'SUBSCRIPTION_AUTORENEW', `${sub.tenantId} -> ${!!enabled}`);
  return `Auto-renew is now ${enabled ? 'on' : 'off'}.`;
}

export async function createInvoice(a, { tenantId, planId, seats = 0, taxPct = 18, dueDays = 15, notes = '' }) {
  need(a, 'billing.manage'); assertScope(a, tenantId);
  const plan = await get('plans', planId); if (!plan) fail('Pick a plan.');
  const usage = await computeUsage(tenantId);
  const sub = await subscriptionFor(tenantId);
  const qty = Number(seats) || sub?.seats || usage.candidates || 0;
  const candidatesLine = plan.pricePerCandidate * qty;
  const centersLine = plan.pricePerCenter * Math.max(1, usage.centers);
  const subtotal = candidatesLine + centersLine;
  const tax = Math.round(subtotal * (Number(taxPct) / 100) * 100) / 100;
  const count = (await all('invoices')).length + 1;
  const inv = {
    id: id('inv'), tenantId, number: `INV-${new Date().getFullYear()}-${String(count).padStart(4, '0')}`,
    planId, status: 'open', currency: 'INR', issuedAt: Date.now(), dueAt: Date.now() + (Number(dueDays) || 15) * 864e5,
    subtotal, tax, total: subtotal + tax, seats: qty, notes: clean(notes, 300),
    lines: [
      { label: `${plan.name} · candidate licences`, qty, unit: plan.pricePerCandidate, amount: candidatesLine },
      { label: `${plan.name} · centre licences`, qty: Math.max(1, usage.centers), unit: plan.pricePerCenter, amount: centersLine },
      { label: `Tax (${Number(taxPct) || 0}%)`, qty: 1, unit: tax, amount: tax },
    ],
    history: [{ at: Date.now(), by: a.id, action: 'Invoice issued' }],
  };
  await put('invoices', inv); await log(a, 'INVOICE_CREATED', `${inv.number} ${inv.total}`);
  return inv;
}

export async function markInvoice(a, inv, status, reason = '') {
  need(a, 'billing.manage'); assertScope(a, inv.tenantId);
  if (!INVOICE_STATUSES.includes(status)) fail('Unknown invoice status.');
  if (status === 'paid' && inv.status === 'paid') fail('This invoice is already paid.');
  const next = { ...inv, status, history: [...(inv.history || []), { at: Date.now(), by: a.id, action: `Status → ${status}`, reason: clean(reason, 200) }] };
  if (status === 'paid') { next.paidAt = Date.now(); next.paidBy = a.id; }
  await put('invoices', next);
  await log(a, 'INVOICE_' + status.toUpperCase(), `${inv.number}${reason ? ': ' + clean(reason, 100) : ''}`);
  return `${inv.number} marked ${status}.`;
}

export async function computeUsage(tenantId, ctx = {}) {
  const { candidates = await all('candidates'), centers = await all('centers'), devices = await all('devices'), exams = await all('exams'), evidence = await all('evidence'), support = await all('support') } = ctx;
  const f = (r) => r.tenantId === tenantId;
  const storageMb = Math.round(evidence.filter(f).reduce((s, e) => s + (e.size || 0), 0) / 1048576 * 100) / 100;
  return {
    candidates: candidates.filter(f).length, centers: centers.filter(f).length, devices: devices.filter(f).length,
    exams: exams.filter(f).length, storageMb, support: support.filter(f).length,
  };
}

export function usageAgainstPlan(usage, plan) {
  if (!plan) return [];
  return [
    { key: 'centers', label: 'Centres', used: usage.centers, limit: plan.limits.centers },
    { key: 'candidates', label: 'Candidates', used: usage.candidates, limit: plan.limits.candidates },
    { key: 'devices', label: 'Devices', used: usage.devices, limit: plan.limits.devices },
    { key: 'storageMb', label: 'Storage (MB)', used: usage.storageMb, limit: plan.limits.storageGb * 1024 },
  ].map((x) => ({ ...x, pct: x.limit ? Math.min(999, Math.round((x.used / x.limit) * 1000) / 10) : 0, over: x.used > x.limit }));
}

export function billingStats(subs, invoices) {
  const paid = invoices.filter((i) => i.status === 'paid');
  return {
    activeSubscriptions: subs.filter((s) => s.status === 'active').length,
    mrr: subs.filter((s) => s.status === 'active').length,
    outstanding: invoices.filter((i) => ['open', 'overdue'].includes(i.status)).reduce((s, i) => s + (i.total || 0), 0),
    overdue: invoices.filter((i) => i.status === 'overdue').length,
    paidTotal: paid.reduce((s, i) => s + (i.total || 0), 0),
    invoices: invoices.length,
  };
}

export const invoiceStats = (list) => ({
  total: list.length,
  open: list.filter((i) => i.status === 'open').length,
  overdue: list.filter((i) => i.status === 'overdue').length,
  paid: list.filter((i) => i.status === 'paid').length,
  outstanding: list.filter((i) => ['open', 'overdue'].includes(i.status)).reduce((s, i) => s + (i.total || 0), 0),
  collected: list.filter((i) => i.status === 'paid').reduce((s, i) => s + (i.total || 0), 0),
});
