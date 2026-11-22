import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { usePerm, useLoad } from '../../core/ui/hooks';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, KeyValue, Progress, Tabs, Modal, Field, Input, Select, Textarea, Loading,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import { resolvePlan } from '../../core/ui/normalizers';
import { getReport } from '../reports/service';
import {
  ensurePlans, createPlan, subscriptionFor, startSubscription, changePlan, setAutoRenew,
  createInvoice, markInvoice, computeUsage, usageAgainstPlan, invoiceStats, billingStats,
  PLAN_TEMPLATES, INVOICE_STATUSES,
} from './service';
import { normalizeExamUsageSummary } from './usage';

const money = (n) => `₹${Number(n || 0).toLocaleString('en-IN', { maximumFractionDigits: 2 })}`;
const planLabel = (p) => `${p.name} · ${p.interval === 'year' ? 'yearly' : 'monthly'}`;

function PlanCards({ plans, currentPlanId, onChoose, canChoose }) {
  return (
    <div className="plangrid">
      {plans.map((p) => {
        const current = p.id === currentPlanId;
        return <div key={p.id} className={'card plan' + (current ? ' current' : '')}>
          <div className="plan-head"><b>{p.name}</b>{current && <Badge value="current" />}</div>
          <div className="plan-price">{money(p.pricePerCandidate)}<small>/candidate</small></div>
          <div className="muted sm">{money(p.pricePerCenter)} / centre · {p.interval === 'year' ? 'yearly' : 'monthly'}</div>
          <ul className="plan-feats">
            <li>{p.limits.centers} centres</li>
            <li>{p.limits.candidates.toLocaleString('en-IN')} candidates</li>
            <li>{p.limits.devices.toLocaleString('en-IN')} devices</li>
            <li>{p.limits.storageGb} GB evidence storage</li>
            {(p.features || []).map((f) => <li key={f}>
              {String(f).trim().toLowerCase() === 'scheduled reports' ? 'Scheduled reports (not available)' : f}
            </li>)}
          </ul>
          <button className="btn" disabled={current || !canChoose} onClick={() => onChoose(p)}>{current ? 'Current plan' : 'Choose plan'}</button>
        </div>;
      })}
    </div>
  );
}

export function SubscriptionPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const { data, loading, error, reload } = useLoad(async () => ({
    sub: await subscriptionFor(tenantId), plans: await ensurePlans(), usage: await computeUsage(tenantId),
  }), [tenantId]);
  const { msg, setMsg, run, busy } = useFlash();
  const [choose, setChoose] = useState(null);
  const [start, setStart] = useState(false);
  const [reason, setReason] = useState('');

  if (loading && !data) return <Page title="Subscription"><Card><Loading label="Loading subscription…" /></Card></Page>;
  if (error) return <Page title="Subscription"><Alert tone="danger">{error.message}</Alert></Page>;
  const { sub, plans, usage } = data || {};
  const plan = resolvePlan(plans, sub?.planId);
  const planValue = !sub?.planId ? 'Not assigned' : plan?.name || `Unrecognized plan (${sub.planId})`;
  const against = plan ? usageAgainstPlan(usage, plan) : [];
  const over = against.filter((a) => a.over);

  const doChoose = async () => {
    const ok = await run(() => sub ? changePlan(user, tenantId, choose.id, reason) : startSubscription(user, { tenantId, planId: choose.id, seats: usage.candidates }), 'Subscription updated.');
    if (ok) { setChoose(null); setReason(''); setStart(false); reload(); }
  };

  return (
    <Page
      title="Subscription"
      desc="Plan, usage limits and billing status for your institution."
      actions={<Link className="btn" to="/admin/billing">Invoices & billing</Link>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {!sub ? <>
        <Alert tone="info" title="No active subscription">Choose a plan to activate billing. Pilot is free and suitable for a first evaluation.</Alert>
        <Card title="Available plans"><PlanCards plans={plans || []} currentPlanId={null} canChoose={may('billing.manage')} onChoose={(p) => { setChoose(p); setStart(true); }} /></Card>
      </> : <>
        <StatGrid cols={4}>
          <Stat label="Plan" value={planValue} icon="card" sub={plan ? `${plan.interval}ly` : ''} />
          <Stat label="Status" value={sub.status} icon={sub.status === 'active' ? 'check' : 'warn'} tone={sub.status === 'active' ? 'green' : 'amber'} />
          <Stat label="Seats" value={sub.seats || usage.candidates} icon="candidate" sub={`${usage.candidates} candidates in use`} />
          <Stat label="Renews" value={sub.renewsAt ? fmt(sub.renewsAt) : '—'} icon="clock" sub={sub.autoRenew ? 'Auto-renew on' : 'Auto-renew off'} />
        </StatGrid>
        {over.length > 0 && <Alert tone="warn" title="Plan limits exceeded">{over.map((o) => o.label).join(', ')} exceed the current plan. Upgrade to avoid disruption.</Alert>}
        <Card title="Current subscription">
          <KeyValue cols={3} items={[
            ['Plan', plan ? planLabel(plan) : planValue], ['Status', <Badge value={sub.status} />],
            ['Started', fmt(sub.startedAt)], ['Renews', sub.renewsAt ? fmt(sub.renewsAt) : '—'],
            ['Auto-renew', sub.autoRenew ? 'On' : 'Off'], ['Payment method', sub.paymentMethod || 'invoice'],
            ['Candidate price', plan ? money(plan.pricePerCandidate) : '—'], ['Centre price', plan ? money(plan.pricePerCenter) : '—'],
            ['Support', plan ? `${plan.limits.centers} centres · ${plan.limits.devices} devices` : '—'],
          ]} />
          <div className="row gap mt">
            <button className="btn" disabled={!may('billing.manage') || busy} onClick={() => run(async () => {
              await setAutoRenew(user, sub, !sub.autoRenew); reload();
              return `Auto-renew ${sub.autoRenew ? 'disabled' : 'enabled'}.`;
            })}>{sub.autoRenew ? 'Turn off auto-renew' : 'Turn on auto-renew'}</button>
            <Link className="btn" to="/admin/usage">View usage</Link>
          </div>
        </Card>
        <Card title="Usage against plan">
          <div className="stack">
            {against.map((a) => <Progress key={a.key} label={`${a.label} · ${a.used.toLocaleString('en-IN')} / ${a.limit.toLocaleString('en-IN')}`} value={a.used} max={a.limit} tone={a.over ? 'r' : a.pct > 80 ? 'a' : 'g'} />)}
          </div>
        </Card>
        <Card title="Change plan" desc="Platform administrators can change immediately; institution users submit a two-person approval.">
          <PlanCards plans={plans || []} currentPlanId={plan?.id || null} canChoose={may('billing.manage')} onChoose={(p) => setChoose(p)} />
        </Card>
      </>}

      {choose && <Modal title={sub ? `Change to ${choose.name}` : `Start ${choose.name}`} desc={sub ? 'A plan change is recorded in the audit trail.' : 'Billing starts when the subscription is activated.'} onClose={() => setChoose(null)} footer={<><button className="btn" onClick={() => setChoose(null)}>Cancel</button><button className="btn primary" form="plan-form" disabled={busy}>{busy ? 'Saving…' : sub ? 'Request change' : 'Start subscription'}</button></>}>
        <form id="plan-form" className="stack" onSubmit={(e) => { e.preventDefault(); doChoose(); }}>
          <Flash msg={msg} onClose={() => setMsg(null)} />
          <KeyValue cols={2} items={[['Plan', choose.name], ['Candidate price', money(choose.pricePerCandidate)], ['Centre price', money(choose.pricePerCenter)], ['Interval', choose.interval]]} />
          {sub && <Field label="Reason" required help="At least 8 characters."><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} autoFocus /></Field>}
        </form>
      </Modal>}
    </Page>
  );
}

function InvoiceModal({ tenantId, plans, sub, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ planId: resolvePlan(plans, sub?.planId)?.id || plans[0]?.id || '', seats: sub?.seats || 0, taxPct: 18, dueDays: 15, notes: '' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(async () => {
      const inv = await createInvoice(user, { tenantId, ...v, seats: Number(v.seats), taxPct: Number(v.taxPct), dueDays: Number(v.dueDays) });
      return `Invoice ${inv.number} issued for ${money(inv.total)}.`;
    });
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Create invoice" desc="Amounts are calculated from the plan, current usage and tax." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="invoice-form" disabled={busy}>{busy ? 'Creating…' : 'Create invoice'}</button></>}>
      <form id="invoice-form" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <div className="formgrid">
          <Field label="Plan"><Select value={v.planId} onChange={(e) => set('planId', e.target.value)} options={plans.map((p) => ({ v: p.id, l: `${p.name} · ${money(p.pricePerCandidate)}/candidate` }))} placeholder={false} /></Field>
          <Field label="Seats" help="Blank uses the subscription or usage count"><Input type="number" min={0} value={v.seats} onChange={(e) => set('seats', e.target.value)} /></Field>
          <Field label="Tax (%)"><Input type="number" min={0} max={28} value={v.taxPct} onChange={(e) => set('taxPct', e.target.value)} /></Field>
          <Field label="Due in (days)"><Input type="number" min={1} max={90} value={v.dueDays} onChange={(e) => set('dueDays', e.target.value)} /></Field>
          <Field label="Notes" className="span2"><Textarea rows={2} value={v.notes} onChange={(e) => set('notes', e.target.value)} maxLength={300} /></Field>
        </div>
      </form>
    </Modal>
  );
}

function PlanModal({ onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ name: '', pricePerCandidate: 18, pricePerCenter: 2500, interval: 'month', centers: 10, candidates: 5000, devices: 2000, storageGb: 50, features: '' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(async () => {
      const p = await createPlan(user, v);
      return `Plan ${p.name} created.`;
    });
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Create plan" desc="Custom plans can be assigned to institutions by a platform administrator." onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="plan-create" disabled={busy}>{busy ? 'Creating…' : 'Create plan'}</button></>}>
      <form id="plan-create" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <div className="formgrid">
          <Field label="Name" required><Input value={v.name} onChange={(e) => set('name', e.target.value)} maxLength={60} autoFocus /></Field>
          <Field label="Interval"><Select value={v.interval} onChange={(e) => set('interval', e.target.value)} options={[{ v: 'month', l: 'Monthly' }, { v: 'year', l: 'Yearly' }]} placeholder={false} /></Field>
          <Field label="Price per candidate"><Input type="number" min={0} value={v.pricePerCandidate} onChange={(e) => set('pricePerCandidate', e.target.value)} /></Field>
          <Field label="Price per centre"><Input type="number" min={0} value={v.pricePerCenter} onChange={(e) => set('pricePerCenter', e.target.value)} /></Field>
          <Field label="Centre limit"><Input type="number" min={1} value={v.centers} onChange={(e) => set('centers', e.target.value)} /></Field>
          <Field label="Candidate limit"><Input type="number" min={1} value={v.candidates} onChange={(e) => set('candidates', e.target.value)} /></Field>
          <Field label="Device limit"><Input type="number" min={1} value={v.devices} onChange={(e) => set('devices', e.target.value)} /></Field>
          <Field label="Storage (GB)"><Input type="number" min={1} value={v.storageGb} onChange={(e) => set('storageGb', e.target.value)} /></Field>
          <Field label="Features" className="span2" help="One per line"><Textarea rows={4} value={v.features} onChange={(e) => set('features', e.target.value)} /></Field>
        </div>
      </form>
    </Modal>
  );
}

export function BillingPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const invoices = useCol('invoices');
  const { data, loading, reload } = useLoad(async () => ({ plans: await ensurePlans(), sub: await subscriptionFor(tenantId) }), [tenantId]);
  const { msg, setMsg, run, busy } = useFlash();
  const [tab, setTab] = useState('invoices');
  const [create, setCreate] = useState(false);
  const [planOpen, setPlanOpen] = useState(false);
  const [pending, setPending] = useState(null);
  const plans = data?.plans || [];
  const sub = data?.sub;
  const currentPlan = resolvePlan(plans, sub?.planId);
  const stats = invoiceStats(invoices);

  return (
    <Page
      title="Plans & billing"
      desc="Invoices, payment reconciliation and commercial plan catalogue."
      actions={<>
        <Link className="btn" to="/college/subscription">Subscription</Link>
        {tab === 'invoices' ? <button className="btn primary" disabled={!may('billing.manage') || !plans.length} onClick={() => setCreate(true)}><Icon name="plus" size={15} /> New invoice</button>
          : <button className="btn primary" disabled={!may('billing.manage')} onClick={() => setPlanOpen(true)}><Icon name="plus" size={15} /> New plan</button>}
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Invoices" value={stats.total} icon="card" />
        <Stat label="Outstanding" value={money(stats.outstanding)} icon="clock" tone={stats.overdue ? 'red' : 'amber'} sub={`${stats.overdue} overdue`} />
        <Stat label="Collected" value={money(stats.collected)} icon="check" tone="green" />
        <Stat label="Active plan" value={sub?.planId ? currentPlan?.name || `Unrecognized plan (${sub.planId})` : 'Not assigned'} icon="package" sub={sub ? sub.status : 'No subscription'} />
      </StatGrid>

      <Card pad>
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: 'invoices', label: 'Invoices', count: invoices.length },
          { key: 'plans', label: 'Plan catalogue', count: plans.length },
        ]} />
        {tab === 'invoices' ? <DataTable
          rows={invoices}
          search={(i) => `${i.number} ${i.status} ${i.total}`}
          filters={[{ key: 'status', label: 'Any status', options: INVOICE_STATUSES.map((s) => ({ v: s, l: s })) }]}
          columns={[
            { label: 'Invoice', render: (i) => <><b>{i.number}</b><br /><small className="muted">{fmt(i.issuedAt)}</small></> },
            { label: 'Plan', render: (i) => i.planId ? resolvePlan(plans, i.planId)?.name || `Unrecognized plan (${i.planId})` : 'Not assigned' },
            { label: 'Subtotal', render: (i) => money(i.subtotal) },
            { label: 'Tax', render: (i) => money(i.tax) },
            { label: 'Total', render: (i) => <b>{money(i.total)}</b> },
            { label: 'Status', key: 'status', badge: true },
            { label: 'Due', render: (i) => i.dueAt ? <span title={fmt(i.dueAt)}>{fmt(i.dueAt)}</span> : '—' },
            { label: 'Paid', render: (i) => i.paidAt ? fmt(i.paidAt) : '—' },
          ]}
          actions={(i) => [
            { label: 'Mark paid', disabled: !may('billing.manage') || i.status === 'paid', onClick: () => setPending({ i, status: 'paid' }) },
            { label: 'Mark overdue', disabled: !may('billing.manage') || !['open'].includes(i.status), onClick: () => run(() => markInvoice(user, i, 'overdue'), 'Invoice marked overdue.') },
            { label: 'Void', danger: true, disabled: !may('billing.manage') || ['paid', 'void'].includes(i.status), onClick: () => setPending({ i, status: 'void' }) },
          ]}
          empty={<Empty icon="card" title="No invoices yet">Create an invoice from the active plan and current usage.</Empty>}
        /> : <div>
          {loading && !plans.length ? <Loading /> : <PlanCards plans={plans} currentPlanId={currentPlan?.id || null} canChoose={false} onChoose={() => {}} />}
          {sub && <Alert tone="info" title="Institution subscription">{sub.planId ? currentPlan?.name || `Unrecognized plan (${sub.planId})` : 'Not assigned'} · {sub.status} · renews {fmt(sub.renewsAt)}</Alert>}
        </div>}
      </Card>

      {create && <InvoiceModal tenantId={tenantId} plans={plans} sub={sub} onClose={() => setCreate(false)} onDone={reload} />}
      {planOpen && <PlanModal onClose={() => setPlanOpen(false)} onDone={reload} />}
      {pending && <ActionDialog
        title={`${pending.status === 'paid' ? 'Mark paid' : 'Void'} · ${pending.i.number}`}
        desc={pending.status === 'paid' ? 'Payment is recorded against the invoice and written to the audit trail.' : 'Voiding is permanent. A new invoice is required for any further billing.'}
        danger={pending.status === 'void'}
        confirmLabel={pending.status === 'paid' ? 'Mark paid' : 'Void invoice'}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason) => { await run(() => markInvoice(user, pending.i, pending.status, reason)); setPending(null); }}
      />}
    </Page>
  );
}

export function UsagePage() {
  const { tenantId } = useTenant();
  const { data, loading, error, reload } = useLoad(async () => {
    const plans = await ensurePlans();
    const sub = await subscriptionFor(tenantId);
    return { usage: await computeUsage(tenantId), sub, plan: resolvePlan(plans, sub?.planId) };
  }, [tenantId]);
  const examUsage = useLoad(async () => {
    if (!tenantId) throw new Error('Select an institution to load scoped exam usage.');
    const report = await getReport('exams', 'exam-summary', {}, tenantId);
    return normalizeExamUsageSummary(report.summary);
  }, [tenantId]);
  if (loading && !data) return <Page title="Usage"><Card><Loading label="Computing usage…" /></Card></Page>;
  if (error) return <Page title="Usage"><Alert tone="danger">{error.message}</Alert></Page>;
  const { usage, plan, sub } = data;
  const against = plan ? usageAgainstPlan(usage, plan) : [];
  return (
    <Page title="Usage" desc="Candidate, centre and device totals use workspace records. Exam lifecycle counts come from the tenant-scoped server report." actions={<button className="btn" onClick={() => { reload(); examUsage.reload(); }}><Icon name="refresh" size={14} /> Refresh</button>}>
      <StatGrid cols={3}>
        <Stat label="Candidates" value={usage.candidates.toLocaleString('en-IN')} icon="candidate" />
        <Stat label="Centres" value={usage.centers} icon="building" />
        <Stat label="Devices" value={usage.devices} icon="device" />
      </StatGrid>
      <StatGrid cols={4}>
        <Stat label="Exam records created" value={examUsage.data?.created ?? (examUsage.loading ? '…' : '—')} icon="exam" />
        <Stat label="Exams published" value={examUsage.data?.published ?? (examUsage.loading ? '…' : '—')} icon="check" />
        <Stat label="Exams attempted" value={examUsage.data?.attempted ?? (examUsage.loading ? '…' : '—')} icon="pulse" />
        <Stat label="Exams finalized" value={examUsage.data?.completed ?? (examUsage.loading ? '…' : '—')} icon="check" />
      </StatGrid>
      {examUsage.error && <Alert tone="warn" title="Exam usage unavailable">{examUsage.error.message}</Alert>}
      <Alert tone="info" title="Billable exams: not tracked">
        Current plans are priced by candidates and centres. Drafts, publication, retries and finalization do not create an exam charge.
      </Alert>
      {!plan ? <Alert tone="warn" title="No active plan">Subscribe to a plan to compare usage against purchased limits.</Alert> : <Card title={`Usage vs ${plan.name}`} desc={`${sub?.status || 'active'} · renews ${fmt(sub?.renewsAt)}`}>
        <div className="stack">
          {against.map((a) => <Progress key={a.key} label={`${a.label} · ${a.used.toLocaleString('en-IN')} / ${a.limit.toLocaleString('en-IN')}`} value={a.used} max={a.limit} tone={a.over ? 'r' : a.pct > 80 ? 'a' : 'g'} />)}
        </div>
        <DataTable rows={against.map((a) => ({ ...a, status: a.over ? 'over limit' : a.pct > 80 ? 'near limit' : 'within limit' }))} columns={[
          { label: 'Metric', key: 'label' }, { label: 'Used', render: (a) => a.used.toLocaleString('en-IN') },
          { label: 'Limit', render: (a) => a.limit.toLocaleString('en-IN') },
          { label: 'Utilisation', render: (a) => `${a.pct}%` }, { label: 'Status', key: 'status', badge: true },
        ]} />
      </Card>}
      <Card title="Other consumption">
        <KeyValue cols={2} items={[['Support requests', usage.support], ['Evidence storage', `${usage.storageMb} MB`]]} />
      </Card>
    </Page>
  );
}
