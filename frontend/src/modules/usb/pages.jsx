import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol, useColLoaded } from '../../core/db/tenant';
import { usePerm } from '../../core/ui/hooks';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, KeyValue, Timeline, Modal, Field, Input, Select, Textarea, Checkbox, Loading,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import {
  createUsb, prepareUsb, issueUsb, returnUsb, setUsbStatus, reportUsb, inventoryCheck,
  usbStats, HARDWARE_MODELS, STATUSES,
} from './service';

const FILTER_STATUS = STATUSES.map((s) => ({ v: s, l: s }));

function RegisterModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ assetId: '', serial: '', model: HARDWARE_MODELS[0], capacityGb: 64, notes: '' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(async () => {
      const u = await createUsb(user, { tenantId, ...v, capacityGb: Number(v.capacityGb) });
      return `USB ${u.assetId} registered. Prepare it with an approved release before issue.`;
    });
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Register USB asset" desc="The hardware serial is unique. Registration does not write an image." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="usb-reg" disabled={busy}>{busy ? 'Saving…' : 'Register asset'}</button></>}>
      <form id="usb-reg" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <div className="formgrid">
          <Field label="Asset ID" required help="4–40 letters, digits or dashes"><Input value={v.assetId} onChange={(e) => set('assetId', e.target.value.toUpperCase())} placeholder="USB-NORTH-001" maxLength={40} autoFocus /></Field>
          <Field label="Hardware serial" required help="6–40 letters, digits or dashes"><Input value={v.serial} onChange={(e) => set('serial', e.target.value.toUpperCase())} maxLength={40} /></Field>
          <Field label="Model"><Select value={v.model} onChange={(e) => set('model', e.target.value)} options={HARDWARE_MODELS} placeholder={false} /></Field>
          <Field label="Capacity (GB)"><Input type="number" min={8} max={1024} value={v.capacityGb} onChange={(e) => set('capacityGb', e.target.value)} /></Field>
          <Field label="Notes" className="span2"><Textarea rows={2} value={v.notes} onChange={(e) => set('notes', e.target.value)} maxLength={300} /></Field>
        </div>
      </form>
    </Modal>
  );
}

function PrepareModal({ usb, releases, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const approved = releases.filter((r) => ['approved', 'rolling', 'stable'].includes(r.status));
  const [v, setV] = useState({ releaseId: approved[0]?.id || '', station: 'exam-console', writtenHash: approved[0]?.digest || '', confirmation: '', target: false });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const rel = approved.find((r) => r.id === v.releaseId);
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => prepareUsb(user, usb, {
      releaseId: v.releaseId, station: v.station, writtenHash: v.writtenHash,
      confirmation: v.confirmation, target: v.target ? 'removable-usb' : '',
    }), 'USB prepared and hash-verified.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title={`Prepare ${usb.assetId}`} desc="The image is written to the removable USB and verified against the signed release manifest." onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="usb-prep" disabled={busy || !v.target}>{busy ? 'Preparing…' : 'Prepare & verify'}</button></>}>
      <form id="usb-prep" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Alert tone="warn" title="Destructive operation">This erases the target device. Internal disks are never eligible — confirm the removable target explicitly.</Alert>
        <div className="formgrid">
          <Field label="Approved release" required><Select value={v.releaseId} onChange={(e) => { const r = approved.find((x) => x.id === e.target.value); setV((s) => ({ ...s, releaseId: e.target.value, writtenHash: r?.digest || '' })); }} options={approved.map((r) => ({ v: r.id, l: `${r.version} · ${r.status}` }))} placeholder="Choose a release" /></Field>
          <Field label="Preparation station" required><Input value={v.station} onChange={(e) => set('station', e.target.value)} maxLength={60} /></Field>
          <Field label="Written image SHA-256" className="span2" help="Defaults to the approved manifest digest. A mismatch quarantines the USB."><Input className="mono" value={v.writtenHash} onChange={(e) => set('writtenHash', e.target.value)} maxLength={64} /></Field>
          <Field label={`Type ${usb.assetId} to confirm`} className="span2" required><Input value={v.confirmation} onChange={(e) => set('confirmation', e.target.value.toUpperCase())} autoComplete="off" /></Field>
        </div>
        <Checkbox label="I have selected the removable USB target (not an internal disk)" checked={v.target} onChange={(e) => set('target', e.target.checked)} />
        {rel && <p className="muted sm">Manifest digest: <code>{rel.digest?.slice(0, 24)}…</code> · signature verified before writing.</p>}
      </form>
    </Modal>
  );
}

function IssueModal({ usb, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ holderName: '', holderId: '', reason: 'Exam delivery' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => issueUsb(user, usb, v), 'USB issued.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title={`Issue ${usb.assetId}`} desc="A signed custody receipt is generated for the holder." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="usb-issue" disabled={busy}>{busy ? 'Issuing…' : 'Issue USB'}</button></>}>
      <form id="usb-issue" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="Holder name" required><Input value={v.holderName} onChange={(e) => set('holderName', e.target.value)} maxLength={80} autoFocus /></Field>
        <Field label="Holder ID"><Input value={v.holderId} onChange={(e) => set('holderId', e.target.value)} maxLength={40} placeholder="Staff or candidate ID" /></Field>
        <Field label="Reason" required help="At least 5 characters."><Input value={v.reason} onChange={(e) => set('reason', e.target.value)} maxLength={200} /></Field>
      </form>
    </Modal>
  );
}

function ReturnModal({ usb, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [condition, setCondition] = useState('good');
  const [reason, setReason] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => returnUsb(user, usb, { condition, reason }), 'USB returned.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title={`Return ${usb.assetId}`} desc="A non-good condition quarantines the USB for inspection." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="usb-return" disabled={busy}>{busy ? 'Recording…' : 'Record return'}</button></>}>
      <form id="usb-return" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="Condition"><Select value={condition} onChange={(e) => setCondition(e.target.value)} options={[{ v: 'good', l: 'Good — return to inventory' }, { v: 'damaged', l: 'Damaged — quarantine' }, { v: 'tampered', l: 'Tampered — quarantine' }]} placeholder={false} /></Field>
        <Field label="Notes"><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} placeholder="Optional condition notes" /></Field>
      </form>
    </Modal>
  );
}

function InventoryModal({ usb, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [present, setPresent] = useState(true);
  const [location, setLocation] = useState(usb.lastLocation || '');
  const [reason, setReason] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => inventoryCheck(user, usb, { present, location, reason }), 'Inventory check recorded.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title={`Inventory check · ${usb.assetId}`} desc="Record whether the asset was physically sighted during the stock check." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="usb-inv" disabled={busy}>{busy ? 'Saving…' : 'Record check'}</button></>}>
      <form id="usb-inv" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Checkbox label="Asset present and sighted" checked={present} onChange={(e) => setPresent(e.target.checked)} />
        <Field label="Location"><Input value={location} onChange={(e) => setLocation(e.target.value)} maxLength={80} placeholder="Strongroom cabinet B" /></Field>
        {!present && <Field label="Why is it missing?" required><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} /></Field>}
      </form>
    </Modal>
  );
}

export function UsbInventoryPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const navigate = useNavigate();
  const usbs = useCol('usbs');
  const releases = useCol('releases');
  const centers = useCol('centers');
  const { msg, setMsg, run, busy } = useFlash();
  const [register, setRegister] = useState(false);
  const [prepare, setPrepare] = useState(null);
  const [issue, setIssue] = useState(null);
  const [ret, setRet] = useState(null);
  const [inventory, setInventory] = useState(null);
  const [pending, setPending] = useState(null);
  const stats = usbStats(usbs);

  const releaseVersion = (id) => releases.find((r) => r.id === id)?.version || '—';
  const centerCode = (id) => centers.find((c) => c.id === id)?.code || '—';

  return (
    <Page
      title="USB inventory"
      desc="Register, prepare, issue and reconcile bootable USB assets. Custody is signed and hash-verified."
      actions={<button className="btn primary" disabled={!may('usb.manage')} onClick={() => setRegister(true)}><Icon name="plus" size={15} /> Register USB</button>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Assets" value={stats.total} icon="usb" sub={`${stats.prepared} prepared`} />
        <Stat label="Issued" value={stats.issued} icon="candidate" tone="amber" />
        <Stat label="Returned" value={stats.returned} icon="check" tone="green" />
        <Stat label="Quarantined / revoked" value={stats.quarantined + stats.revoked} icon="warn" tone={stats.quarantined + stats.revoked ? 'red' : 'blue'} />
      </StatGrid>
      {stats.stale > 0 && <Alert tone="warn" title={`${stats.stale} asset(s) overdue for an inventory check`}>Assets not sighted in 30 days should be reconciled before the next exam window.</Alert>}

      <Card title="USB assets">
        <DataTable
          rows={usbs}
          search={(u) => `${u.assetId} ${u.serial} ${u.model} ${u.status} ${u.holder?.name || ''}`}
          filters={[
            { key: 'status', label: 'All statuses', options: FILTER_STATUS },
            { key: 'centerId', label: 'Any centre', get: (u) => u.assigned?.centerId || '', options: centers.map((c) => ({ v: c.id, l: c.code })) },
          ]}
          columns={[
            { label: 'Asset ID', render: (u) => <Link to={`/usb-inventory/${u.id}`}><b>{u.assetId}</b></Link> },
            { label: 'Release', render: (u) => releaseVersion(u.releaseId) },
            { label: 'Status', key: 'status', badge: true },
            { label: 'Model', key: 'model' },
            { label: 'Holder', render: (u) => u.holder ? <><b>{u.holder.name}</b><br /><small className="muted">since {fmt(u.holder.since)}</small></> : '—' },
            { label: 'Centre', render: (u) => centerCode(u.assigned?.centerId) },
            { label: 'Last check', render: (u) => <span title={fmt(u.lastCheckAt)}>{ago(u.lastCheckAt)}</span> },
            { label: 'Digest', render: (u) => u.imageDigest ? <code title={u.imageDigest}>{u.imageDigest.slice(0, 10)}…</code> : '—' },
          ]}
          actions={(u) => [
            { label: 'Open', onClick: () => navigate(`/usb-inventory/${u.id}`) },
            { label: 'Prepare', disabled: !may('usb.manage') || u.status === 'issued' || ['revoked', 'retired'].includes(u.status), onClick: () => setPrepare(u) },
            { label: 'Issue', disabled: !may('usb.manage') || !['prepared', 'verified', 'returned'].includes(u.status), onClick: () => setIssue(u) },
            { label: 'Return', disabled: !may('usb.manage') || u.status !== 'issued', onClick: () => setRet(u) },
            { label: 'Inventory check', disabled: !may('usb.manage'), onClick: () => setInventory(u) },
            { label: 'Report incident', danger: true, disabled: !may('usb.manage'), onClick: () => setPending({ kind: 'report', u }) },
            { label: 'Change status', disabled: !may('usb.manage'), onClick: () => setPending({ kind: 'status', u }) },
          ]}
          empty={<Empty icon="usb" title="No USB assets registered">Register an asset, prepare it with an approved release, then issue it to a centre.</Empty>}
        />
      </Card>

      {register && <RegisterModal tenantId={tenantId} onClose={() => setRegister(false)} onDone={() => {}} />}
      {prepare && <PrepareModal usb={prepare} releases={releases} onClose={() => setPrepare(null)} onDone={() => {}} />}
      {issue && <IssueModal usb={issue} onClose={() => setIssue(null)} onDone={() => {}} />}
      {ret && <ReturnModal usb={ret} onClose={() => setRet(null)} onDone={() => {}} />}
      {inventory && <InventoryModal usb={inventory} onClose={() => setInventory(null)} onDone={() => {}} />}

      {pending?.kind === 'report' && <ActionDialog
        title={`Report ${pending.u.assetId}`}
        desc="Lost or stolen assets raise a security incident. Damaged assets are quarantined for inspection."
        danger
        confirmLabel="Report incident"
        field={{ label: 'Report type', type: 'select', options: [{ v: 'lost', l: 'Lost' }, { v: 'stolen', l: 'Stolen' }, { v: 'damaged', l: 'Damaged' }] }}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason, kind) => { await run(() => reportUsb(user, pending.u, { kind, reason })); setPending(null); }}
      />}
      {pending?.kind === 'status' && <ActionDialog
        title={`Change status · ${pending.u.assetId}`}
        desc="Revoking needs a security role. Retired assets cannot be re-imaged."
        danger
        confirmLabel="Update status"
        field={{ label: 'New status', type: 'select', options: [{ v: 'quarantined', l: 'Quarantined' }, { v: 'revoked', l: 'Revoked' }, { v: 'retired', l: 'Retired' }] }}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason, status) => { await run(() => setUsbStatus(user, pending.u, status, reason)); setPending(null); }}
      />}
    </Page>
  );
}

// The list action needs router navigation; keep it local so the page stays declarative.
export function UsbDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const may = usePerm();
  const { rows: usbs, loaded } = useColLoaded('usbs');
  const releases = useCol('releases');
  const centers = useCol('centers');
  const { msg, setMsg, run, busy } = useFlash();
  const [prepare, setPrepare] = useState(false);
  const [issue, setIssue] = useState(false);
  const [ret, setRet] = useState(false);
  const [inventory, setInventory] = useState(false);
  const [pending, setPending] = useState(null);

  const u = usbs.find((x) => x.id === id);
  if (!loaded) return <Page title="USB asset"><Loading /></Page>;
  if (!u) return <Page title="USB asset"><Empty icon="usb" title="No such USB asset" action={<Link className="btn" to="/usb-inventory">Back to inventory</Link>} /></Page>;

  const rel = releases.find((r) => r.id === u.releaseId);
  const center = centers.find((c) => c.id === u.assigned?.centerId);
  const timeline = [...(u.custody || [])].reverse().map((c, i) => ({
    id: `${c.at}-${i}`, title: c.action, meta: `${fmt(c.at)} · ${c.by || 'system'}${c.station ? ' · ' + c.station : ''}${c.hash ? ' · ' + c.hash.slice(0, 12) + '…' : ''}`,
    tone: /lost|stolen|damaged|quarantine/i.test(c.action) ? 'r' : /issued/i.test(c.action) ? 'a' : 'g',
  }));

  return (
    <Page
      title={u.assetId}
      desc={`USB asset · ${u.status}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/usb-inventory">USB inventory</Link><Icon name="arrow" size={12} /><span>{u.assetId}</span></div>}
      actions={<>
        <button className="btn" disabled={!may('usb.manage') || u.status === 'issued' || ['revoked', 'retired'].includes(u.status)} onClick={() => setPrepare(true)}>Prepare</button>
        <button className="btn" disabled={!may('usb.manage') || !['prepared', 'verified', 'returned'].includes(u.status)} onClick={() => setIssue(true)}>Issue</button>
        <button className="btn" disabled={!may('usb.manage') || u.status !== 'issued'} onClick={() => setRet(true)}>Return</button>
        <button className="btn" disabled={!may('usb.manage')} onClick={() => setInventory(true)}>Inventory check</button>
        <button className="btn danger" disabled={!may('usb.manage')} onClick={() => setPending({ kind: 'report' })}>Report incident</button>
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {u.status === 'quarantined' && <Alert tone="warn" title="Quarantined">This asset is withheld from issue until it is re-imaged and hash-verified.</Alert>}
      {u.incident && <Alert tone="danger" title={`${u.incident.kind} reported`}>{u.incident.reason} · {fmt(u.incident.at)}</Alert>}
      <StatGrid cols={4}>
        <Stat label="Status" value={u.status} icon="usb" />
        <Stat label="Release" value={rel?.version || '—'} icon="package" sub={rel?.status} />
        <Stat label="Holder" value={u.holder?.name || 'In storage'} icon="candidate" sub={u.holder ? fmt(u.holder.since) : ''} />
        <Stat label="Last check" value={ago(u.lastCheckAt)} icon="clock" sub={u.lastLocation || ''} />
      </StatGrid>
      <Card title="Asset details">
        <KeyValue cols={2} items={[
          ['Asset ID', u.assetId], ['Serial', u.serial], ['Model', u.model], ['Capacity', `${u.capacityGb} GB`],
          ['Status', <Badge value={u.status} />], ['Release', rel ? `${rel.version} · ${rel.status}` : '—'],
          ['Image digest', u.imageDigest ? <code>{u.imageDigest}</code> : '—'], ['Written hash', u.writtenHash ? <code>{u.writtenHash}</code> : '—'],
          ['Station', u.station || '—'], ['Prepared', u.preparedAt ? fmt(u.preparedAt) : '—'],
          ['Assigned centre', center?.code || '—'], ['Assigned', u.assigned?.at ? fmt(u.assigned.at) : '—'],
          ['Notes', u.notes || '—'], ['Registered', fmt(u.createdAt)],
        ]} />
      </Card>
      <Card title="Custody & audit trail">
        {timeline.length ? <Timeline items={timeline} /> : <Empty icon="history" title="No custody events yet" />}
      </Card>

      {prepare && <PrepareModal usb={u} releases={releases} onClose={() => setPrepare(false)} onDone={() => {}} />}
      {issue && <IssueModal usb={u} onClose={() => setIssue(false)} onDone={() => {}} />}
      {ret && <ReturnModal usb={u} onClose={() => setRet(false)} onDone={() => {}} />}
      {inventory && <InventoryModal usb={u} onClose={() => setInventory(false)} onDone={() => {}} />}
      {pending?.kind === 'report' && <ActionDialog
        title={`Report ${u.assetId}`}
        desc="Lost or stolen assets raise a security incident. Damaged assets are quarantined."
        danger confirmLabel="Report incident"
        field={{ label: 'Report type', type: 'select', options: [{ v: 'lost', l: 'Lost' }, { v: 'stolen', l: 'Stolen' }, { v: 'damaged', l: 'Damaged' }] }}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason, kind) => { await run(() => reportUsb(user, u, { kind, reason })); setPending(null); }}
      />}
    </Page>
  );
}
