import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs, Progress, Skeleton,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { useLoad, usePerm } from '../../core/ui/hooks';
import {
  enrollDevices, enrollSingle, setDeviceStatus, runCompatibility, grantException, deviceState,
  deviceStats, CHECKS, COMPAT_PROFILES, deviceDetail, timelineFor, attestDeviceFor,
  releaseIsolation, simulateOutage, reassignDevice, replaceDevice, requestReauth, latestCompat,
} from './service';

const STATE_FILTERS = ['enrolled', 'isolated', 'offline', 'failed', 'compat-fail', 'suspended', 'revoked', 'rejected'];

/* ------------------------------------------------------------------ fleet */
export function DevicesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const navigate = useNavigate();
  const devices = useCol('devices', false);
  const centers = useCol('centers', false);
  const compat = useCol('compat', false);
  const [act, setAct] = useState(null);
  const [reassign, setReassign] = useState(null);
  const [enrolling, setEnrolling] = useState(false);
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => devices.filter((d) => d.tenantId === tenantId), [devices, tenantId]);
  const stats = deviceStats(rows);
  const centerName = (id) => centers.find((c) => c.id === id)?.code || '—';

  return (
    <Page title="Devices" desc="Enrolled devices, trust status, compatibility and last check-in."
      actions={<>
        <Link className="btn" to="/devices/enrollment">Enrollment</Link>
        <Link className="btn" to="/devices/compatibility">Compatibility</Link>
        {perms('device.manage') && <button className="btn primary" onClick={() => setEnrolling(true)}><Icon name="plus" size={15} /> Enroll devices</button>}
      </>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={6}>
        <Stat label="Total" value={stats.total} icon="device" />
        <Stat label="Enrolled" value={stats.enrolled} icon="check" tone="green" />
        <Stat label="Online" value={stats.online} icon="pulse" tone="green" />
        <Stat label="Attested" value={stats.attested} icon="shield" tone="violet" />
        <Stat label="Suspended" value={stats.suspended} icon="warn" tone="amber" />
        <Stat label="Revoked" value={stats.revoked} icon="warn" tone="red" />
      </StatGrid>
      <DataTable
        title="Device fleet" desc="Devices must be reachable and attested before a candidate can start."
        rows={rows} search={(d) => `${d.hostname} ${d.seat} ${d.serial} ${d.trust} ${d.status}`}
        filters={[
          { key: 'state', label: 'State', get: (d) => deviceState(d), options: STATE_FILTERS.map((s) => ({ v: s, l: s })) },
          { key: 'centerId', label: 'Centre', options: centers.filter((c) => c.tenantId === tenantId).map((c) => ({ v: c.id, l: `${c.code} · ${c.name}` })) },
          { key: 'trust', label: 'Trust', options: ['unknown', 'attested', 'failed'].map((s) => ({ v: s, l: s })) },
        ]}
        defaultSort={{ key: 'hostname', dir: 'asc' }}
        columns={[
          { key: 'hostname', label: 'Hostname', sortable: true, render: (d) => <Link className="strong-link mono" to={`/devices/${d.id}`}>{d.hostname}</Link> },
          { key: 'seat', label: 'Seat', mono: true },
          { key: 'centerId', label: 'Centre', render: (d) => centerName(d.centerId) },
          { key: 'state', label: 'State', render: (d) => <Badge value={deviceState(d)} /> },
          { key: 'trust', label: 'Trust', render: (d) => <Badge value={d.trust} /> },
          { key: 'compatStatus', label: 'Compat', render: (d) => <Badge value={d.compatStatus || 'NOT_RUN'} /> },
          { key: 'lastSeen', label: 'Last seen', sortable: true, render: (d) => <span title={fmt(d.lastSeen)}>{ago(d.lastSeen)}</span> },
          { key: 'lastAttested', label: 'Attested', render: (d) => (d.lastAttested ? ago(d.lastAttested) : 'Never') },
        ]}
        actions={(d) => {
          const out = [{ label: 'Open', onClick: () => navigate(`/devices/${d.id}`) }];
          if (!perms('device.manage')) return out;
          out.push({ label: 'Attest', onClick: () => setAct({ type: 'attest', row: d }) });
          if (perms('compat.manage')) out.push({ label: 'Compat check', onClick: () => flash.run(async () => { const r = await runCompatibility(user, d, d.profile); return `Compatibility: ${r.overall}`; }) });
          if (d.status === 'revoked') {
            out.push({ label: 'Request reauth', onClick: () => setAct({ type: 'reauth', row: d }) });
          } else if (d.status === 'enrolled') {
            out.push({ label: 'Suspend', danger: true, onClick: () => setAct({ type: 'status', row: d, next: 'suspended' }) });
          } else {
            out.push({ label: 'Reactivate', onClick: () => setAct({ type: 'status', row: d, next: 'enrolled' }) });
          }
          if (d.isolated) out.push({ label: 'Release isolation', onClick: () => setAct({ type: 'isolation', row: d }) });
          out.push({ label: 'Reassign', onClick: () => setReassign(d) });
          out.push({ label: 'Simulate outage', onClick: () => setAct({ type: 'outage', row: d }) });
          return out;
        }}
      />

      {enrolling && <BulkEnrollModal onClose={() => setEnrolling(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {reassign && <ReassignModal device={reassign} centers={centers.filter((c) => c.tenantId === tenantId)} onClose={() => setReassign(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}

      {act?.type === 'attest' && (
        <ActionDialog title="Attest device" desc={`${act.row.hostname} · verifies TPM quote and PCR values.`} confirmLabel="Attest" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => attestDeviceFor(user, act.row.id))} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title={act.next === 'suspended' ? 'Suspend device' : 'Reactivate device'} desc={act.row.hostname} danger={act.next === 'suspended'}
          confirmLabel={act.next === 'suspended' ? 'Suspend' : 'Reactivate'} onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(() => setDeviceStatus(user, act.row, act.next, reason))} />
      )}
      {act?.type === 'reauth' && (
        <ActionDialog title="Request reauthorisation" desc="A different privileged user must approve this." confirmLabel="Request"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => requestReauth(user, act.row, reason))} />
      )}
      {act?.type === 'isolation' && (
        <ActionDialog title="Release isolation" desc={`${act.row.hostname} will be allowed to reach the exam network again.`} confirmLabel="Release" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => releaseIsolation(user, act.row))} />
      )}
      {act?.type === 'outage' && (
        <ActionDialog title="Simulate outage" desc="The device stops heartbeating for 70 seconds. Use only in a test window." confirmLabel="Simulate" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => simulateOutage(user, act.row))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ enrollment */
function BulkEnrollModal({ onClose, onDone }) {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const centers = useCol('centers', false);
  const [v, setV] = useState({ centerId: '', count: '1' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const m = await enrollDevices(user, { tenantId, centerId: v.centerId, count: v.count }); onDone?.(m); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Enroll devices" desc="Enrolls consecutive free seats at the selected centre." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="bulk-enroll" disabled={busy}>{busy ? 'Enrolling…' : 'Enroll'}</button></>}>
      <form id="bulk-enroll" onSubmit={submit} className="formgrid">
        <Field label="Centre" required>
          <Select value={v.centerId} onChange={(e) => setV({ ...v, centerId: e.target.value })} options={centers.filter((c) => c.tenantId === tenantId && c.status === 'active').map((c) => ({ v: c.id, l: `${c.code} · ${c.name}` }))} />
        </Field>
        <Field label="How many" required help="1–100 devices."><Input type="number" min="1" max="100" value={v.count} onChange={(e) => setV({ ...v, count: e.target.value })} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function EnrollmentPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const centers = useCol('centers', false);
  const releases = useCol('releases', false);
  const [bulk, setBulk] = useState(false);
  const [v, setV] = useState({ hostname: '', seat: '', centerId: '', serial: '', profile: 'standard-uefi', releaseId: '' });
  const [err, setErr] = useState(''); const [result, setResult] = useState(null);
  const flash = useFlash();
  const perms = usePerm();
  const activeCenters = centers.filter((c) => c.tenantId === tenantId && c.status === 'active');

  const submit = async (e) => {
    e.preventDefault();
    await flash.run(async () => {
      const d = await enrollSingle(user, { tenantId, ...v });
      setResult(d);
      setV({ hostname: '', seat: '', centerId: '', serial: '', profile: 'standard-uefi', releaseId: '' });
      return `Enrolled ${d.hostname} (${d.serial}).`;
    });
  };

  return (
    <Page title="Enrollment" desc="Enroll devices into the fleet with a hardware-bound identity."
      actions={perms('device.manage') ? <button className="btn primary" onClick={() => setBulk(true)}><Icon name="plus" size={15} /> Bulk enroll</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <div className="two">
        <Card title="Enroll a single device" desc="Generates a unique key pair and binds it to the seat.">
          <form onSubmit={submit} className="formgrid">
            <Field label="Centre" required><Select value={v.centerId} onChange={(e) => setV({ ...v, centerId: e.target.value })} options={activeCenters.map((c) => ({ v: c.id, l: `${c.code} · ${c.name}` }))} /></Field>
            <Field label="Seat" required help="Format A01."><Input value={v.seat} onChange={(e) => setV({ ...v, seat: e.target.value.toUpperCase() })} maxLength={3} placeholder="A01" /></Field>
            <Field label="Hostname" help="Defaults to centre-seat."><Input value={v.hostname} onChange={(e) => setV({ ...v, hostname: e.target.value })} maxLength={60} /></Field>
            <Field label="Serial number"><Input value={v.serial} onChange={(e) => setV({ ...v, serial: e.target.value })} maxLength={40} /></Field>
            <Field label="Hardware profile"><Select value={v.profile} onChange={(e) => setV({ ...v, profile: e.target.value })} options={COMPAT_PROFILES} placeholder={false} /></Field>
            <Field label="Release" help="Defaults to the latest stable release.">
              <Select value={v.releaseId} onChange={(e) => setV({ ...v, releaseId: e.target.value })} options={releases.filter((r) => r.status !== 'revoked').map((r) => ({ v: r.id, l: `${r.version} (${r.status})` }))} placeholder="Latest stable" />
            </Field>
            <div className="span2"><button className="btn primary" disabled={flash.busy || !v.centerId || !v.seat}>{flash.busy ? 'Enrolling…' : 'Enroll device'}</button></div>
          </form>
        </Card>
        <Card title="Enrollment checklist" desc="What happens when a device is enrolled.">
          <ol className="checklist">
            <li>A fresh ECDSA key pair is generated in the browser and bound to the device id.</li>
            <li>The device inherits the institution policy and latest stable release.</li>
            <li>It starts as <Badge value="unknown" /> trust and must be attested.</li>
            <li>Run a compatibility check before assigning candidates.</li>
            <li>Devices must heartbeat at least every 40 seconds to be reachable.</li>
          </ol>
          {result && (
            <Alert tone="success" title="Device enrolled">
              <KeyValue cols={2} items={[['Hostname', result.hostname], ['Seat', result.seat], ['Serial', result.serial], ['Trust', <Badge key="t" value={result.trust} />]]} />
            </Alert>
          )}
        </Card>
      </div>
      {bulk && <BulkEnrollModal onClose={() => setBulk(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
    </Page>
  );
}

/* ------------------------------------------------------------------ compatibility */
function ExceptionModal({ device, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ check: '', days: '7', reason: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const m = await grantException(user, device, v.check, v.reason, v.days); onDone?.(m); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Grant compatibility exception" desc={`${device.hostname} · exceptions expire automatically.`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="exception-form" disabled={busy}>{busy ? 'Saving…' : 'Grant exception'}</button></>}>
      <form id="exception-form" onSubmit={submit} className="formgrid">
        <Field label="Check" required><Select value={v.check} onChange={(e) => setV({ ...v, check: e.target.value })} options={CHECKS.map((c) => ({ v: c.key, l: `${c.group} · ${c.label}${c.mandatory ? ' (mandatory)' : ''}` }))} /></Field>
        <Field label="Valid for (days)" required><Input type="number" min="1" max="30" value={v.days} onChange={(e) => setV({ ...v, days: e.target.value })} /></Field>
        <Field label="Justification" required className="span2"><Textarea rows={3} value={v.reason} onChange={(e) => setV({ ...v, reason: e.target.value })} maxLength={300} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function CompatibilityPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const devices = useCol('devices', false);
  const compat = useCol('compat', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const [exc, setExc] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const mine = devices.filter((d) => d.tenantId === tenantId);
  const rows = compat.filter((c) => mine.some((d) => d.id === c.deviceId)).sort((a, b) => b.runAt - a.runAt);

  return (
    <Page title="Compatibility" desc="Hardware compatibility results per device, with expiring exceptions."
      actions={perms('compat.manage') ? <button className="btn primary" onClick={() => setAct({ type: 'run' })}><Icon name="checklist" size={15} /> Run check</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Checks run" value={rows.length} icon="checklist" />
        <Stat label="Pass" value={rows.filter((c) => c.overall === 'PASS').length} icon="check" tone="green" />
        <Stat label="Fail" value={rows.filter((c) => c.overall === 'FAIL').length} icon="warn" tone="red" />
        <Stat label="Devices with exceptions" value={mine.filter((d) => (d.exceptions || []).length).length} icon="shield" tone="amber" />
      </StatGrid>
      <DataTable
        title="Compatibility runs" desc="Open a run to see each check and its effective result."
        rows={rows} search={(c) => `${c.hostname || c.deviceId} ${c.profile} ${c.overall}`}
        filters={[{ key: 'overall', label: 'Result', options: ['PASS', 'FAIL', 'BLOCKED', 'UNKNOWN'].map((s) => ({ v: s, l: s })) }]}
        columns={[
          { key: 'hostname', label: 'Device', render: (c) => <Link className="strong-link mono" to={`/devices/${c.deviceId}`}>{c.hostname || c.deviceId}</Link> },
          { key: 'profile', label: 'Profile' },
          { key: 'overall', label: 'Overall', render: (c) => <Badge value={c.overall} /> },
          { key: 'checks', label: 'Checks', render: (c) => `${(c.checks || []).filter((x) => x.effective === 'PASS').length}/${(c.checks || []).length}` },
          { key: 'runAt', label: 'Run at', sortable: true, render: (c) => fmt(c.runAt) },
        ]}
        actions={(c) => [
          { label: 'View', onClick: () => setView(c) },
          ...(perms('compat.manage') ? [
            { label: 'Re-run', onClick: () => { const d = mine.find((x) => x.id === c.deviceId); if (d) flash.run(async () => { const r = await runCompatibility(user, d, c.profile); return `Compatibility: ${r.overall}`; }); } },
            { label: 'Exception', onClick: () => { const d = mine.find((x) => x.id === c.deviceId); if (d) setExc(d); } },
          ] : []),
        ]}
      />

      {act?.type === 'run' && (
        <RunCompatModal devices={mine} onClose={() => setAct(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />
      )}
      {view && (
        <Modal wide title={`Compatibility · ${view.hostname || view.deviceId}`} desc={`${view.profile} · ${view.overall}`} onClose={() => setView(null)}
          footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <DataTable rows={view.checks || []} dense columns={[
            { key: 'group', label: 'Group' },
            { key: 'label', label: 'Check' },
            { key: 'status', label: 'Raw', render: (c) => <Badge value={c.status} /> },
            { key: 'effective', label: 'Effective', render: (c) => <Badge value={c.effective} /> },
            { key: 'reason', label: 'Detail' },
            { key: 'mandatory', label: 'Required', render: (c) => (c.mandatory ? 'Yes' : 'No') },
            { key: 'exception', label: 'Exception', render: (c) => (c.exception ? `Until ${fmt(c.exception.expiresAt)}` : '—') },
          ]} />
        </Modal>
      )}
      {exc && <ExceptionModal device={exc} onClose={() => setExc(null)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
    </Page>
  );
}

function RunCompatModal({ devices, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ deviceId: '', profile: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      const d = devices.find((x) => x.id === v.deviceId); if (!d) throw new Error('Pick a device.');
      const r = await runCompatibility(user, d, v.profile || d.profile);
      onDone?.(`Compatibility for ${d.hostname}: ${r.overall}`); onClose();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Run compatibility check" onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="compat-form" disabled={busy}>{busy ? 'Running…' : 'Run check'}</button></>}>
      <form id="compat-form" onSubmit={submit} className="formgrid">
        <Field label="Device" required><Select value={v.deviceId} onChange={(e) => setV({ ...v, deviceId: e.target.value })} options={devices.map((d) => ({ v: d.id, l: `${d.hostname} · ${d.seat}` }))} /></Field>
        <Field label="Profile" help="Defaults to the device profile."><Select value={v.profile} onChange={(e) => setV({ ...v, profile: e.target.value })} options={COMPAT_PROFILES} placeholder="Device default" /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ device detail */
function ReassignModal({ device, centers, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({ centerId: device.centerId, seat: device.seat, reason: '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try { const m = await reassignDevice(user, device, v); onDone?.(m); onClose(); }
    catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal title="Reassign device" desc={device.hostname} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="reassign-form" disabled={busy}>{busy ? 'Saving…' : 'Reassign'}</button></>}>
      <form id="reassign-form" onSubmit={submit} className="formgrid">
        <Field label="Centre" required><Select value={v.centerId} onChange={(e) => setV({ ...v, centerId: e.target.value })} options={centers.map((c) => ({ v: c.id, l: `${c.code} · ${c.name}` }))} /></Field>
        <Field label="Seat" required><Input value={v.seat} onChange={(e) => setV({ ...v, seat: e.target.value.toUpperCase() })} maxLength={3} /></Field>
        <Field label="Reason" required className="span2"><Textarea rows={3} value={v.reason} onChange={(e) => setV({ ...v, reason: e.target.value })} maxLength={300} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function DeviceDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const devices = useCol('devices', false);
  const attestations = useCol('attestations', false);
  const compat = useCol('compat', false);
  const incidents = useCol('incidents', false);
  const policies = useCol('policies', false);
  const releases = useCol('releases', false);
  const centers = useCol('centers', false);
  const sessions = useCol('sessions', false);
  const [act, setAct] = useState(null);
  const [reassign, setReassign] = useState(false);
  const flash = useFlash();
  const perms = usePerm();

  const { data: detail, loading, error } = useLoad(
    () => deviceDetail(id, { attestations, compat, incidents, policies, releases, centers, sessions }),
    [id, attestations, compat, incidents, policies, releases, centers, sessions],
  );

  if (loading) return <Page title="Device"><Loading /></Page>;
  if (error) return <Page title="Device"><Alert tone="danger" title="Could not load device">{error.message}</Alert></Page>;
  const d = detail?.device;
  if (!d) return <Page title="Device not found"><Empty icon="device" title="No such device" action={<Link className="btn" to="/devices">Back to devices</Link>} /></Page>;
  const timeline = timelineFor(detail);
  const lastCompat = latestCompat(compat, d.id);

  return (
    <Page title={d.hostname} desc={`Seat ${d.seat} · ${deviceState(d)}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/devices">Devices</Link><Icon name="arrow" size={12} /><span>{d.hostname}</span></div>}
      actions={perms('device.manage') ? <>
        <button className="btn" onClick={() => setAct({ type: 'attest' })}>Attest</button>
        <button className="btn" onClick={() => setAct({ type: 'compat' })}>Compat check</button>
        <button className="btn" onClick={() => setReassign(true)}>Reassign</button>
        {d.isolated && <button className="btn" onClick={() => setAct({ type: 'isolation' })}>Release isolation</button>}
        {d.status === 'enrolled'
          ? <button className="btn danger" onClick={() => setAct({ type: 'status', next: 'suspended' })}>Suspend</button>
          : d.status === 'revoked'
            ? <button className="btn primary" onClick={() => setAct({ type: 'reauth' })}>Request reauth</button>
            : <button className="btn" onClick={() => setAct({ type: 'status', next: 'enrolled' })}>Reactivate</button>}
      </> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="State" value={deviceState(d)} icon="device" tone={deviceState(d) === 'enrolled' ? 'green' : 'amber'} />
        <Stat label="Trust" value={d.trust} icon="shield" tone={d.trust === 'attested' ? 'green' : 'amber'} />
        <Stat label="Last seen" value={ago(d.lastSeen)} icon="clock" sub={fmt(d.lastSeen)} />
        <Stat label="Centre" value={detail.center?.code || '—'} icon="building" sub={detail.center?.name} />
      </StatGrid>
      <div className="two">
        <Card title="Device details">
          <KeyValue cols={2} items={[
            ['Hostname', d.hostname], ['Serial', d.serial],
            ['Seat', d.seat], ['Profile', d.profile],
            ['Release', detail.release ? `${detail.release.version} (${detail.release.status})` : '—'],
            ['Policy', detail.policy?.name || '—'],
            ['Compatibility', <Badge key="c" value={d.compatStatus || 'NOT_RUN'} />],
            ['Isolated', d.isolated ? 'Yes' : 'No'],
            ['Enrolled', fmt(d.enrolledAt)], ['Last attested', d.lastAttested ? fmt(d.lastAttested) : 'Never'],
          ]} />
        </Card>
        <Card title="Compatibility summary" desc={lastCompat ? `Last run ${fmt(lastCompat.runAt)}` : 'No compatibility run yet.'}>
          {lastCompat ? (
            <>
              <Progress value={(lastCompat.checks || []).filter((c) => c.effective === 'PASS').length} max={(lastCompat.checks || []).length || 1} label={`${lastCompat.overall} result`} />
              <div className="chips">{(lastCompat.checks || []).filter((c) => c.effective !== 'PASS').map((c) => <span key={c.key} className="chip"><Badge value={c.effective} /> {c.label}</span>)}</div>
              {(d.exceptions || []).length > 0 && <Alert tone="warn" title="Active exceptions">{(d.exceptions || []).map((e) => <div key={e.check}>{e.check} until {fmt(e.expiresAt)} — {e.reason}</div>)}</Alert>}
            </>
          ) : <Empty icon="checklist" title="Not checked" action={perms('compat.manage') ? <button className="btn" onClick={() => setAct({ type: 'compat' })}>Run check</button> : null} />}
        </Card>
      </div>
      <Card title="Timeline" desc="Attestations, compatibility runs, incidents and sessions.">
        {timeline.length ? <Timeline items={timeline} /> : <Empty icon="history" title="No activity yet" />}
      </Card>
      <Card title="Danger zone" desc="These actions are audited and may require re-attestation.">
        <div className="row wrap">
          {perms('device.manage') && <button className="btn" onClick={() => setAct({ type: 'outage' })}>Simulate outage</button>}
          {perms('device.manage') && <button className="btn" onClick={() => setAct({ type: 'replace' })}>Replace hardware</button>}
          {perms('device.manage') && <button className="btn danger" onClick={() => setAct({ type: 'status', next: 'revoked' })}>Revoke device</button>}
          {perms('compat.manage') && <button className="btn" onClick={() => setAct({ type: 'exception' })}>Grant exception</button>}
        </div>
      </Card>

      {reassign && <ReassignModal device={d} centers={centers.filter((c) => c.tenantId === d.tenantId)} onClose={() => setReassign(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act?.type === 'attest' && (
        <ActionDialog title="Attest device" desc={`${d.hostname} · verifies TPM quote and PCR values.`} confirmLabel="Attest" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => attestDeviceFor(user, d.id))} />
      )}
      {act?.type === 'compat' && (
        <ActionDialog title="Run compatibility check" desc={d.hostname} confirmLabel="Run check" requireReason={false}
          field={{ label: 'Hardware profile', options: COMPAT_PROFILES, default: d.profile }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(async () => { const r = await runCompatibility(user, d, val); return `Compatibility: ${r.overall}`; })} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title={act.next === 'suspended' ? 'Suspend device' : act.next === 'revoked' ? 'Revoke device' : 'Reactivate device'}
          desc={d.hostname} danger={act.next !== 'enrolled'} confirmLabel={act.next === 'suspended' ? 'Suspend' : act.next === 'revoked' ? 'Revoke' : 'Reactivate'}
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => setDeviceStatus(user, d, act.next, reason))} />
      )}
      {act?.type === 'reauth' && (
        <ActionDialog title="Request reauthorisation" desc="A different privileged user must approve this." confirmLabel="Request"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => requestReauth(user, d, reason))} />
      )}
      {act?.type === 'isolation' && (
        <ActionDialog title="Release isolation" desc={d.hostname} confirmLabel="Release" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => releaseIsolation(user, d))} />
      )}
      {act?.type === 'outage' && (
        <ActionDialog title="Simulate outage" desc="Stops heartbeats for 70 seconds. Use only in a test window." confirmLabel="Simulate" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => simulateOutage(user, d))} />
      )}
      {act?.type === 'replace' && (
        <ActionDialog title="Replace hardware" desc="The current identity is revoked; enroll the replacement separately." danger confirmLabel="Replace"
          field={{ label: 'Replacement serial number' }} onClose={() => setAct(null)}
          onConfirm={(reason, val) => flash.run(() => replaceDevice(user, d, { serial: val, reason }))} />
      )}
      {act?.type === 'exception' && (
        <ActionDialog title="Grant compatibility exception" desc={d.hostname} confirmLabel="Grant"
          field={{ label: 'Check', options: CHECKS.map((c) => ({ v: c.key, l: `${c.group} · ${c.label}` })) }}
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(() => grantException(user, d, val, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ attestation */
export function DeviceAttestationPage() {
  const { id } = useParams();
  const devices = useCol('devices', false);
  const attestations = useCol('attestations', false);
  const device = devices.find((d) => d.id === id);
  const rows = useMemo(() => attestations
    .filter((a) => a.deviceId === id)
    .sort((a, b) => (b.verifiedAt || b.issuedAt || 0) - (a.verifiedAt || a.issuedAt || 0)), [attestations, id]);

  return (
    <Page title="Attestation" desc={device ? `${device.hostname} · TPM quote history` : 'TPM quote history for this device.'}
      breadcrumb={<div className="crumbs-inline"><Link to="/devices">Devices</Link><Icon name="arrow" size={12} /><Link to={`/devices/${id}`}>{device?.hostname || id}</Link></div>}>
      <StatGrid cols={3}>
        <Stat label="Attestations" value={rows.length} icon="shield" />
        <Stat label="Passed" value={rows.filter((a) => a.result === 'attested' || a.result === 'pass').length} icon="check" tone="green" />
        <Stat label="Failed" value={rows.filter((a) => a.result === 'failed' || a.result === 'fail').length} icon="warn" tone="red" />
      </StatGrid>
      <DataTable
        title="Attestation history" desc="Newest first."
        rows={rows}
        columns={[
          { key: 'result', label: 'Result', render: (a) => <Badge value={a.result || a.status} /> },
          { key: 'pcrMatch', label: 'PCR match', render: (a) => <Badge value={a.pcrMatch ? 'match' : 'mismatch'} /> },
          { key: 'nonce', label: 'Nonce', render: (a) => <span className="mono sm">{a.nonce || '—'}</span> },
          { key: 'reason', label: 'Detail', render: (a) => a.reason || '—' },
          { key: 'issuedAt', label: 'Issued', sortable: true, render: (a) => fmt(a.issuedAt || a.verifiedAt) },
          { key: 'verifiedAt', label: 'Verified', render: (a) => (a.verifiedAt ? fmt(a.verifiedAt) : '—') },
        ]}
        empty={<Empty icon="shield" title="No attestations yet">Attest this device from the device page.</Empty>}
      />
    </Page>
  );
}
