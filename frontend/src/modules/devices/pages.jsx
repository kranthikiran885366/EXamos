import { useMemo, useState, useEffect } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs, Progress, Skeleton,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { useLoad, usePerm } from '../../core/ui/hooks';
import * as Api from '../../core/api/services';
import {
  setDeviceStatus, runCompatibility, grantException, deviceState,
  CHECKS, COMPAT_PROFILES, timelineFor,
  releaseIsolation, simulateOutage, reassignDevice, replaceDevice, requestReauth, latestCompat,
} from './service';

const STATE_FILTERS = ['registered', 'enrolled', 'pending_approval', 'suspended', 'revoked', 'retired', 'quarantined'];

function mapBackendDevice(d) {
  return {
    ...d,
    id: d.id,
    hostname: d.hostname || d.device_name || d.id,
    tenantId: d.institution_id || d.tenant_id || '',
    status: d.status || 'unknown',
    backendTrustOutcome: d.backend_trust_outcome || null,
    lastSeen: d.last_contact_at || 0,
    lastAttested: d.last_attestation_at || 0,
    tpmPresent: d.tpm_present,
    secureBootState: d.secure_boot_state,
    osReleaseId: d.os_release_id,
  };
}

/* ------------------------------------------------------------------ fleet */
export function DevicesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const navigate = useNavigate();
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const { data: rawDevices, loading, error, reload } = useLoad(async () => {
    const res = await Api.listRegisteredDevices();
    return (res?.devices || []).map(mapBackendDevice);
  }, [tenantId]);

  const rows = useMemo(() => {
    const all = rawDevices || [];
    return tenantId ? all.filter((d) => d.tenantId === tenantId) : all;
  }, [rawDevices, tenantId]);

  const stats = {
    total: rows.length,
    enrolled: rows.filter((d) => d.status === 'enrolled' || d.status === 'registered').length,
    pending: rows.filter((d) => d.status === 'pending_approval').length,
    trusted: rows.filter((d) => d.backendTrustOutcome === 'ALLOW').length,
    suspended: rows.filter((d) => d.status === 'suspended').length,
    revoked: rows.filter((d) => d.status === 'revoked').length,
  };

  return (
    <Page title="Devices" desc="Enrolled devices, trust status, and last check-in."
      actions={<>
        <Link className="btn" to="/devices/enrollment">Enrollment</Link>
        <Link className="btn" to="/devices/compatibility">Compatibility</Link>
      </>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      {error && <Alert tone="danger" title="Could not load devices">{error.message}</Alert>}
      <StatGrid cols={6}>
        <Stat label="Total" value={stats.total} icon="device" />
        <Stat label="Active" value={stats.enrolled} icon="check" tone="green" />
        <Stat label="Pending" value={stats.pending} icon="clock" tone="amber" />
        <Stat label="Trusted" value={stats.trusted} icon="shield" tone="violet" />
        <Stat label="Suspended" value={stats.suspended} icon="warn" tone="amber" />
        <Stat label="Revoked" value={stats.revoked} icon="warn" tone="red" />
      </StatGrid>
      {loading ? <Loading /> : (
        <DataTable
          title="Device fleet" desc="Candidates require backend-verified device trust before an exam can start."
          rows={rows} search={(d) => `${d.hostname} ${d.id} ${d.status} ${d.osReleaseId || ''}`}
          filters={[
            { key: 'status', label: 'Status', options: STATE_FILTERS.map((s) => ({ v: s, l: s })) },
          ]}
          defaultSort={{ key: 'hostname', dir: 'asc' }}
          columns={[
            { key: 'hostname', label: 'Hostname', sortable: true, render: (d) => <Link className="strong-link mono" to={`/devices/${d.id}`}>{d.hostname}</Link> },
            { key: 'status', label: 'Status', render: (d) => <Badge value={d.status} /> },
            { key: 'trust', label: 'Trust', render: (d) => <Badge value={d.backendTrustOutcome === 'ALLOW' ? 'verified' : 'unverified'} /> },
            { key: 'secureBootState', label: 'Secure Boot', render: (d) => d.secureBootState || '—' },
            { key: 'tpmPresent', label: 'TPM', render: (d) => d.tpmPresent ? 'Yes' : 'No' },
            { key: 'osReleaseId', label: 'OS Release', render: (d) => d.osReleaseId || '—' },
            { key: 'lastSeen', label: 'Last contact', sortable: true, render: (d) => d.lastSeen ? <span title={fmt(d.lastSeen)}>{ago(d.lastSeen)}</span> : '—' },
            { key: 'lastAttested', label: 'Last attested', render: (d) => d.lastAttested ? ago(d.lastAttested) : 'Never' },
          ]}
          actions={(d) => {
            const out = [{ label: 'Open', onClick: () => navigate(`/devices/${d.id}`) }];
            if (!perms('device.manage')) return out;
            if (d.status === 'pending_approval') {
              out.push({ label: 'Approve enrollment', onClick: () => setAct({ type: 'approve', row: d }) });
            } else if (d.status === 'enrolled' || d.status === 'registered') {
              out.push({ label: 'Suspend', danger: true, onClick: () => setAct({ type: 'status', row: d, next: 'suspended' }) });
            }
            if (d.status !== 'revoked') {
              out.push({ label: 'Revoke', danger: true, onClick: () => setAct({ type: 'status', row: d, next: 'revoked' }) });
            }
            return out;
          }}
          empty={<Empty icon="device" title="No devices registered" action={<Link className="btn" to="/devices/enrollment">Enroll a device</Link>} />}
        />
      )}

      {act?.type === 'approve' && (
        <ActionDialog title="Approve device enrollment" desc={act.row.hostname} confirmLabel="Approve" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={() => flash.run(async () => {
            await Api.approveDeviceRegistration(act.row.id);
            reload?.();
            return `${act.row.hostname} approved.`;
          })} />
      )}
      {act?.type === 'status' && (
        <ActionDialog title={act.next === 'suspended' ? 'Suspend device' : 'Revoke device'} desc={act.row.hostname} danger
          confirmLabel={act.next === 'suspended' ? 'Suspend' : 'Revoke'}
          onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(async () => {
            if (act.next === 'suspended') await Api.suspendDevice(act.row.id, reason);
            else await Api.revokeDeviceIdentity(act.row.id, reason);
            reload?.();
            return `${act.row.hostname} ${act.next}.`;
          })} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ enrollment */
export function EnrollmentPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const perms = usePerm();
  const [step, setStep] = useState('form'); // form | submitting | pending | done | error
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');
  const [form, setForm] = useState({
    device_id: '', hostname: '', device_name: '', device_category: 'lab_pc',
    manufacturer: '', model: '', cpu_arch: 'x86_64', boot_mode: 'UEFI',
    secure_boot_state: 'enabled', tpm_present: true, tpm_version: '2.0',
    os_release_id: '', kernel_version: '', ak_public_key_pem: '',
  });

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    if (!perms('device.manage')) { setErr('You do not have permission to register devices.'); return; }
    if (!form.device_id.trim()) { setErr('Device ID is required.'); return; }
    if (!form.ak_public_key_pem.trim()) { setErr('Attestation public key (PEM) is required.'); return; }
    if (!tenantId) { setErr('Select an institution first.'); return; }
    setStep('submitting'); setErr('');
    try {
      const res = await Api.registerDeviceIdentity({
        ...form,
        institution_id: tenantId,
        tpm_present: form.tpm_present,
      });
      setResult(res);
      setStep(res.status === 'pending_approval' ? 'pending' : 'done');
    } catch (x) {
      setErr(x.message || 'Registration failed.');
      setStep('form');
    }
  };

  return (
    <Page title="Device Enrollment" desc="Register a hardware-backed device identity with the ExamOS trust backend.">
      {step === 'done' && (
        <Alert tone="success" title="Device registered">
          Device <b>{result?.device_id}</b> registered with status <b>{result?.status}</b>.
          Secure Boot: {result?.secure_boot}, TPM: {result?.tpm_present ? 'present' : 'absent'}, OS: {result?.os_release}.
        </Alert>
      )}
      {step === 'pending' && (
        <Alert tone="warn" title="Awaiting administrator approval">
          Device <b>{result?.device_id}</b> is registered and awaiting approval by an independent administrator.
          Go to Fleet → Devices to approve it.
        </Alert>
      )}
      {err && <Alert tone="danger">{err}</Alert>}

      {(step === 'form' || step === 'submitting') && (
        <Card title="Register device" desc="All fields are required for TPM attestation. The AK public key must be generated by the device TPM.">
          <form className="formgrid" onSubmit={submit}>
            <Field label="Device ID" required help="Unique hardware identifier (e.g. serial number or TPM EK fingerprint).">
              <Input value={form.device_id} onChange={(e) => set('device_id', e.target.value)} maxLength={63} placeholder="dev-abc123" />
            </Field>
            <Field label="Hostname">
              <Input value={form.hostname} onChange={(e) => set('hostname', e.target.value)} maxLength={127} placeholder="qat-a01.examos.local" />
            </Field>
            <Field label="Device name">
              <Input value={form.device_name} onChange={(e) => set('device_name', e.target.value)} maxLength={127} placeholder="ExamOS Terminal A01" />
            </Field>
            <Field label="Category">
              <Select value={form.device_category} onChange={(e) => set('device_category', e.target.value)}
                options={['lab_pc','institution_laptop','personal_laptop','kiosk_appliance'].map((v) => ({ v, l: v }))} />
            </Field>
            <Field label="Manufacturer">
              <Input value={form.manufacturer} onChange={(e) => set('manufacturer', e.target.value)} maxLength={127} placeholder="Dell" />
            </Field>
            <Field label="Model">
              <Input value={form.model} onChange={(e) => set('model', e.target.value)} maxLength={127} placeholder="OptiPlex 7090" />
            </Field>
            <Field label="Boot mode">
              <Select value={form.boot_mode} onChange={(e) => set('boot_mode', e.target.value)}
                options={['UEFI','Legacy'].map((v) => ({ v, l: v }))} />
            </Field>
            <Field label="Secure Boot state">
              <Select value={form.secure_boot_state} onChange={(e) => set('secure_boot_state', e.target.value)}
                options={['enabled','disabled','unknown'].map((v) => ({ v, l: v }))} />
            </Field>
            <Field label="TPM present">
              <Select value={form.tpm_present ? 'yes' : 'no'} onChange={(e) => set('tpm_present', e.target.value === 'yes')}
                options={[{ v: 'yes', l: 'Yes' }, { v: 'no', l: 'No' }]} />
            </Field>
            <Field label="TPM version">
              <Input value={form.tpm_version} onChange={(e) => set('tpm_version', e.target.value)} maxLength={31} placeholder="2.0" />
            </Field>
            <Field label="OS release ID" help="Must match an active release in Fleet → OS Releases.">
              <Input value={form.os_release_id} onChange={(e) => set('os_release_id', e.target.value)} maxLength={63} placeholder="ExamOS 2.0" />
            </Field>
            <Field label="Kernel version">
              <Input value={form.kernel_version} onChange={(e) => set('kernel_version', e.target.value)} maxLength={63} placeholder="6.6.0-examos" />
            </Field>
            <Field label="AK public key (PEM)" required className="span2"
              help="RSA-2048, RSA-3072, ECC-P256, or ECC-P384 public key generated by the device TPM. Never submit a private key.">
              <Textarea rows={8} value={form.ak_public_key_pem} onChange={(e) => set('ak_public_key_pem', e.target.value)}
                placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----" />
            </Field>
            <div className="span2">
              <button className="btn primary" type="submit" disabled={step === 'submitting'}>
                {step === 'submitting' ? 'Registering…' : 'Register device'}
              </button>
            </div>
          </form>
        </Card>
      )}

      <Card title="Enrollment requirements" desc="What the backend validates before accepting a device.">
        <ul className="list">
          <li>Institution must exist and have an active device trust policy.</li>
          <li>Device ID must be unique — duplicate registrations are rejected.</li>
          <li>AK public key must be RSA-2048/3072 or ECC-P256/P384 — validated server-side.</li>
          <li>In production mode, device identity must match the signed production registry.</li>
          <li>If the policy requires admin approval, the device enters <b>pending_approval</b> state.</li>
          <li>TPM attestation challenge/verify is a separate step after approval.</li>
        </ul>
      </Card>
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
  const { data: rawDevices } = useLoad(async () => {
    const res = await Api.listRegisteredDevices();
    return (res?.devices || []).map(mapBackendDevice);
  }, [tenantId]);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const [exc, setExc] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const mine = (rawDevices || []).filter((d) => !tenantId || d.tenantId === tenantId);
  const rows = [];

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
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const { data: detail, loading, error, reload } = useLoad(async () => {
    const [devRes, trustRes] = await Promise.all([
      Api.getRegisteredDevice(id),
      Api.getDeviceTrustStatus(id).catch(() => null),
    ]);
    const d = devRes?.device || devRes;
    if (!d) throw new Error('Device not found.');
    return {
      device: { ...d, id: d.id, hostname: d.hostname || d.device_name || d.id,
        tenantId: d.institution_id || '', status: d.status || 'unknown',
        backendTrustOutcome: trustRes?.outcome || null,
        trustReason: trustRes?.reason || '',
        secureBootState: d.secure_boot_state, tpmPresent: d.tpm_present,
        osReleaseId: d.os_release_id, lastSeen: d.last_contact_at || 0,
        lastAttested: d.last_attestation_at || 0,
      },
      trust: trustRes,
    };
  }, [id]);

  if (loading) return <Page title="Device"><Loading /></Page>;
  if (error) return <Page title="Device"><Alert tone="danger" title="Could not load device">{error.message}</Alert></Page>;
  const d = detail?.device;
  if (!d) return <Page title="Device not found"><Empty icon="device" title="No such device" action={<Link className="btn" to="/devices">Back to devices</Link>} /></Page>;
  const trust = detail?.trust;

  return (
    <Page title={d.hostname} desc={`${d.status} · ${d.institution_id || d.tenantId}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/devices">Devices</Link><Icon name="arrow" size={12} /><span>{d.hostname}</span></div>}
      actions={perms('device.manage') ? <>
        {(d.status === 'enrolled' || d.status === 'registered') && <button className="btn danger" onClick={() => setAct({ type: 'suspend' })}>Suspend</button>}
        {d.status === 'pending_approval' && <button className="btn" onClick={() => setAct({ type: 'approve' })}>Approve enrollment</button>}
        {d.status !== 'revoked' && <button className="btn danger" onClick={() => setAct({ type: 'revoke' })}>Revoke</button>}
      </> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Status" value={d.status} icon="device" tone={d.status === 'enrolled' || d.status === 'registered' ? 'green' : 'amber'} />
        <Stat label="Trust" value={trust?.outcome || 'unknown'} icon="shield" tone={trust?.outcome === 'ALLOW' ? 'green' : 'amber'} />
        <Stat label="Secure Boot" value={d.secureBootState || '—'} icon="lock" />
        <Stat label="TPM" value={d.tpmPresent ? 'Present' : 'Absent'} icon="chip" />
      </StatGrid>
      <div className="two">
        <Card title="Device details">
          <KeyValue cols={2} items={[
            ['Device ID', <span className="mono sm" key="id">{d.id}</span>],
            ['Hostname', d.hostname],
            ['Institution', d.institution_id || d.tenantId],
            ['Campus', d.campus_id || '—'],
            ['Category', d.device_category || '—'],
            ['Manufacturer', d.manufacturer || '—'],
            ['Model', d.model || '—'],
            ['CPU arch', d.cpu_arch || '—'],
            ['Boot mode', d.boot_mode || '—'],
            ['OS release', d.osReleaseId || '—'],
            ['Kernel', d.kernel_version || '—'],
            ['Last contact', d.lastSeen ? fmt(d.lastSeen) : 'Never'],
            ['Last attested', d.lastAttested ? fmt(d.lastAttested) : 'Never'],
          ]} />
        </Card>
        <Card title="Trust evaluation" desc={trust ? `Policy: ${trust.policy_id || 'none'}` : 'Not evaluated'}>
          {trust ? (
            <KeyValue cols={1} items={[
              ['Outcome', <Badge key="o" value={trust.outcome} />],
              ['Reason', trust.reason || '—'],
              ['Secure Boot', trust.secure_boot || '—'],
              ['TPM present', trust.tpm_present ? 'Yes' : 'No'],
              ['OS release', trust.os_release || '—'],
            ]} />
          ) : <Empty icon="shield" title="Trust not evaluated" />}
        </Card>
      </div>

      {act?.type === 'approve' && (
        <ActionDialog title="Approve device enrollment" desc={d.hostname} confirmLabel="Approve" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={() => flash.run(async () => { await Api.approveDeviceRegistration(d.id); reload?.(); return `${d.hostname} approved.`; })} />
      )}
      {act?.type === 'suspend' && (
        <ActionDialog title="Suspend device" desc={d.hostname} danger confirmLabel="Suspend"
          onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(async () => { await Api.suspendDevice(d.id, reason); reload?.(); return `${d.hostname} suspended.`; })} />
      )}
      {act?.type === 'revoke' && (
        <ActionDialog title="Revoke device" desc={d.hostname} danger confirmLabel="Revoke"
          onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(async () => { await Api.revokeDeviceIdentity(d.id, reason); reload?.(); return `${d.hostname} revoked.`; })} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ attestation */
export function DeviceAttestationPage() {
  const { id } = useParams();
  const { data: detail } = useLoad(async () => {
    const res = await Api.getRegisteredDevice(id).catch(() => null);
    return res?.device || res || null;
  }, [id]);

  return (
    <Page title="Attestation" desc={detail ? `${detail.hostname || id} · attestation history` : 'Attestation history.'}
      breadcrumb={<div className="crumbs-inline"><Link to="/devices">Devices</Link><Icon name="arrow" size={12} /><Link to={`/devices/${id}`}>{detail?.hostname || id}</Link></div>}>
      <Alert tone="info" title="TPM attestation">
        Use the SPPIO agent on the device to submit a TPM quote via <span className="mono">POST /api/v1/devices/{id}/attestation/verify</span>.
        The server verifies the RSA-2048/SHA-256 quote, nonce binding, AK identity, and PCR 0/4/7/11 against the approved release baseline.
      </Alert>
      <Empty icon="shield" title="No attestation records" />
    </Page>
  );
}
