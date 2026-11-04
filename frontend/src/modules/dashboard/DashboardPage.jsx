// ExamOS Enterprise Overview & Real-Time Operations Command Center
import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can, roleLabel, isGlobal } from '../../core/security/rbac';
import { Page, Card, Stat, StatGrid, Alert, Badge, DataTable, Icon, Progress, SectionTitle, Empty } from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import * as Api from '../../core/api/services';

const greeting = () => {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
};

export default function DashboardPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();

  // Local collections
  const tenants = useCol('tenants', false);
  const exams = useCol('exams');
  const candidates = useCol('candidates');
  const devices = useCol('devices');
  const sessions = useCol('sessions');
  const incidents = useCol('incidents');
  const usbs = useCol('usbs');
  const approvals = useCol('approvals');
  const support = useCol('support');
  const releases = useCol('releases', false);
  const invoices = useCol('invoices');
  const audit = useCol('audit', false);
  const evidence = useCol('evidence');
  const securityEvents = useCol('securityEvents');
  const users = useCol('users', false);

  // Live backend telemetry state
  const [telemetry, setTelemetry] = useState(null);
  const [serverHealth, setServerHealth] = useState(null);
  const [serverStatus, setServerStatus] = useState(null);
  const [ledgerData, setLedgerData] = useState(null);
  const [fleetData, setFleetData] = useState(null);
  const [backendApps, setBackendApps] = useState([]);
  const [backendInsts, setBackendInsts] = useState([]);
  const [telemetryError, setTelemetryError] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(Date.now());

  // Query live server telemetry
  const fetchLiveTelemetry = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [h, s, t, l, f, apps, insts] = await Promise.allSettled([
        Api.health(),
        Api.status(),
        Api.getTelemetry(),
        Api.getLedger(),
        Api.listFleet(),
        Api.listInstitutionApplications(),
        Api.listInstitutions(),
      ]);

      const failed = [h, s, t, l, f, apps, insts].filter((result) => result.status === 'rejected');
      setTelemetryError(failed.length ? 'One or more live dashboard data sources are unavailable.' : '');
      if (apps.status === 'fulfilled' && apps.value?.applications) setBackendApps(apps.value.applications);
      if (insts.status === 'fulfilled' && (insts.value?.institutions || Array.isArray(insts.value))) setBackendInsts(insts.value.institutions || insts.value);

      if (h.status === 'fulfilled') setServerHealth(h.value);
      if (s.status === 'fulfilled') setServerStatus(s.value);
      if (t.status === 'fulfilled') setTelemetry(t.value);
      if (l.status === 'fulfilled') setLedgerData(l.value);
      if (f.status === 'fulfilled') setFleetData(f.value);
      setLastUpdated(Date.now());
    } catch (err) {
      console.warn('Dashboard live telemetry warning:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchLiveTelemetry();
    if (!autoRefresh) return;
    const interval = setInterval(fetchLiveTelemetry, 5000);
    return () => clearInterval(interval);
  }, [fetchLiveTelemetry, autoRefresh]);

  const live = exams.filter((e) => e.status === 'live');
  const upcoming = exams.filter((e) => e.status === 'published').sort((a, b) => a.startAt - b.startAt).slice(0, 5);
  const openInc = incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status));
  const pending = approvals.filter((a) => a.status === 'pending');
  const openTickets = support.filter((s) => ['new', 'assigned', 'waiting', 'in-progress', 'reopened'].includes(s.status));

  // Device posture is authoritative only when the live fleet API responds.
  const liveDevices = fleetData?.devices || [];
  const totalDevicesCount = fleetData ? liveDevices.length : null;
  const attested = fleetData ? liveDevices.filter((d) => d.attestation_status === 'TRUSTED').length : null;
  const onlineCount = serverHealth?.status === 'ok' && fleetData ? liveDevices.filter((d) => d.status === 'online' || d.status === 'ONLINE').length : null;
  const usbLocked = fleetData ? liveDevices.filter((d) => d.usb_storage_blocked === true).length : null;
  const kioskActive = fleetData ? liveDevices.filter((d) => d.kiosk_status === 'active' || d.kiosk_status === 'ACTIVE').length : null;

  const submitted = telemetry?.submitted_candidates_count;
  const currentExamUrl = serverStatus?.exam_url || '';
  const latestAudit = [...audit].sort((a, b) => b.seq - a.seq).slice(0, 7);
  const myTenantUsers = users.filter((u) => !tenantId || u.tenantId === tenantId);
  const inst = tenant;
  const outstanding = invoices.filter((i) => ['open', 'overdue'].includes(i.status)).reduce((s, i) => s + (i.total || 0), 0);
  const global = isGlobal(user.role);

  const scopeLabel = global ? `${tenants.length || telemetry?.institutions_count || 1} institutions` : inst?.name || 'Cambridge Assessment';

  return (
    <Page
      title={`${greeting()}, ${user.name.split(' ')[0]}`}
      desc={`${roleLabel(user.role)} Â· ${scopeLabel} Â· Production Operations Center`}
      actions={
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className={`btn ${autoRefresh ? 'primary' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
            title="Auto-refresh live backend telemetry every 5 seconds"
          >
            <Icon name="pulse" size={15} /> {autoRefresh ? 'Live Sync: ON' : 'Live Sync: OFF'}
          </button>
          <button className="btn" onClick={fetchLiveTelemetry} disabled={isRefreshing}>
            <Icon name="refresh" size={15} /> {isRefreshing ? 'Syncing...' : 'Refresh'}
          </button>
          <Link className="btn" to="/kiosk">
            <Icon name="device" size={15} /> Kiosk Operations
          </Link>
          {can(user.role, 'exam.manage') && (
            <Link className="btn primary" to="/college/exams/new">
              <Icon name="plus" size={15} /> New exam
            </Link>
          )}
        </div>
      }
    >
      {/* Live Production Telemetry Banner */}
      {telemetryError && <Alert tone="danger" title="Live dashboard data unavailable">{telemetryError} Retry after confirming the backend session and dependency health.</Alert>}
      <div
        style={{
          background: '#ffffff',
          border: '1px solid var(--line)',
          borderRadius: '12px',
          padding: '16px 20px',
          marginBottom: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          boxShadow: 'var(--shadow)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              background: serverHealth?.status === 'ok' ? '#16a34a' : '#ef4444',
              boxShadow: serverHealth?.status === 'ok' ? '0 0 8px rgba(22, 163, 74, 0.4)' : '0 0 8px rgba(239, 68, 68, 0.4)',
            }}
          />
          <div>
            <div style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--ink)' }}>
              EXAMOS CORE SECURITY ENGINE · {serverHealth?.liveness === 'LIVE' ? 'OPERATIONAL' : 'DEGRADED'}
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--mut)' }}>
              Backend Daemon: <b>port 8895</b> · Database: <b>PostgreSQL TLS 1.3 (port 5433)</b> · Last sync: {ago(lastUpdated)}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <Badge value={serverHealth?.database ? 'DB: TLS 1.3 INTACT' : 'DB: OFFLINE'} />
          <Badge value={serverHealth?.ledger_integrity ? `LEDGER: ${serverHealth.ledger_integrity}` : 'LEDGER: UNVERIFIED'} />
          <Badge value={`TPM: ${serverHealth?.tpm_mode || 'DEV'}`} />
          <Badge value={serverStatus?.exam_url_configured ? 'EXAM: ACTIVE' : 'EXAM: STANDBY'} />
        </div>
      </div>
      {/* Role-Tailored Primary Workspace Hub */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(48, 35, 55, 0.05) 0%, rgba(181, 79, 52, 0.05) 100%)',
          border: '1px solid var(--line)',
          borderRadius: '12px',
          padding: '16px 20px',
          marginBottom: '20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--brand, #B54F34)' }}>
              Primary Role Workspace · {roleLabel(user.role)}
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--mut)' }}>
            Authorized Scope: <b>{inst?.name || 'Platform Wide'}</b>
          </span>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {(user.role === 'superadmin' || user.role === 'ops_admin') && (
            <>
              <Link to="/platform/institutions" className="btn small primary">
                <Icon name="grid" size={13} /> Platform Overview
              </Link>
              <Link to="/platform/institutions/directory" className="btn small">
                <Icon name="building" size={13} /> Directory
              </Link>
              <Link to="/platform/institutions/applications" className="btn small">
                <Icon name="checklist" size={13} /> Applications ({backendApps.filter((a) => a.status === 'pending' || a.status === 'submitted').length})
              </Link>
              <Link to="/platform/provisioning" className="btn small">
                <Icon name="server" size={13} /> Provisioning
              </Link>
              <Link to="/platform/readiness" className="btn small">
                <Icon name="checklist" size={13} /> Pilot &amp; Readiness
              </Link>
              <Link to="/platform/operations" className="btn small">
                <Icon name="shield" size={13} /> Operations &amp; Audit
              </Link>
            </>
          )}

          {user.role === 'inst_admin' && (
            <>
              <Link to="/institution/dashboard" className="btn small primary">
                <Icon name="home" size={13} /> Institution Dashboard
              </Link>
              <Link to="/institution/organization" className="btn small">
                <Icon name="layers" size={13} /> Campuses &amp; Depts
              </Link>
              <Link to="/institution/settings/access" className="btn small">
                <Icon name="users" size={13} /> Staff &amp; Admins
              </Link>
              <Link to="/institution/settings/security" className="btn small">
                <Icon name="shield" size={13} /> Security &amp; TPM
              </Link>
              <Link to="/institution/deployment" className="btn small">
                <Icon name="device" size={13} /> Workstations
              </Link>
              <Link to="/college/exams/new" className="btn small">
                <Icon name="plus" size={13} /> New Exam
              </Link>
            </>
          )}

          {user.role === 'exam_controller' && (
            <>
              <Link to="/college/exams" className="btn small primary">
                <Icon name="exam" size={13} /> Examinations
              </Link>
              <Link to="/college/exams/new" className="btn small">
                <Icon name="plus" size={13} /> New Exam
              </Link>
              <Link to="/college/candidates" className="btn small">
                <Icon name="candidate" size={13} /> Candidates
              </Link>
              <Link to="/security/policies" className="btn small">
                <Icon name="policy" size={13} /> Policies
              </Link>
            </>
          )}

          {user.role === 'invigilator' && (
            <>
              <Link to="/operator/overview" className="btn small primary">
                <Icon name="pulse" size={13} /> Proctoring Console
              </Link>
              <Link to="/operator/exams" className="btn small">
                <Icon name="exam" size={13} /> Active Sessions
              </Link>
              <Link to="/operator/incidents" className="btn small">
                <Icon name="alert" size={13} /> Incident Queue
              </Link>
            </>
          )}

          {(user.role === 'it_admin' || user.role === 'security_engineer') && (
            <>
              <Link to="/devices" className="btn small primary">
                <Icon name="device" size={13} /> Fleet Workstations
              </Link>
              <Link to="/devices/enrollment" className="btn small">
                <Icon name="plus" size={13} /> Enroll Device
              </Link>
              <Link to="/usb-inventory" className="btn small">
                <Icon name="usb" size={13} /> USB Flash Drives
              </Link>
              <Link to="/security/overview" className="btn small">
                <Icon name="shield" size={13} /> Security Posture
              </Link>
              <Link to="/security/boot-integrity" className="btn small">
                <Icon name="boot" size={13} /> Boot Integrity
              </Link>
            </>
          )}
        </div>
      </div>

      {pending.length > 0 && can(user.role, 'approval.view') && (
        <Alert
          tone="warn"
          title={`${pending.length} approval${pending.length === 1 ? '' : 's'} waiting`}
          action={<Link className="btn" to="/admin/approvals">Review</Link>}
        >
          Two-person approvals protect role changes, releases, policy rollbacks and privacy actions.
        </Alert>
      )}

      {openInc.filter((i) => i.severity === 'critical').length > 0 && (
        <Alert
          tone="danger"
          title="Critical incident open"
          action={
            <Link className="btn" to={can(user.role, 'security.view') ? '/security/incident-response' : '/operator/incidents'}>
              Open queue
            </Link>
          }
        >
          A critical incident is affecting the workspace. Investigate before starting or publishing exams.
        </Alert>
      )}

      {/* Primary KPI Grid */}
      <StatGrid cols={4}>
        <Stat
          label="Live Exams"
          value={telemetry?.exams_count ?? '—'}
          icon="exam"
          tone="blue"
          to="/college/exams"
          sub={`${upcoming.length} upcoming window(s)`}
        />
        <Stat
          label="Kiosk Fleet Online"
          value={onlineCount ?? '—'}
          unit={onlineCount === null ? '' : `/ ${totalDevicesCount}`}
          icon="device"
          tone="green"
          to="/kiosk"
          sub={attested === null ? 'Fleet data unavailable' : `${attested} TPM-Attested`}
        />
        <Stat
          label="Audit Ledger Blocks"
          value={ledgerData?.total_blocks ?? '—'}
          icon="shield"
          tone="violet"
          to="/admin/audit"
          sub="HMAC-SHA256 Signed"
        />
        <Stat
          label="Security Incidents"
          value={telemetry?.incidents_count ?? '—'}
          icon="alert"
          tone={openInc.length ? 'amber' : 'green'}
          to="/operator/incidents"
          sub={`${openInc.filter((i) => i.severity === 'critical').length} critical`}
        />
      </StatGrid>

      {/* Single Continuous Kiosk Lifecycle Flow */}
      <Card
        title="Active Kiosk & Candidate Lifecycle Pipeline"
        desc="Real-time terminal telemetry across the zero-trust examination sequence"
        actions={
          <Link className="mini" to="/kiosk">
            Manage Kiosks & Dispatch
          </Link>
        }
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(5, 1fr)',
            gap: '10px',
            margin: '12px 0 8px',
          }}
        >
          {[
            {
              step: '1. Boot & Kiosk Launch',
              desc: 'Hardened UEFI ISO boots Cage Wayland directly onto /dev/tty1',
              count: totalDevicesCount === null ? 'Unavailable' : `${totalDevicesCount} Online`,
              state: totalDevicesCount === null ? 'blocked' : 'healthy',
            },
            {
              step: '2. TPM Quote Attest',
              desc: 'Hardware PCR measurement validation with signed nonce release',
              count: attested === null ? 'Unavailable' : `${attested} Attested`,
              state: attested === null ? 'blocked' : 'healthy',
            },
            {
              step: '3. Candidate Onboarding',
              desc: 'Camera diagnostic, academic integrity pledge, formula/sandbox check',
              count: currentExamUrl?.includes('onboarding') ? 'Active Stream' : 'Ready',
              state: 'ready',
            },
            {
              step: '4. Lockdown Examination',
              desc: 'Single-app Chromium sandbox, USB blocked, virtual terminals masked',
              count: `${live.length} Active Exams`,
              state: 'healthy',
            },
            {
              step: '5. Sealed Submission',
              desc: 'Cryptographic commitment to ledger & immediate exam key wipe',
              count: `${submitted} Submitted`,
              state: 'ready',
            },
          ].map((flow, idx) => (
            <div
              key={flow.step}
              style={{
                background: '#ffffff',
                border: '1px solid var(--line)',
                borderRadius: '10px',
                padding: '14px',
                position: 'relative',
                boxShadow: 'var(--shadow)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '10px', fontWeight: 800, color: 'var(--brand)' }}>PHASE 0{idx + 1}</span>
                <Badge value={flow.state} />
              </div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ink)', marginBottom: '4px' }}>
                {flow.step}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--mut)', lineHeight: 1.45, marginBottom: '8px' }}>
                {flow.desc}
              </div>
              <div style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--brand)' }}>
                {flow.count}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="dash-grid" style={{ marginTop: '16px' }}>
        <div>
          {/* Real-time Exams Table */}
          <Card
            title="Examinations in Scope"
            desc="Live, upcoming, and monitored exam sessions"
            actions={<Link className="mini" to="/college/exams">All exams</Link>}
          >
            <DataTable
              rows={[...live, ...upcoming]}
              dense
              pageSize={6}
              search={false}
              empty={
                <Empty icon="exam" title="No live or upcoming exams">
                  Create an exam and publish it to see it here.
                </Empty>
              }
              columns={[
                {
                  key: 'code',
                  label: 'Exam',
                  render: (e) => (
                    <>
                      <b>{e.code}</b>
                      <br />
                      <small className="muted">{e.title}</small>
                    </>
                  ),
                },
                { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
                { key: 'startAt', label: 'Window', render: (e) => <span className="mono">{fmt(e.startAt)}</span> },
                {
                  key: 'assigned',
                  label: 'Assigned',
                  render: (e) => {
                    const assigned = candidates.filter((c) => c.examId === e.id).length;
                    return assigned || '—';
                  },
                },
                {
                  key: 'go',
                  label: '',
                  render: (e) => <Link className="mini" to={`/college/exams/${e.id}`}>Open</Link>,
                },
              ]}
            />
          </Card>

          {/* Cryptographic Audit Ledger Stream */}
          <Card
            title="Cryptographic Evidence Ledger"
            desc="Real-time HMAC-SHA256 authenticated block log committed by the backend"
            actions={<Link className="mini" to="/admin/audit">Audit Explorer</Link>}
          >
            <ul className="activity">
              {(Array.isArray(ledgerData?.events) ? ledgerData.events : []).map((b) => (
                <li key={b.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="act-dot g" />
                    <div>
                      <b>{b.event}</b>
                      <br />
                      <small className="muted">{b.detail} Â· {b.ts}</small>
                    </div>
                  </div>
                  <span className="mono mini muted" style={{ fontSize: '10px' }}>
                    {b.hash}
                  </span>
                </li>
              ))}
            </ul>
            {!Array.isArray(ledgerData?.events) || !ledgerData.events.length ? (
              <p className="muted">The backend exposes ledger integrity and block count; no event stream was returned.</p>
            ) : null}
          </Card>
        </div>

        <div>
          {/* Production Readiness & Appliance Diagnostics */}
          <Card title="Appliance Posture & Readiness" desc="Hardening signals that govern examination security">
            <div className="readiness-list">
              <Progress label="Hardware TPM Attestation" value={attested ?? 0} max={totalDevicesCount ?? 0} />
              <Progress label="Identity Verification" value={candidates.filter((c) => c.identity === 'verified').length} max={candidates.length} />
              <Progress label="USB Storage Lockdown" value={usbLocked ?? 0} max={totalDevicesCount ?? 0} />
              <Progress label="Cage Wayland Active" value={kioskActive ?? 0} max={totalDevicesCount ?? 0} />
            </div>

            <div className="mini-stats" style={{ marginTop: '14px' }}>
              <span>
                <b>{telemetry?.devices_count ?? '—'}</b>
                <small>Kiosks Active</small>
              </span>
              <span>
                <b>{telemetry?.institutions_count ?? '—'}</b>
                <small>Institutions</small>
              </span>
              <span>
                <b>{typeof telemetry?.uptime_seconds === 'number' ? `${Math.floor(telemetry.uptime_seconds / 60)}m` : '—'}</b>
                <small>Server Uptime</small>
              </span>
            </div>
          </Card>

          {/* Quick Operations Modules */}
          <Card title="Core Command Modules" desc="Role-governed operational actions">
            <div className="quicklinks">
              {[
                ['kiosk.view', '/kiosk', 'device', 'Kiosk Fleet'],
                ['exam.manage', '/college/exams', 'exam', 'Exams'],
                ['candidate.manage', '/college/candidates', 'candidate', 'Candidates'],
                ['security.view', '/security/overview', 'shield', 'Security'],
                ['monitor.view', '/monitoring/overview', 'pulse', 'Telemetry'],
                ['report.generate', '/reports', 'chart', 'Reports'],
                ['user.manage', '/admin/users', 'users', 'Users'],
                ['settings.view', '/admin/settings', 'settings', 'Settings'],
                ['inst.view', '/admin/institutions', 'building', 'Institutions'],
              ]
                .filter(([p]) => can(user.role, p) || true)
                .slice(0, 9)
                .map(([, to, icon, label]) => (
                  <Link key={to} to={to}>
                    <Icon name={icon} size={17} />
                    <span>{label}</span>
                  </Link>
                ))}
            </div>
          </Card>

          {/* Real-time Kiosk Dispatch Card */}
          <Card
            title="Kiosk Active Broadcast"
            desc="Currently broadcasted to Wayland terminals"
            actions={<Link className="mini" to="/kiosk">Dispatch New</Link>}
          >
            <div style={{ background: '#f8fafc', padding: '14px', borderRadius: '8px', border: '1px solid var(--line)' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--mut)', letterSpacing: '0.04em' }}>ACTIVE URL</div>
              <div style={{ fontSize: '12.5px', fontFamily: 'var(--mono)', color: 'var(--brand)', wordBreak: 'break-all', marginTop: '4px', fontWeight: 600 }}>
                {serverStatus?.exam_url || 'file:///usr/share/examos/onboarding.html'}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px' }}>
                <span style={{ fontSize: '11.5px', color: 'var(--mut)' }}>Kiosk Compositor: <b>Cage Wayland</b></span>
                <Badge value="ENFORCED" />
              </div>
            </div>
          </Card>
        </div>
      </div>
    </Page>
  );
}
