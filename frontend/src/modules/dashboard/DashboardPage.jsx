import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can, roleLabel, isGlobal } from '../../core/security/rbac';
import { Page, Card, Stat, StatGrid, Alert, Badge, DataTable, Icon, Progress, SectionTitle, Empty } from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';

const greeting = () => { const h = new Date().getHours(); return h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening'; };

export default function DashboardPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
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

  const live = exams.filter((e) => e.status === 'live');
  const upcoming = exams.filter((e) => e.status === 'published').sort((a, b) => a.startAt - b.startAt).slice(0, 5);
  const openInc = incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status));
  const pending = approvals.filter((a) => a.status === 'pending');
  const openTickets = support.filter((s) => ['new', 'assigned', 'waiting', 'in-progress', 'reopened'].includes(s.status));
  const attested = devices.filter((d) => d.trust === 'attested').length;
  const online = devices.filter((d) => Date.now() - (d.lastSeen || 0) < 40000).length;
  const submitted = sessions.filter((s) => s.status === 'submitted').length;
  const latestAudit = [...audit].sort((a, b) => b.seq - a.seq).slice(0, 7);
  const myTenantUsers = users.filter((u) => !tenantId || u.tenantId === tenantId);
  const inst = tenant;
  const outstanding = invoices.filter((i) => ['open', 'overdue'].includes(i.status)).reduce((s, i) => s + (i.total || 0), 0);
  const global = isGlobal(user.role);

  const scopeLabel = global ? `${tenants.length} institutions` : inst?.name || 'No institution';

  return <Page
    title={`${greeting()}, ${user.name.split(' ')[0]}`}
    desc={`${roleLabel(user.role)} · ${scopeLabel}${inst?.timezone ? ' · ' + inst.timezone : ''}`}
    actions={<>
      <Link className="btn" to="/notifications"><Icon name="bell" size={15} /> Inbox</Link>
      {can(user.role, 'exam.manage') && <Link className="btn primary" to="/college/exams/new"><Icon name="plus" size={15} /> New exam</Link>}
    </>}
  >
    {!inst && !global && <Alert tone="warn" title="No institution scope">Your account is not linked to an institution. Ask a platform administrator to assign one.</Alert>}
    {inst?.status !== 'active' && inst && <Alert tone="danger" title={`Institution is ${inst.status}`}>Exams cannot be published or started while the institution is suspended. Contact the platform team.</Alert>}
    {pending.length > 0 && can(user.role, 'approval.view') && <Alert tone="warn" title={`${pending.length} approval${pending.length === 1 ? '' : 's'} waiting`} action={<Link className="btn" to="/admin/approvals">Review</Link>}>
      Two-person approvals protect role changes, releases, policy rollbacks and privacy actions.
    </Alert>}
    {openInc.filter((i) => i.severity === 'critical').length > 0 && <Alert tone="danger" title="Critical incident open" action={<Link className="btn" to={can(user.role, 'security.view') ? '/security/incident-response' : '/operator/incidents'}>Open queue</Link>}>
      A critical incident is affecting the workspace. Investigate before starting or publishing exams.
    </Alert>}

    <StatGrid cols={4}>
      <Stat label="Live exams" value={live.length} icon="exam" tone="blue" to="/college/exams" sub={`${upcoming.length} published upcoming`} />
      <Stat label="Candidates" value={candidates.length} icon="candidate" tone="green" to="/college/candidates" sub={`${candidates.filter((c) => c.identity === 'verified').length} identity verified`} />
      <Stat label="Devices online" value={online} unit={`/ ${devices.length}`} icon="device" tone="violet" to="/devices" sub={`${attested} attested`} />
      <Stat label="Open incidents" value={openInc.length} icon="alert" tone={openInc.length ? 'amber' : 'green'} to="/operator/incidents" sub={`${openInc.filter((i) => i.severity === 'critical').length} critical`} />
    </StatGrid>

    <div className="dash-grid">
      <div>
        <Card title="Exams needing attention" desc="Live and upcoming windows in your scope" actions={<Link className="mini" to="/college/exams">All exams</Link>}>
          <DataTable rows={[...live, ...upcoming]} dense pageSize={6} search={false}
            empty={<Empty icon="exam" title="No live or upcoming exams">Create an exam and publish it to see it here.</Empty>}
            columns={[
              { key: 'code', label: 'Exam', render: (e) => <><b>{e.code}</b><br /><small className="muted">{e.title}</small></> },
              { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
              { key: 'startAt', label: 'Window', render: (e) => <span className="mono">{fmt(e.startAt)}</span> },
              { key: 'assigned', label: 'Assigned', render: (e) => candidates.filter((c) => c.examId === e.id).length },
              { key: 'go', label: '', render: (e) => <Link className="mini" to={`/college/exams/${e.id}`}>Open</Link> },
            ]} />
        </Card>

        <Card title="Recent activity" desc="Hash-chained audit events" actions={<Link className="mini" to="/admin/audit">Audit trail</Link>}>
          <ul className="activity">
            {latestAudit.map((e) => <li key={e.id}><span className={'act-dot ' + (e.event.includes('FAIL') || e.event.includes('DENIED') ? 'r' : e.event.includes('APPROV') ? 'g' : '')} /><div><b>{e.event.replace(/_/g, ' ')}</b><small className="muted">{e.detail || '—'} · {e.actor} · {ago(Date.parse(e.ts))}</small></div></li>)}
            {!latestAudit.length && <li className="muted">No activity recorded yet.</li>}
          </ul>
        </Card>
      </div>

      <div>
        <Card title="Readiness" desc="Signals that block a safe exam">
          <div className="readiness-list">
            <Progress label="Device attestation" value={attested} max={devices.length || 1} />
            <Progress label="Identity verification" value={candidates.filter((c) => c.identity === 'verified').length} max={candidates.length || 1} />
            <Progress label="USB custody verified" value={usbs.filter((u) => ['verified', 'returned', 'issued'].includes(u.status)).length} max={usbs.length || 1} />
            <Progress label="Sessions submitted" value={submitted} max={sessions.length || 1} />
          </div>
          <div className="mini-stats">
            <span><b>{devices.filter((d) => d.isolated).length}</b><small>isolated</small></span>
            <span><b>{securityEvents.filter((e) => e.status === 'open').length}</b><small>security events</small></span>
            <span><b>{evidence.filter((e) => e.verification === 'tampered').length}</b><small>evidence alerts</small></span>
          </div>
        </Card>

        <Card title="Your modules" desc="Based on your effective permissions">
          <div className="quicklinks">
            {[
              ['exam.manage', '/college/exams', 'exam', 'Exams'], ['candidate.manage', '/college/candidates', 'candidate', 'Candidates'],
              ['device.view', '/devices', 'device', 'Devices'], ['usb.view', '/usb-inventory', 'usb', 'USB inventory'],
              ['security.view', '/security/overview', 'shield', 'Security'], ['release.view', '/admin/releases', 'package', 'Releases'],
              ['monitor.view', '/monitoring/overview', 'pulse', 'Monitoring'], ['report.generate', '/reports', 'chart', 'Reports'],
              ['support.view', '/support', 'life', 'Support'], ['billing.view', '/admin/billing', 'card', 'Billing'],
              ['privacy.view', '/admin/privacy', 'lock', 'Privacy'], ['user.manage', '/admin/users', 'users', 'Users'],
              ['settings.view', '/admin/settings', 'settings', 'Settings'], ['approval.view', '/admin/approvals', 'check', 'Approvals'],
              ['inst.view', '/admin/institutions', 'building', 'Institutions'], ['student.view', '/student/home', 'home', 'My exams'],
            ].filter(([p]) => can(user.role, p)).slice(0, 10).map(([, to, icon, label]) => <Link key={to} to={to}><Icon name={icon} size={17} /><span>{label}</span></Link>)}
          </div>
        </Card>

        {can(user.role, 'billing.view') && <Card title="Commercial" actions={<Link className="mini" to="/admin/billing">Billing</Link>}>
          <div className="mini-stats">
            <span><b>{invoices.filter((i) => i.status === 'paid').length}</b><small>paid invoices</small></span>
            <span><b>₹{outstanding.toLocaleString('en-IN')}</b><small>outstanding</small></span>
            <span><b>{inst?.plan || '—'}</b><small>plan</small></span>
          </div>
        </Card>}
        {can(user.role, 'support.view') && <Card title="Support" actions={<Link className="mini" to="/support/requests">Requests</Link>}>
          <div className="mini-stats">
            <span><b>{openTickets.length}</b><small>open</small></span>
            <span><b>{openTickets.filter((t) => t.priority === 'critical').length}</b><small>critical</small></span>
            <span><b>{support.filter((t) => t.slaDue < Date.now() && !t.firstResponseAt && ['new', 'assigned', 'waiting', 'in-progress', 'reopened'].includes(t.status)).length}</b><small>SLA breached</small></span>
          </div>
        </Card>}
      </div>
    </div>

    {can(user.role, 'release.view') && <Card title="Release posture" desc="Approved and rolling releases across the platform" actions={<Link className="mini" to="/admin/releases">All releases</Link>}>
      <div className="release-strip">
        {releases.slice(0, 5).map((r) => <Link key={r.id} to={`/releases/${r.id}`} className="release-chip"><b>{r.version}</b><Badge value={r.status} /><small>{r.rollout || 0}% rollout · {r.criticalCves || 0} critical</small></Link>)}
        {!releases.length && <span className="muted">No releases yet.</span>}
      </div>
    </Card>}

    {can(user.role, 'user.manage') && <Card title="People" desc="Accounts in your scope" actions={<Link className="mini" to="/admin/users">Manage users</Link>}>
      <div className="mini-stats">
        <span><b>{myTenantUsers.filter((u) => u.status === 'active').length}</b><small>active accounts</small></span>
        <span><b>{myTenantUsers.filter((u) => u.mfaEnabled !== false).length}</b><small>MFA enabled</small></span>
        <span><b>{myTenantUsers.filter((u) => u.status === 'suspended' || u.status === 'locked').length}</b><small>suspended or locked</small></span>
        <span><b>{myTenantUsers.filter((u) => u.role === 'student').length}</b><small>students</small></span>
      </div>
    </Card>}
  </Page>;
}
