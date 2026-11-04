import { useState, useMemo, useEffect } from 'react';
import * as Api from '../../core/api/services';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import { can, roleLabel } from '../../core/security/rbac';
import { fmt, ago } from '../../core/ui/format';
import {
  Page, Card, StatGrid, Stat, Alert, Empty, Loading,
  DataTable, Badge, Modal, ActionDialog, useFlash, Flash,
  Icon, Field, Input, Select, Textarea, Checkbox
} from '../../core/ui/kit';
import {
  createCampus, createDepartment, assignStaff, removeStaff,
  saveSecuritySettings, saveExamDefaults,
  listInstitutionAdmins, inviteInstitutionAdmin, removeInstitutionAdmin,
  getOrgTerms, isCorporateEntity, institutionStats,
  fetchInstitutionOnboarding,
} from '../institutions/service';

/* =====================================================================
   PAGE 9 — Institution Home / Dashboard (/institution/dashboard)
===================================================================== */
export function InstitutionDashboardPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
  const [stats, setStats] = useState(null);
  const [onboarding, setOnboarding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    let active = true;
    setStats(null);
    setOnboarding(null);
    setLoading(true);
    setLoadError('');
    if (!tenantId) {
      setLoadError('Select an institution to load its dashboard.');
      setLoading(false);
      return () => { active = false; };
    }
    Promise.allSettled([
      institutionStats(tenantId),
      fetchInstitutionOnboarding(tenantId),
    ]).then(([statsResult, onboardingResult]) => {
      if (!active) return;
      const errors = [];
      if (statsResult.status === 'fulfilled') setStats(statsResult.value);
      else errors.push(`Statistics: ${statsResult.reason?.message || 'request failed'}`);
      if (onboardingResult.status === 'fulfilled') setOnboarding(onboardingResult.value);
      else errors.push(`Onboarding: ${onboardingResult.reason?.message || 'request failed'}`);
      setLoadError(errors.join('; '));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [tenantId]);

  return (
    <Page
      title={tenant?.name ? `${tenant.name} · Console` : 'Institution Dashboard'}
      desc="Certified testing enclave management: Sites, staff, candidate/examinee rosters, workstation attestation, and live examinations."
      breadcrumb={<div className="crumbs-inline"><span>Institution Admin</span><Icon name="arrow" size={12} /><span>Dashboard</span></div>}
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to="/institution/organization" className="btn">
            <Icon name="layers" size={14} /> Organization
          </Link>
          <Link to="/college/exams/new" className="btn primary">
            <Icon name="plus" size={14} /> Schedule New Exam
          </Link>
        </div>
      }
    >
      {loadError && <Alert tone="danger">{loadError}</Alert>}

      <StatGrid cols={4}>
        <Stat label="Campuses" value={stats?.campuses ?? (loading ? '…' : '—')} icon="building" />
        <Stat label="Centres" value={stats?.centers ?? (loading ? '…' : '—')} icon="building" />
        <Stat label="Enrolled devices" value={stats?.enrolledDevices ?? (loading ? '…' : '—')} icon="device" to="/institution/deployment" />
        <Stat label="Candidates" value={stats?.candidates ?? (loading ? '…' : '—')} icon="candidate" />
        <Stat label="Live / Total exams" value={stats ? `${stats.liveExams} / ${stats.exams}` : (loading ? '…' : '—')} icon="exam" to="/college/exams" />
        <Stat label="Open incidents" value={stats?.openIncidents ?? (loading ? '…' : '—')} icon="alert" to="/operator/incidents" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px', margin: '20px 0' }}>
        <Card title="Backend onboarding state" desc="Current persisted onboarding checklist status">
          {onboarding ? (
            <KeyValue items={[
              ['Status', onboarding.status || '—'],
              ['Completed steps', onboarding.completedSteps ?? '—'],
              ['Total steps', onboarding.totalSteps ?? '—'],
              ['Updated', onboarding.updatedAt ? fmt(onboarding.updatedAt) : '—'],
            ]} />
          ) : (
            <p className="muted">{loading ? 'Loading onboarding state…' : 'Onboarding state is unavailable.'}</p>
          )}
        </Card>

        <Card title="Quick Institutional Links" desc="Direct access to operational workflows">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <Link to="/institution/settings/profile" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="home" size={16} /> Official Institution Profile &amp; Domains
            </Link>
            <Link to="/institution/organization" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="pin" size={16} /> {`${getOrgTerms(tenant?.entityType).campusLabel}, ${getOrgTerms(tenant?.entityType).departmentLabel} & Programs`}
            </Link>
            <Link to="/institution/settings/access" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="users" size={16} /> Administrators &amp; Access Controls
            </Link>
            <Link to="/institution/settings/security" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="shield" size={16} /> Security Policies &amp; Deployment Bounds
            </Link>
            <Link to="/institution/deployment" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="checklist" size={16} /> Deployment Readiness &amp; Workstations
            </Link>
          </div>
        </Card>
      </div>
    </Page>
  );
}

/* =====================================================================
   PAGE 10 — Institution Profile (/institution/settings/profile)
===================================================================== */
export function InstitutionProfilePage() {
  const { tenant } = useTenant();

  return (
    <Page
      title="Institution Profile"
      desc="Official legal identity, registration identifier, primary physical address, and verified organizational domains."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Profile</span></div>}
    >
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Official Institutional Identity" desc="Verified educational charter data">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div><small className="muted">Official Legal Name</small><br /><b>{tenant?.name || '—'}</b></div>
            <div><small className="muted">Institution Code</small><br /><code>{tenant?.code || '—'}</code></div>
            {/* H7 fix: show real website_url from backend, not fabricated URL. */}
            {tenant?.website_url && (
              <div><small className="muted">Accredited Website</small><br /><a href={tenant.website_url} target="_blank" rel="noreferrer">{tenant.website_url}</a></div>
            )}
            <div><small className="muted">Jurisdiction / State</small><br /><span>{tenant?.region || '—'}</span></div>
            <div><small className="muted">Operational Status</small><br /><Badge value={tenant?.status || '—'} /></div>
          </div>
        </Card>

        <Card title="Verified Organizational Domains" desc="Domains permitted for SSO and email attribution">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* H7 fix: show real domains from backend data, no fabricated entries or fake "Verified" badges. */}
            {(tenant?.domains?.length ? tenant.domains : []).map((domain) => (
              <div key={domain} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', background: 'var(--bg-subtle, #f8fafc)', borderRadius: '6px' }}>
                <div>
                  <b>@{domain}</b>
                </div>
              </div>
            ))}
            {!tenant?.domains?.length && (
              <div style={{ padding: '12px', color: 'var(--muted, #94a3b8)' }}>No domains registered.</div>
            )}
          </div>
        </Card>

        <Card title="Sensitive profile updates" desc="Legal name, registration number and accredited domains" className="span2">
          <p className="muted" style={{ margin: 0 }}>
            Changes to the official legal identity or accredited domains require verification by the
            ExamOS platform team. There is no self-service change path: a platform administrator must
            review the supporting documentation and apply the update in the backend before it appears here.
          </p>
        </Card>
      </div>
    </Page>
  );
}

/* =====================================================================
   PAGE 11 — Organization Structure (/institution/organization)
===================================================================== */
export function InstitutionOrganizationPage() {
  const { user } = useAuth();
  const { tenant } = useTenant();
  const [liveCampuses, setLiveCampuses] = useState(null);
  const [liveDepartments, setLiveDepartments] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const { msg, setMsg, run, busy } = useFlash();

  const loadOrg = async () => {
    if (!tenant?.id) {
      setLiveCampuses(null);
      setLiveDepartments(null);
      setLoadError('Select an institution to load its organization structure.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setLoadError('');
    setLiveCampuses(null);
    setLiveDepartments(null);
    const [campusResult, departmentResult] = await Promise.allSettled([
      Api.listCampuses(tenant.id),
      Api.listDepartments(tenant.id),
    ]);
    const errors = [];
    const readRows = (result, key, label) => {
      if (result.status === 'rejected') {
        errors.push(`${label}: ${result.reason?.message || 'request failed'}`);
        return null;
      }
      const rows = result.value?.[key] || result.value;
      if (!Array.isArray(rows)) {
        errors.push(`${label}: backend returned an unexpected response.`);
        return null;
      }
      return rows;
    };
    const campuses = readRows(campusResult, 'campuses', 'Campuses');
    const departments = readRows(departmentResult, 'departments', 'Departments');
    if (campuses) setLiveCampuses(campuses.map(c => ({ ...c, id: c.id || c.campus_id, tenantId: c.tenantId || c.tenant_id })));
    if (departments) setLiveDepartments(departments.map(d => ({ ...d, id: d.id || d.department_id, tenantId: d.tenantId || d.tenant_id })));
    setLoadError(errors.join('; '));
    setLoading(false);
  };

  useEffect(() => {
    let active = true;
    loadOrg().catch((error) => {
      if (active) {
        setLoadError(error.message || 'Unable to load organization structure.');
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [tenant?.id]);

  const campuses = liveCampuses || [];
  const departments = liveDepartments || [];

  const [newCampusModal, setNewCampusModal] = useState(false);
  const [newCampus, setNewCampus] = useState({ name: '', code: '', city: '', address: '', capacity: '' });

  const [newDeptModal, setNewDeptModal] = useState(false);
  const [newDept, setNewDept] = useState({ name: '', code: '', campusId: '', type: 'academic' });

  const handleAddCampus = async () => {
    await run(async () => {
      await createCampus(user, { tenantId: tenant?.id, ...newCampus });
      setNewCampusModal(false);
      await loadOrg();
      return `Campus ${newCampus.name} created.`;
    }, 'Campus added.');
  };

  const handleAddDept = async () => {
    await run(async () => {
      await createDepartment(user, { tenantId: tenant?.id, ...newDept });
      setNewDeptModal(false);
      await loadOrg();
      return `Department ${newDept.name} created.`;
    }, 'Department added.');
  };

  return (
    <Page
      title="Organization Structure"
      desc={`${getOrgTerms(tenant?.entityType).campusLabel}, ${getOrgTerms(tenant?.entityType).departmentLabel}, programs, and local site administrators.`}
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Organization</span></div>}
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          {can(user.role, 'dept.manage') && (
            <button className="btn" onClick={() => setNewDeptModal(true)}>
              <Icon name="plus" size={14} /> New Department
            </button>
          )}
          {can(user.role, 'campus.manage') && (
            <button className="btn primary" onClick={() => setNewCampusModal(true)}>
              <Icon name="pin" size={14} /> Add Campus
            </button>
          )}
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Alert tone="danger">{loadError}</Alert>}
      <StatGrid cols={3}>
        <Stat label={getOrgTerms(tenant?.entityType).campusLabel} value={liveCampuses ? campuses.length : loading ? '…' : '—'} icon="pin" sub="Physical Testing Sites" />
        <Stat label={getOrgTerms(tenant?.entityType).departmentLabel} value={liveDepartments ? departments.length : loading ? '…' : '—'} icon="layers" sub="Organizational Divisions" />
        <Stat label="Total Testing Seats" value={liveCampuses ? campuses.reduce((acc, c) => acc + (Number(c.capacity) || 0), 0) : loading ? '…' : '—'} icon="users" sub="Capacity" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginTop: '16px' }}>
        <Card title={getOrgTerms(tenant?.entityType).campusLabel} desc="Approved physical testing sites">
          <DataTable
            rows={campuses}
            columns={[
              { key: 'name', label: 'Campus', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code} · {c.city}</small></> },
              { key: 'capacity', label: 'Capacity', render: (c) => (c.capacity != null ? `${c.capacity} seats` : '—') },
              { key: 'status', label: 'Status', badge: true },
            ]}
            empty={<Empty icon="pin" title={`No ${getOrgTerms(tenant?.entityType).campusLabel} added yet`} />}
          />
        </Card>

        <Card title={`${getOrgTerms(tenant?.entityType).departmentLabel} & Teams`} desc="Organizational governance units">
          <DataTable
            rows={departments}
            columns={[
              { key: 'name', label: 'Department', render: (d) => <><b>{d.name}</b><br /><small className="muted">{d.code}</small></> },
              { key: 'campus', label: 'Campus', render: (d) => campuses.find((c) => c.id === d.campusId)?.code || '—' },
              { key: 'type', label: 'Type', badge: true },
            ]}
            empty={<Empty icon="layers" title="No departments added yet" />}
          />
        </Card>
      </div>

      {newCampusModal && (
        <Modal title={`Add New ${isCorporateEntity(tenant?.entityType) ? "Office / Testing Center" : "Campus"}`} onClose={() => setNewCampusModal(false)}>
          <div className="formgrid">
            <Field label={isCorporateEntity(tenant?.entityType) ? "Site / Office Name" : "Campus Name"}><Input value={newCampus.name} onChange={(e) => setNewCampus({ ...newCampus, name: e.target.value })} placeholder={isCorporateEntity(tenant?.entityType) ? "e.g. HQ Office" : "e.g. North Campus"} required /></Field>
            <Field label={isCorporateEntity(tenant?.entityType) ? "Site Code" : "Campus Code"}><Input value={newCampus.code} onChange={(e) => setNewCampus({ ...newCampus, code: e.target.value.toUpperCase() })} placeholder="e.g. NC-01" required /></Field>
            <Field label="City"><Input value={newCampus.city} onChange={(e) => setNewCampus({ ...newCampus, city: e.target.value })} placeholder="e.g. Hyderabad" /></Field>
            <Field label="Seating Capacity"><Input type="number" value={newCampus.capacity} onChange={(e) => setNewCampus({ ...newCampus, capacity: Number(e.target.value) })} /></Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setNewCampusModal(false)}>Cancel</button>
            <button className="btn primary" onClick={handleAddCampus} disabled={busy || !newCampus.name || !newCampus.code}>{isCorporateEntity(tenant?.entityType) ? "Save Site" : "Save Campus"}</button>
          </div>
        </Modal>
      )}

      {newDeptModal && (
        <Modal title={`Add ${isCorporateEntity(tenant?.entityType) ? "Business Unit / Team" : "Academic Department"}`} onClose={() => setNewDeptModal(false)}>
          <div className="formgrid">
            <Field label="Department Name"><Input value={newDept.name} onChange={(e) => setNewDept({ ...newDept, name: e.target.value })} placeholder="e.g. Computer Science & Engineering" required /></Field>
            <Field label="Department Code"><Input value={newDept.code} onChange={(e) => setNewDept({ ...newDept, code: e.target.value.toUpperCase() })} placeholder="e.g. CSE" required /></Field>
            <Field label="Assigned Campus">
              <Select value={newDept.campusId} onChange={(e) => setNewDept({ ...newDept, campusId: e.target.value })} options={campuses.map((c) => ({ v: c.id, l: c.name }))} />
            </Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setNewDeptModal(false)}>Cancel</button>
            <button className="btn primary" onClick={handleAddDept} disabled={busy || !newDept.name || !newDept.code}>Save Department</button>
          </div>
        </Modal>
      )}
    </Page>
  );
}

/* =====================================================================
   PAGE 12 — Administrators and Access (/institution/settings/access)
===================================================================== */
export function InstitutionAccessPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
  const { msg, setMsg, run, busy } = useFlash();

  const [admins, setAdmins] = useState([]);
  const [campuses, setCampuses] = useState([]);
  const [campusError, setCampusError] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [inviteModal, setInviteModal] = useState(false);
  const [removeTarget, setRemoveTarget] = useState(null);
  const [inviteResult, setInviteResult] = useState(null); // shows credentials popup
  const [inviteData, setInviteData] = useState({
    email: '', name: '', role: 'inst_admin', campusId: '',
  });

  const loadAdmins = async () => {
    if (!tenantId) return;
    setLoading(true);
    try {
      const list = await listInstitutionAdmins(tenantId);
      setAdmins(Array.isArray(list) ? list : []);
      setLoadError('');
    } catch (e) {
      setAdmins([]);
      setLoadError(e.message || 'Unable to load administrators from the backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAdmins(); }, [tenantId]);

  useEffect(() => {
    let active = true;
    setCampuses([]);
    setCampusError('');
    if (!tenantId) return () => { active = false; };
    Api.listCampuses(tenantId).then((response) => {
      const rows = response?.campuses || response;
      if (!Array.isArray(rows)) throw new Error('Backend returned an unexpected campus response.');
      if (active) setCampuses(rows.map(c => ({ ...c, id: c.id || c.campus_id })));
    }).catch((error) => {
      if (active) setCampusError(error.message || 'Unable to load campuses from the backend.');
    });
    return () => { active = false; };
  }, [tenantId]);

  const handleInvite = async () => {
    if (!inviteData.email || !inviteData.name) return;
    await run(async () => {
      const result = await inviteInstitutionAdmin(user, tenantId, inviteData);
      setInviteModal(false);
      setInviteResult(result);
      await loadAdmins();
      return `Administrator ${inviteData.name} (${inviteData.email}) created and linked to ${tenant?.name || 'this institution'}.`;
    }, 'Administrator created.');
  };

  const handleRemove = async (reason) => {
    if (!removeTarget) return;
    await run(async () => {
      await removeInstitutionAdmin(user, tenantId, removeTarget.id, reason);
      setRemoveTarget(null);
      await loadAdmins();
      return `${removeTarget.name} removed from institution administrators.`;
    }, 'Administrator removed.');
  };

  const ADMIN_ROLE_OPTIONS = [
    { v: 'inst_admin', l: 'Institution Admin (Full Management)' },
    { v: 'exam_controller', l: 'Examination Controller (Exams & Policies)' },
    { v: 'invigilator', l: isCorporateEntity(tenant?.entityType) ? 'Exam Supervisor (Session Supervision)' : 'Invigilator (Session Supervision)' },
    { v: 'it_admin', l: 'IT Admin (Workstations & Devices)' },
    { v: 'security_engineer', l: 'Security Engineer (Attestation & Audit)' },
    { v: 'auditor', l: 'Auditor (Read-only Audit Access)' },
  ];

  return (
    <Page
      title="Administrators and Access"
      desc="Manage organizational administrators, exam supervisors, exam controllers, and monitor MFA security enrollment."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Administrators</span></div>}
      actions={
        can(user.role, 'user.manage') && (
          <button className="btn primary" onClick={() => { setInviteData({ email: '', name: '', role: 'inst_admin', campusId: '' }); setInviteModal(true); }}>
            <Icon name="plus" size={14} /> Invite Administrator
          </button>
        )
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Flash msg={{ tone: 'danger', text: loadError }} onClose={() => setLoadError('')} />}
      {campusError && <Flash msg={{ tone: 'danger', text: campusError }} onClose={() => setCampusError('')} />}

      <StatGrid cols={4}>
        <Stat label="Total Administrators" value={admins.length} icon="users" />
        <Stat label="Active Accounts" value={admins.filter((u) => u.status === 'active').length} tone="green" icon="check" />
        <Stat label="MFA Enrolled" value={admins.filter((u) => u.mfaEnabled).length} tone="blue" icon="shield" />
        <Stat label="Pending / Inactive" value={admins.filter((u) => u.status !== 'active').length} tone="amber" icon="warn" />
      </StatGrid>

      <Card title="Institutional Administrative Accounts" desc="Scoped roles, MFA security posture, and campus assignments">
        {loading ? (
          <Loading label="Loading administrators from server..." />
        ) : (
          <DataTable
            rows={admins}
            search={['name', 'email', 'username', 'role']}
            filters={[
              { key: 'role', label: 'All Roles', options: ADMIN_ROLE_OPTIONS.map((r) => r.v) },
              { key: 'status', label: 'All Statuses', options: ['active', 'suspended', 'locked'] },
            ]}
            columns={[
              {
                key: 'name',
                label: 'Administrator',
                sortable: true,
                render: (u) => (
                  <>
                    <b>{u.name || u.username}</b>
                    <br />
                    <small className="muted">{u.email || u.username}</small>
                  </>
                ),
              },
              {
                key: 'role',
                label: 'Role',
                render: (u) => <Badge value={roleLabel(u.role) || u.role} />,
              },
              {
                key: 'campusId',
                label: 'Campus',
                render: (u) => {
                  if (!u.campusId) return <span className="muted">All Campuses</span>;
                  const c = campuses.find((x) => x.id === u.campusId);
                  return c ? c.name : <code className="sm">{u.campusId}</code>;
                },
              },
              {
                key: 'mfa',
                label: '2FA / TOTP',
                render: (u) => u.mfaEnabled === true
                  ? <span className="badge g">RFC 6238 Active</span>
                  : u.mfaEnabled === false
                    ? <span className="badge amber">Not Enrolled</span>
                    : '—',
              },
              { key: 'status', label: 'Status', badge: true },
              {
                key: 'lastLogin',
                label: 'Last Login',
                render: (u) => u.lastLogin ? ago(u.lastLogin) : <span className="muted">Never</span>,
              },
            ]}
            actions={(u) => [
              ...(can(user.role, 'user.manage') && u.id !== user.id ? [{
                label: 'Remove Access',
                danger: true,
                onClick: () => setRemoveTarget(u),
              }] : []),
            ]}
            empty={
              <Empty
                icon="users"
                title="No administrators yet"
                desc="Invite your first institutional administrator using the button above."
                action={
                  can(user.role, 'user.manage') && (
                    <button className="btn primary" onClick={() => setInviteModal(true)}>
                      Invite Administrator
                    </button>
                  )
                }
              />
            }
          />
        )}
      </Card>

      {/* Invite Modal */}
      {inviteModal && (
        <Modal title="Invite Institutional Administrator" desc={`Add a new administrator to ${tenant?.name || 'this institution'}. Their account will be scoped to this institution only.`} onClose={() => setInviteModal(false)}>
          <div className="formgrid">
            <Field label="Full Name" required className="span2">
              <Input
                value={inviteData.name}
                onChange={(e) => setInviteData({ ...inviteData, name: e.target.value })}
                placeholder="e.g. Dr. Priya Sharma"
                required
              />
            </Field>
            <Field label="Institutional Email Address" required className="span2">
              <Input
                type="email"
                value={inviteData.email}
                onChange={(e) => setInviteData({ ...inviteData, email: e.target.value })}
                placeholder={`e.g. admin@${tenant?.domains?.[0] || 'institution.edu'}`}
                required
              />
            </Field>
            <Field label="Role / Access Level" required>
              <Select
                value={inviteData.role}
                onChange={(e) => setInviteData({ ...inviteData, role: e.target.value })}
                options={ADMIN_ROLE_OPTIONS}
                placeholder={false}
              />
            </Field>
            <Field label="Campus Scope (optional)" help="Leave blank to grant access to all campuses">
              <Select
                value={inviteData.campusId}
                onChange={(e) => setInviteData({ ...inviteData, campusId: e.target.value })}
                options={[{ v: '', l: 'All Campuses (Global)' }, ...campuses.map((c) => ({ v: c.id, l: c.name }))]}
                placeholder={false}
              />
            </Field>
            <div className="span2" style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', padding: '12px 14px', fontSize: '13px' }}>
              <b>How this works:</b> An administrator account is created on the server scoped to <b>{tenant?.name || 'this institution'}</b>. A temporary password is generated — share it securely with the new admin. They must set up MFA (TOTP) on first login.
            </div>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setInviteModal(false)}>Cancel</button>
            <button
              className="btn primary"
              onClick={handleInvite}
              disabled={busy || !inviteData.email || !inviteData.name}
            >
              <Icon name="plus" size={14} /> Create Administrator Account
            </button>
          </div>
        </Modal>
      )}

      {/* Credentials Result Popup */}
      {inviteResult && (
        <Modal
          title="✅ Administrator Account Created"
          desc="Share these credentials securely with the new administrator."
          onClose={() => setInviteResult(null)}
        >
          <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '20px', marginBottom: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13.5px' }}>
              <div>
                <small style={{ color: 'var(--mut, #756F79)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>Full Name</small>
                <div style={{ fontWeight: 700 }}>{inviteResult.name}</div>
              </div>
              <div>
                <small style={{ color: 'var(--mut, #756F79)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>Email</small>
                <div style={{ fontWeight: 700 }}>{inviteResult.email}</div>
              </div>
              <div>
                <small style={{ color: 'var(--mut, #756F79)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>Username</small>
                <code style={{ fontSize: '13px' }}>{inviteResult.username}</code>
              </div>
              <div>
                <small style={{ color: 'var(--mut, #756F79)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>Role</small>
                <div><Badge value={roleLabel(inviteResult.role) || inviteResult.role} /></div>
              </div>
              {inviteResult.tempPassword && (
                <div style={{ gridColumn: 'span 2' }}>
                  <small style={{ color: 'var(--mut, #756F79)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>Temporary Password</small>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                    <code style={{ fontSize: '14px', fontWeight: 800, background: '#FFFFFF', padding: '4px 10px', borderRadius: '6px', border: '1px solid var(--gline, #b9e3cc)' }}>
                      {inviteResult.tempPassword}
                    </code>
                    <button className="btn small" onClick={() => navigator.clipboard?.writeText(inviteResult.tempPassword)}>Copy</button>
                  </div>
                  <small style={{ color: 'var(--r, #c0392b)', fontSize: '12px', display: 'block', marginTop: '4px' }}>
                    ⚠️ Share this password securely. The administrator must change it and set up MFA on first login.
                  </small>
                </div>
              )}
            </div>
          </div>
          <div style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', padding: '12px 14px', fontSize: '13px', marginBottom: '16px' }}>
            <b>Next steps for the administrator:</b>
            <ol style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
              <li>Go to <a href="/login" style={{ color: '#2563EB' }}>/login</a> and sign in with the above username and temporary password</li>
              <li>Set a new strong password when prompted</li>
              <li>Enroll MFA using Google Authenticator or any TOTP app</li>
              <li>Begin configuring the institution's exam schedule and campus hierarchy</li>
            </ol>
          </div>
          <div className="row end" style={{ gap: '8px' }}>
            <button className="btn primary" onClick={() => setInviteResult(null)}>Done</button>
          </div>
        </Modal>
      )}

      {/* Remove Confirmation */}
      {removeTarget && (
        <ActionDialog
          title={`Remove ${removeTarget.name}`}
          desc={`This will suspend ${removeTarget.name}'s access to ${tenant?.name || 'this institution'}. They will not be able to log in. This action is recorded in the audit trail.`}
          danger
          confirmLabel="Remove Access"
          onClose={() => setRemoveTarget(null)}
          onConfirm={handleRemove}
        />
      )}
    </Page>
  );
}

/* =====================================================================
   PAGE 13 — Security and Deployment Settings (/institution/settings/security)
===================================================================== */
export function InstitutionSecurityPage() {
  const { user } = useAuth();
  const { tenant, loading: tenantLoading } = useTenant();
  const { msg, setMsg, run, busy } = useFlash();

  const [settings, setSettings] = useState(() => ({
    requireTpm: tenant?.security?.requireTpm ?? false,
    blockUsb: !(tenant?.security?.allowUsbStorage ?? false),
    kioskFullscreen: tenant?.security?.kioskFullscreen ?? false,
    secondCameraAllowed: tenant?.security?.secondCameraAllowed ?? false,
    allowedOrigins: tenant?.security?.allowedOrigins || '',
  }));

  useEffect(() => {
    if (!tenant) return;
    setSettings({
      requireTpm: tenant.security?.requireTpm ?? false,
      blockUsb: !(tenant.security?.allowUsbStorage ?? false),
      kioskFullscreen: tenant.security?.kioskFullscreen ?? false,
      secondCameraAllowed: tenant.security?.secondCameraAllowed ?? false,
      allowedOrigins: tenant.security?.allowedOrigins || '',
    });
  }, [tenant]);

  const handleSave = async () => {
    await run(async () => {
      await saveSecuritySettings(user, tenant, {
        requireTpm: settings.requireTpm,
        allowUsbStorage: !settings.blockUsb,
        kioskFullscreen: settings.kioskFullscreen,
        secondCameraAllowed: settings.secondCameraAllowed,
        allowedOrigins: settings.allowedOrigins,
      });
      return 'Security configuration saved and synchronized.';
    }, 'Settings updated.');
  };

  return (
    <Page
      title="Security & Deployment Settings"
      desc="Approved ExamOS release, TPM 2.0 hardware attestation parameters, and target Exam URL allowed origins."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Security Settings</span></div>}
      actions={
        <button className="btn primary" onClick={handleSave} disabled={busy || tenantLoading || !tenant}>
          <Icon name="check" size={14} /> Save Security Configuration
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {!tenant && <Alert tone={tenantLoading ? 'info' : 'danger'}>{tenantLoading ? 'Loading institution settings…' : 'Institution settings are unavailable.'}</Alert>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Hardware Attestation & Kiosk Bounds">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', margin: '8px 0' }}>
            <Checkbox label="Require Hardware TPM 2.0 Silicon Attestation" checked={settings.requireTpm} onChange={(e) => setSettings({ ...settings, requireTpm: e.target.checked })} />
            <Checkbox label="Port Containment: Block External USB Storage" checked={settings.blockUsb} onChange={(e) => setSettings({ ...settings, blockUsb: e.target.checked })} />
            <Checkbox label="Force Kiosk Fullscreen Lockout" checked={settings.kioskFullscreen} onChange={(e) => setSettings({ ...settings, kioskFullscreen: e.target.checked })} />
            <Checkbox label="Allow Proctored Mobile Second-Camera Telemetry" checked={settings.secondCameraAllowed} onChange={(e) => setSettings({ ...settings, secondCameraAllowed: e.target.checked })} />
          </div>
        </Card>

        <Card title="Target Exam URL Allowed Origins" desc="Permitted assessment portal domains launched in kiosk">
          <Field label="Allowed Origins (Comma-separated HTTPS origins)">
            <Textarea rows={4} value={settings.allowedOrigins} onChange={(e) => setSettings({ ...settings, allowedOrigins: e.target.value })} />
          </Field>
          <p className="muted sm" style={{ marginTop: '8px' }}>
            The ExamOS kiosk strictly rejects iframe navigation outside these verified origin boundaries.
          </p>
        </Card>
      </div>
    </Page>
  );
}

/* =====================================================================
   PAGE 14 — Deployment Readiness (/institution/deployment)
===================================================================== */
export function InstitutionDeploymentReadinessPage() {
  const { tenant } = useTenant();
  const [liveDevices, setLiveDevices] = useState(null);
  const [liveCampuses, setLiveCampuses] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!tenant?.id) {
      setLiveDevices(null);
      setLiveCampuses(null);
      setLoadError('Select an institution to load deployment readiness.');
      setLoading(false);
      return;
    }

    let active = true;
    setLoading(true);
    setLoadError('');
    setLiveDevices(null);
    setLiveCampuses(null);
    Promise.allSettled([Api.listCampuses(tenant.id), Api.listRegisteredDevices()])
      .then(([campusResult, deviceResult]) => {
        if (!active) return;
        const errors = [];
        if (campusResult.status === 'fulfilled') {
          const rows = campusResult.value?.campuses || campusResult.value || [];
          if (Array.isArray(rows)) {
            setLiveCampuses(rows.filter(c => (c.tenantId || c.tenant_id || c.institution_id) === tenant.id));
          } else {
            errors.push('Campus response had an unexpected format.');
          }
        } else {
          errors.push(`Campuses: ${campusResult.reason?.message || 'request failed'}`);
        }
        if (deviceResult.status === 'fulfilled') {
          const rows = deviceResult.value?.devices || deviceResult.value || [];
          if (Array.isArray(rows)) {
            setLiveDevices(rows
              .filter(d => (d.tenantId || d.tenant_id || d.institution_id) === tenant.id)
              .map(d => ({
                ...d,
                centerId: d.centerId || d.center_id,
                trust: d.trust || d.trust_status,
                lastSeen: d.lastSeen || d.last_seen,
              })));
          } else {
            errors.push('Device response had an unexpected format.');
          }
        } else {
          errors.push(`Devices: ${deviceResult.reason?.message || 'request failed'}`);
        }
        setLoadError(errors.join('; '));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [tenant?.id]);

  const devices = liveDevices || [];
  const campuses = liveCampuses || [];
  const attested = devices.filter((d) => d.trust === 'attested' || d.trust_status === 'trusted' || d.tpm_enrolled);
  const readiness = loading ? 'LOADING' : liveDevices === null ? 'UNKNOWN' :
    (devices.length === 0 ? 'NOT ENROLLED' : (attested.length === devices.length ? 'READY' : 'PENDING'));

  return (
    <Page
      title="Deployment Readiness"
      desc="Registered testing workstations, TPM attestation status, and examination preflight diagnostics."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Deployment</span></div>}
    >
      {loadError && <Flash msg={{ tone: 'danger', text: loadError }} onClose={() => setLoadError('')} />}
      <StatGrid cols={4}>
        <Stat label="Total Workstations" value={liveDevices === null ? '—' : devices.length} icon="device" />
        <Stat label="Hardware Attested" value={liveDevices === null ? '—' : attested.length} tone={attested.length ? 'green' : 'amber'} icon="shield" sub="TPM Validated" />
        <Stat label={`${getOrgTerms(tenant?.entityType).campusLabel} Scoped`} value={liveCampuses === null ? '—' : campuses.length} icon="pin" />
        <Stat label="Readiness State" value={readiness} tone={readiness === 'READY' ? 'green' : 'amber'} icon="checklist" />
      </StatGrid>

      <Card title="Workstation Telemetry & Hardware Health" desc="Preflight verification across testing centers">
        <DataTable
          rows={devices}
          columns={[
            { key: 'hostname', label: 'Workstation', render: (d) => <><b>{d.hostname}</b><br /><small className="muted">{d.mac || '—'}</small></> },
            { key: 'seat', label: 'Seat / Room', render: (d) => d.seat || '—' },
            { key: 'trust', label: 'TPM Attestation', render: (d) => <Badge value={d.trust || '—'} tone={d.trust === 'attested' ? 'green' : 'amber'} /> },
            { key: 'status', label: 'Status', badge: true },
            { key: 'lastSeen', label: 'Last Heartbeat', render: (d) => d.lastSeen ? ago(d.lastSeen) : '—' },
          ]}
          empty={<Empty icon="device" title={loading ? 'Loading workstations…' : loadError ? 'Workstations unavailable' : 'No workstations enrolled yet'}>{loadError ? 'Resolve the backend request error before treating readiness as confirmed.' : 'Enroll testing devices via the approved device enrollment workflow.'}</Empty>}
        />
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 15 — Audit and Activity (/institution/audit)
===================================================================== */
export function InstitutionAuditPage() {
  const [auditRows, setAuditRows] = useState([]);
  const [ledger, setLedger] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [trail, led] = await Promise.all([
        Api.listAuditTrail({ limit: 500 }),
        Api.getLedger(),
      ]);
      const rows = Array.isArray(trail) ? trail : (trail?.events || trail?.audit || []);
      setAuditRows([...rows].sort((a, b) => String(b.recorded_at || b.ts || '').localeCompare(String(a.recorded_at || a.ts || ''))));
      setLedger(led || null);
      setLoadError('');
    } catch (e) {
      setLoadError(e.message || 'Unable to load the audit trail from the backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const chainOk = ledger?.ledger_integrity === 'INTACT';
  const chainKnown = ledger?.ledger_integrity === 'INTACT' || ledger?.ledger_integrity === 'TAMPERED';

  return (
    <Page
      title="Institutional Audit & Activity"
      desc="Backend audit trail of administrative actions, policy adjustments, and deployment events, backed by the tamper-evident ledger."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Audit</span></div>}
    >
      {loadError && <Flash msg={{ tone: 'danger', text: loadError }} onClose={() => setLoadError('')} />}
      <StatGrid cols={4}>
        <Stat
          label="Ledger Chain State"
          value={ledger?.ledger_integrity || '—'}
          tone={chainOk ? 'green' : (chainKnown ? 'red' : 'amber')}
          icon="shield"
          sub="SHA-256 Chained"
        />
        <Stat
          label="Verified Blocks"
          value={ledger?.total_blocks ?? '—'}
          tone="green"
          icon="checklist"
          sub="Cryptographically Proven"
        />
        <Stat
          label="Audit Events"
          value={auditRows.length}
          icon="audit"
          sub="Returned by backend"
        />
        <Stat
          label="Tamper Detection"
          value={chainKnown ? (chainOk ? 'NONE' : 'BROKEN') : '—'}
          tone={chainOk ? 'green' : (chainKnown ? 'red' : 'amber')}
          icon="check"
          sub="Continuous Validation"
        />
      </StatGrid>

      <Card title="Immutable Audit Chain" desc="Read directly from the backend audit store; the local browser cache is not used as evidence.">
        <DataTable
          rows={auditRows}
          search={['event_type', 'event', 'actor', 'subject_id', 'subject_type']}
          columns={[
            { key: 'event_type', label: 'Event Type', render: (l) => <code>{l.event_type || l.event}</code> },
            { key: 'actor', label: 'Actor', render: (l) => <b>{l.actor || 'system'}</b> },
            { key: 'subject', label: 'Subject', render: (l) => `${l.subject_type || '—'} · ${l.subject_id || '—'}` },
            { key: 'recorded_at', label: 'Timestamp', render: (l) => (l.recorded_at || l.ts) ? fmt(l.recorded_at || l.ts) : '—' },
          ]}
          empty={<Empty icon="checklist" title={loading ? 'Loading audit trail…' : 'No audit events logged yet'} desc="Mutating backend operations will appear here." />}
        />
      </Card>
    </Page>
  );
}
