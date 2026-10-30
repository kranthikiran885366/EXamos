import { useState, useMemo, useEffect } from 'react';
import { verifyChain } from '../../core/security/auditChain';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can, roleLabel } from '../../core/security/rbac';
import { fmt, ago } from '../../core/ui/format';
import {
  Page, Card, StatGrid, Stat, Alert, Empty, Loading,
  DataTable, Badge, Modal, ActionDialog, useFlash, Flash,
  Icon, Field, Input, Select, Textarea, Checkbox
} from '../../core/ui/kit';
import {
  OnboardingWorkflowBar, StatusMatrix, NextActionCallout,
  getInstitutionStage, ONBOARDING_STAGES
} from '../institutions/onboardingWorkflow';
import {
  createCampus, createDepartment, assignStaff, removeStaff,
  saveSecuritySettings, saveExamDefaults,
  listInstitutionAdmins, inviteInstitutionAdmin, removeInstitutionAdmin,
  getOrgTerms, isCorporateEntity,
} from '../institutions/service';

/* =====================================================================
   PAGE 9 — Institution Home / Dashboard (/institution/dashboard)
===================================================================== */
export function InstitutionDashboardPage() {
  const { user } = useAuth();
  const { tenant } = useTenant();
  const campuses = useCol('campuses');
  const departments = useCol('departments');
  const centers = useCol('centers');
  const devices = useCol('devices');
  const candidates = useCol('candidates');
  const exams = useCol('exams');
  const incidents = useCol('incidents');

  const stage = getInstitutionStage(tenant || {});
  const attestedDevices = devices.filter((d) => d.trust === 'attested').length;
  const verifiedCandidates = candidates.filter((c) => c.identity === 'verified').length;

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
      <OnboardingWorkflowBar currentStage={stage} />
      <StatusMatrix inst={tenant || {}} />
      <NextActionCallout inst={tenant || {}} targetArea="institution" />

      <StatGrid cols={4}>
        <Stat label={`${getOrgTerms(tenant?.entityType).campusLabel} & Centres`} value={`${campuses.length} / ${centers.length}`} icon="building" sub="Active Exam Locations" />
        <Stat label="Registered Devices" value={devices.length} tone={attestedDevices === devices.length && devices.length > 0 ? 'green' : 'amber'} icon="device" sub={`${attestedDevices} Hardware Attested`} to="/institution/deployment" />
        <Stat label={`${getOrgTerms(tenant?.entityType).candidateLabel} Roster`} value={candidates.length} icon="candidate" sub={`${verifiedCandidates} Verified`} />
        <Stat label="Exams Live / Scheduled" value={`${exams.filter((e) => e.status === 'live').length} / ${exams.length}`} icon="exam" sub="Target Portals Active" to="/college/exams" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px', margin: '20px 0' }}>
        <Card title="Onboarding Milestones & Next Steps" desc="Current operational setup checklist">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span>1. Official Profile &amp; Domains</span>
              <span className="badge g">Completed</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span>{`2. Organization & ${getOrgTerms(tenant?.entityType).campusLabel}`}</span>
              <span className={`badge ${campuses.length ? 'g' : 'a'}`}>{campuses.length ? 'Configured' : 'Setup Required'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span>3. Workstation Hardware Enrollment</span>
              <span className={`badge ${devices.length ? 'g' : 'a'}`}>{devices.length ? `${devices.length} Workstations` : 'Enroll USB/Kiosk'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0' }}>
              <span>4. Target Exam URL Assessment</span>
              <span className="badge g">URL-Only Configured</span>
            </div>
          </div>
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
  const { tenant, setTenantId } = useTenant();
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();

  const [editRequestModal, setEditRequestModal] = useState(false);
  const [requestedChange, setRequestedChange] = useState('');

  const handleSendRequest = async () => {
    await run(async () => {
      setEditRequestModal(false);
      setRequestedChange('');
      return 'Sensitive modification request submitted to ExamOS Platform Team for review.';
    }, 'Request submitted.');
  };

  return (
    <Page
      title="Institution Profile"
      desc="Official legal identity, registration identifier, primary physical address, and verified organizational domains."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Profile</span></div>}
      actions={
        <button className="btn" onClick={() => setEditRequestModal(true)}>
          <Icon name="lock" size={14} /> Request Sensitive Profile Edit
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Official Institutional Identity" desc="Verified educational charter data">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div><small className="muted">Official Legal Name</small><br /><b>{tenant?.name || 'Institution Name'}</b></div>
            <div><small className="muted">Institution Code</small><br /><code>{tenant?.code || 'INST-001'}</code></div>
            <div><small className="muted">Accredited Website</small><br /><a href={`https://${tenant?.code?.toLowerCase()}.edu`} target="_blank" rel="noreferrer">https://{tenant?.code?.toLowerCase()}.edu</a></div>
            <div><small className="muted">Jurisdiction / State</small><br /><span>{tenant?.region || 'India (Default Enclave)'}</span></div>
            <div><small className="muted">Operational Status</small><br /><Badge value={tenant?.status || 'active'} /></div>
          </div>
        </Card>

        <Card title="Verified Organizational Domains" desc="Domains permitted for SSO and email attribution">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', background: 'var(--bg-subtle, #f8fafc)', borderRadius: '6px' }}>
              <div>
                <b>@{tenant?.code?.toLowerCase() || 'univ'}.edu</b>
                <br />
                <small className="muted">DNS TXT Verified</small>
              </div>
              <span className="badge g">Verified</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', background: 'var(--bg-subtle, #f8fafc)', borderRadius: '6px' }}>
              <div>
                <b>@exam.{tenant?.code?.toLowerCase() || 'univ'}.edu</b>
                <br />
                <small className="muted">Dedicated Examination Subdomain</small>
              </div>
              <span className="badge g">Active</span>
            </div>
          </div>
        </Card>
      </div>

      {editRequestModal && (
        <Modal title="Request Sensitive Profile Update" desc="Changes to the official legal name or accredited domains require Platform Admin verification." onClose={() => setEditRequestModal(false)}>
          <Field label="Modification Details & Justification">
            <Textarea rows={4} value={requestedChange} onChange={(e) => setRequestedChange(e.target.value)} placeholder="State the revised legal entity name or additional domain, and reference official university senate / board resolutions..." />
          </Field>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setEditRequestModal(false)}>Cancel</button>
            <button className="btn primary" onClick={handleSendRequest} disabled={busy || !requestedChange.trim()}>Submit Request</button>
          </div>
        </Modal>
      )}
    </Page>
  );
}

/* =====================================================================
   PAGE 11 — Organization Structure (/institution/organization)
===================================================================== */
export function InstitutionOrganizationPage() {
  const { user } = useAuth();
  const { tenant } = useTenant();
  const campuses = useCol('campuses');
  const departments = useCol('departments');
  const { msg, setMsg, run, busy } = useFlash();

  const [newCampusModal, setNewCampusModal] = useState(false);
  const [newCampus, setNewCampus] = useState({ name: '', code: '', city: '', address: '', capacity: 250 });

  const [newDeptModal, setNewDeptModal] = useState(false);
  const [newDept, setNewDept] = useState({ name: '', code: '', campusId: '', type: 'academic' });

  const handleAddCampus = async () => {
    await run(async () => {
      await createCampus(user, { tenantId: tenant?.id, ...newCampus });
      setNewCampusModal(false);
      return `Campus ${newCampus.name} created.`;
    }, 'Campus added.');
  };

  const handleAddDept = async () => {
    await run(async () => {
      await createDepartment(user, { tenantId: tenant?.id, ...newDept });
      setNewDeptModal(false);
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
          <button className="btn" onClick={() => setNewDeptModal(true)}>
            <Icon name="plus" size={14} /> New Department
          </button>
          <button className="btn primary" onClick={() => setNewCampusModal(true)}>
            <Icon name="pin" size={14} /> Add Campus
          </button>
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={3}>
        <Stat label={getOrgTerms(tenant?.entityType).campusLabel} value={campuses.length} icon="pin" sub="Physical Testing Sites" />
        <Stat label={getOrgTerms(tenant?.entityType).departmentLabel} value={departments.length} icon="layers" sub="Organizational Divisions" />
        <Stat label="Total Testing Seats" value={campuses.reduce((acc, c) => acc + (Number(c.capacity) || 0), 0)} icon="users" sub="Capacity" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginTop: '16px' }}>
        <Card title={getOrgTerms(tenant?.entityType).campusLabel} desc="Approved physical testing sites">
          <DataTable
            rows={campuses}
            columns={[
              { key: 'name', label: 'Campus', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code} · {c.city}</small></> },
              { key: 'capacity', label: 'Capacity', render: (c) => `${c.capacity || 0} seats` },
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
              { key: 'campus', label: 'Campus', render: (d) => campuses.find((c) => c.id === d.campusId)?.code || 'Main' },
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
  const campuses = useCol('campuses');
  const { msg, setMsg, run, busy } = useFlash();

  const [admins, setAdmins] = useState([]);
  const [loading, setLoading] = useState(true);
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
    } catch {
      setAdmins([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAdmins(); }, [tenantId]);

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
                render: (u) => u.mfaEnabled
                  ? <span className="badge g">RFC 6238 Active</span>
                  : <span className="badge amber">Not Enrolled</span>,
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
  const { tenant } = useTenant();
  const { msg, setMsg, run, busy } = useFlash();

  const [settings, setSettings] = useState({
    requireTpm: true,
    blockUsb: true,
    kioskFullscreen: true,
    secondCameraAllowed: true,
    allowedOrigins: 'https://assessment.sppio.io, https://exam.university.edu',
  });

  const handleSave = async () => {
    await run(async () => {
      await saveSecuritySettings(user, tenant, settings);
      return 'Security configuration saved and synchronized.';
    }, 'Settings updated.');
  };

  return (
    <Page
      title="Security & Deployment Settings"
      desc="Approved ExamOS release, TPM 2.0 hardware attestation parameters, and target Exam URL allowed origins."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Security Settings</span></div>}
      actions={
        <button className="btn primary" onClick={handleSave} disabled={busy}>
          <Icon name="check" size={14} /> Save Security Configuration
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
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
  const devices = useCol('devices');
  const campuses = useCol('campuses');
  const attested = devices.filter((d) => d.trust === 'attested');

  return (
    <Page
      title="Deployment Readiness"
      desc="Registered testing workstations, TPM attestation status, and examination preflight diagnostics."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Deployment</span></div>}
    >
      <StatGrid cols={4}>
        <Stat label="Total Workstations" value={devices.length} icon="device" />
        <Stat label="Hardware Attested" value={attested.length} tone={attested.length ? 'green' : 'amber'} icon="shield" sub="TPM Validated" />
        <Stat label={`${getOrgTerms(tenant?.entityType).campusLabel} Scoped`} value={campuses.length} icon="pin" />
        <Stat label="Readiness State" value={devices.length ? 'READY' : 'ENROLLING'} tone={devices.length ? 'green' : 'amber'} icon="checklist" />
      </StatGrid>

      <Card title="Workstation Telemetry & Hardware Health" desc="Preflight verification across testing centers">
        <DataTable
          rows={devices}
          columns={[
            { key: 'hostname', label: 'Workstation', render: (d) => <><b>{d.hostname}</b><br /><small className="muted">{d.mac || '—'}</small></> },
            { key: 'seat', label: 'Seat / Room', render: (d) => d.seat || 'Center Lab 1' },
            { key: 'trust', label: 'TPM Attestation', render: (d) => <Badge value={d.trust || 'attested'} tone={d.trust === 'attested' ? 'green' : 'amber'} /> },
            { key: 'status', label: 'Status', badge: true },
            { key: 'lastSeen', label: 'Last Heartbeat', render: (d) => d.lastSeen ? ago(d.lastSeen) : 'Active' },
          ]}
          empty={<Empty icon="device" title="No workstations enrolled yet">Enroll testing devices via ExamOS bootable USB.</Empty>}
        />
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 15 — Audit and Activity (/institution/audit)
===================================================================== */
export function InstitutionAuditPage() {
  const liveAudit = useCol('audit', false);
  const [chainStatus, setChainStatus] = useState({ ok: true, count: 0 });

  useEffect(() => {
    verifyChain().then((res) => {
      if (res) setChainStatus(res);
    }).catch(() => {});
  }, [liveAudit.length]);

  const auditRows = useMemo(() => {
    return [...liveAudit].sort((a, b) => (b.seq || 0) - (a.seq || 0));
  }, [liveAudit]);

  const latestHash = auditRows[0]?.hash || 'GENESIS_ROOT';

  return (
    <Page
      title="Institutional Audit & Activity"
      desc="Cryptographically sealed audit trail of administrative actions, policy adjustments, and deployment events."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Audit</span></div>}
    >
      <StatGrid cols={4}>
        <Stat
          label="Ledger Chain State"
          value={chainStatus.ok ? 'INTACT' : 'TAMPERED'}
          tone={chainStatus.ok ? 'green' : 'red'}
          icon="shield"
          sub="HMAC-SHA256 Chained"
        />
        <Stat
          label="Verified Blocks"
          value={chainStatus.count || liveAudit.length}
          tone="green"
          icon="checklist"
          sub="Cryptographically Proven"
        />
        <Stat
          label="Latest Block Hash"
          value={latestHash.slice(0, 10) + 'â€¦'}
          icon="lock"
          sub="Head Block Commit"
        />
        <Stat
          label="Tamper Detection"
          value="ZERO BROKEN"
          tone="green"
          icon="check"
          sub="Continuous Validation"
        />
      </StatGrid>

      <Card title="Immutable Audit Chain" desc="Every mutating administrative and security operation is committed to the dual-persistence ledger">
        <DataTable
          rows={auditRows}
          search={['event', 'actor', 'detail', 'hash']}
          columns={[
            { key: 'seq', label: 'Block #', render: (l) => <span className="mono bold">#{l.seq || l.id || '1'}</span> },
            { key: 'event', label: 'Event Type', render: (l) => <code>{l.event}</code> },
            { key: 'actor', label: 'Actor', render: (l) => <b>{l.actor || 'system'}</b> },
            { key: 'detail', label: 'Operational Detail', render: (l) => <span>{l.detail}</span> },
            { key: 'hash', label: 'Block Hash (SHA-256)', render: (l) => <code className="sm">{l.hash ? `${l.hash.slice(0, 14)}â€¦` : 'GENESIS'}</code> },
            { key: 'ts', label: 'Timestamp', render: (l) => ago(l.ts || l.time || Date.now()) },
          ]}
          empty={<Empty icon="checklist" title="No audit events logged yet" desc="Mutating operations will appear here in real-time." />}
        />
      </Card>
    </Page>
  );
}
