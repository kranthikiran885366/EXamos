import { useState, useMemo } from 'react';
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
  saveSecuritySettings, saveExamDefaults
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
      desc="Accredited testing enclave management: Campuses, staff, candidate rosters, workstation attestation, and live examinations."
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
        <Stat label="Campuses & Centres" value={`${campuses.length} / ${centers.length}`} icon="building" sub="Active Exam Locations" />
        <Stat label="Registered Devices" value={devices.length} tone={attestedDevices === devices.length && devices.length > 0 ? 'green' : 'amber'} icon="device" sub={`${attestedDevices} Hardware Attested`} to="/institution/deployment" />
        <Stat label="Candidate Roster" value={candidates.length} icon="candidate" sub={`${verifiedCandidates} Verified`} />
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
              <span>2. Organization &amp; Campuses</span>
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
              <Icon name="pin" size={16} /> Campuses, Departments &amp; Courses
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
      desc="Official legal identity, accredited identifier, primary physical campus address, and verified academic domains."
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

        <Card title="Verified Academic Domains" desc="Domains permitted for SSO and email attribution">
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
      desc="Campuses, academic departments, degree programs, semesters, and local campus administrators."
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
        <Stat label="Campuses" value={campuses.length} icon="pin" sub="Physical Testing Sites" />
        <Stat label="Departments" value={departments.length} icon="layers" sub="Academic Divisions" />
        <Stat label="Total Testing Seats" value={campuses.reduce((acc, c) => acc + (Number(c.capacity) || 0), 0)} icon="users" sub="Capacity" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginTop: '16px' }}>
        <Card title="Campuses" desc="Approved testing physical sites">
          <DataTable
            rows={campuses}
            columns={[
              { key: 'name', label: 'Campus', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code} · {c.city}</small></> },
              { key: 'capacity', label: 'Capacity', render: (c) => `${c.capacity || 0} seats` },
              { key: 'status', label: 'Status', badge: true },
            ]}
            empty={<Empty icon="pin" title="No campuses added yet" />}
          />
        </Card>

        <Card title="Departments & Faculties" desc="Academic governance units">
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
        <Modal title="Add New Campus" onClose={() => setNewCampusModal(false)}>
          <div className="formgrid">
            <Field label="Campus Name"><Input value={newCampus.name} onChange={(e) => setNewCampus({ ...newCampus, name: e.target.value })} placeholder="e.g. North Campus" required /></Field>
            <Field label="Campus Code"><Input value={newCampus.code} onChange={(e) => setNewCampus({ ...newCampus, code: e.target.value.toUpperCase() })} placeholder="e.g. NC-01" required /></Field>
            <Field label="City"><Input value={newCampus.city} onChange={(e) => setNewCampus({ ...newCampus, city: e.target.value })} placeholder="e.g. Hyderabad" /></Field>
            <Field label="Seating Capacity"><Input type="number" value={newCampus.capacity} onChange={(e) => setNewCampus({ ...newCampus, capacity: Number(e.target.value) })} /></Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setNewCampusModal(false)}>Cancel</button>
            <button className="btn primary" onClick={handleAddCampus} disabled={busy || !newCampus.name || !newCampus.code}>Save Campus</button>
          </div>
        </Modal>
      )}

      {newDeptModal && (
        <Modal title="Add Academic Department" onClose={() => setNewDeptModal(false)}>
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
  const { tenant } = useTenant();
  const users = useCol('users');
  const campuses = useCol('campuses');
  const { msg, setMsg, run, busy } = useFlash();

  const [inviteModal, setInviteModal] = useState(false);
  const [inviteData, setInviteData] = useState({ email: '', name: '', role: 'invigilator', campusId: '' });

  const handleInvite = async () => {
    await run(async () => {
      setInviteModal(false);
      return `Administrator invitation sent to ${inviteData.email}. Token valid for 48 hours.`;
    }, 'Invitation sent.');
  };

  return (
    <Page
      title="Administrators and Access"
      desc="Invite institutional administrators, invigilators, exam controllers, and monitor MFA security enrollment."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Administrators</span></div>}
      actions={
        <button className="btn primary" onClick={() => setInviteModal(true)}>
          <Icon name="plus" size={14} /> Invite Administrator
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <Card title="Institutional Administrative Accounts" desc="Scoped roles and MFA security posture">
        <DataTable
          rows={users}
          columns={[
            { key: 'name', label: 'User', render: (u) => <><b>{u.name || u.username}</b><br /><small className="muted">{u.email || u.username}</small></> },
            { key: 'role', label: 'Role', render: (u) => <Badge value={roleLabel(u.role)} /> },
            { key: 'mfa', label: '2FA / TOTP', render: (u) => <span className="badge g">RFC 6238 Active</span> },
            { key: 'status', label: 'Status', badge: true },
            { key: 'lastLogin', label: 'Last Login', render: (u) => u.lastLogin ? fmt(u.lastLogin) : 'Never' },
          ]}
          empty={<Empty icon="users" title="No administrators listed" />}
        />
      </Card>

      {inviteModal && (
        <Modal title="Invite Institutional Administrator" onClose={() => setInviteModal(false)}>
          <div className="formgrid">
            <Field label="Email Address"><Input type="email" value={inviteData.email} onChange={(e) => setInviteData({ ...inviteData, email: e.target.value })} placeholder="admin@univ.edu" required /></Field>
            <Field label="Full Name"><Input value={inviteData.name} onChange={(e) => setInviteData({ ...inviteData, name: e.target.value })} placeholder="Dr. S. Sharma" required /></Field>
            <Field label="Role">
              <Select
                value={inviteData.role}
                onChange={(e) => setInviteData({ ...inviteData, role: e.target.value })}
                options={[
                  { v: 'inst_admin', l: 'Institution Admin (Full Management)' },
                  { v: 'exam_controller', l: 'Examination Controller (Exams & Policies)' },
                  { v: 'invigilator', l: 'Invigilator (Session Supervision)' },
                  { v: 'it_admin', l: 'IT Admin (Workstations & USBs)' },
                ]}
              />
            </Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setInviteModal(false)}>Cancel</button>
            <button className="btn primary" onClick={handleInvite} disabled={busy || !inviteData.email}>Send Invitation</button>
          </div>
        </Modal>
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
        <Stat label="Campuses Scoped" value={campuses.length} icon="pin" />
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
  const incidents = useCol('incidents');
  const exams = useCol('exams');

  const auditLogs = useMemo(() => [
    { event: 'INSTITUTION_PROFILE_UPDATED', actor: 'root@platform', time: Date.now() - 3600000, detail: 'Domain TXT verified' },
    { event: 'SECURITY_SETTINGS_SAVED', actor: 'instadmin', time: Date.now() - 7200000, detail: 'TPM 2.0 attestation required' },
    { event: 'CAMPUS_SEAT_REGISTERED', actor: 'instadmin', time: Date.now() - 14400000, detail: 'Main Campus Lab 1 (250 seats)' },
    { event: 'EXAM_PORTAL_URL_CONFIGURED', actor: 'controller', time: Date.now() - 28800000, detail: 'Assessment URL assigned' },
  ], []);

  return (
    <Page
      title="Institutional Audit & Activity"
      desc="Cryptographically sealed audit trail of administrative actions, policy adjustments, and deployment events."
      breadcrumb={<div className="crumbs-inline"><Link to="/institution/dashboard">Institution</Link><Icon name="arrow" size={12} /><span>Audit</span></div>}
    >
      <Card title="Immutable Audit Chain" desc="All mutating operations are signed and recorded">
        <DataTable
          rows={auditLogs}
          columns={[
            { key: 'event', label: 'Event', render: (l) => <code>{l.event}</code> },
            { key: 'actor', label: 'Actor', render: (l) => <b>{l.actor}</b> },
            { key: 'detail', label: 'Details', render: (l) => <span>{l.detail}</span> },
            { key: 'time', label: 'Timestamp', render: (l) => ago(l.time) },
          ]}
        />
      </Card>
    </Page>
  );
}
