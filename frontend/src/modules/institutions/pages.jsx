import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { Page, Card, Stat, StatGrid, Badge, DataTable, Modal, Field, Input, Select, Textarea, Checkbox, ActionDialog, Flash, useFlash, KeyValue, Tabs, Empty, Icon, CopyField } from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { createInstitution, updateInstitution, setInstitutionStatus, createCampus, updateCampus, setCampusStatus, createDepartment, setDepartmentStatus, assignStaff, removeStaff, saveExamDefaults, institutionStats, DEPLOYMENT_MODELS, TIMEZONES, DEPT_TYPES } from './service';
import { createCenter, updateCenter, setCenterStatus } from '../centers/service';

const PLAN_OPTIONS = [{ v: 'pilot', l: 'Pilot' }, { v: 'standard', l: 'Standard' }, { v: 'enterprise', l: 'Enterprise' }];
const tenantOptions = (list) => list.map((t) => ({ v: t.id, l: t.name }));

function InstitutionForm({ value = {}, onSubmit, onClose, busy }) {
  const [f, setF] = useState({ name: '', code: '', contactEmail: '', contactPhone: '', region: 'India · Mumbai', timezone: 'Asia/Kolkata', plan: 'pilot', maxCenters: 5, maxCandidates: 500, deploymentModel: 'usb-boot', ...value, domains: Array.isArray(value.domains) ? value.domains.join(' ') : value.domains || '' });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  return <form id="inst-form" onSubmit={(e) => { e.preventDefault(); onSubmit(f); }} className="formgrid">
    <Field label="Institution name" required><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
    <Field label="Code" help="Leave blank to generate"><Input value={f.code} onChange={set('code')} maxLength={20} /></Field>
    <Field label="Email domains" help="Space or comma separated"><Input value={f.domains} onChange={set('domains')} maxLength={300} /></Field>
    <Field label="Contact email"><Input type="email" value={f.contactEmail} onChange={set('contactEmail')} maxLength={120} /></Field>
    <Field label="Contact phone"><Input value={f.contactPhone} onChange={set('contactPhone')} maxLength={30} /></Field>
    <Field label="Region"><Input value={f.region} onChange={set('region')} maxLength={40} /></Field>
    <Field label="Timezone"><Select value={f.timezone} onChange={set('timezone')} options={TIMEZONES} placeholder={false} /></Field>
    <Field label="Plan"><Select value={f.plan} onChange={set('plan')} options={PLAN_OPTIONS} placeholder={false} /></Field>
    <Field label="Max centres"><Input type="number" min="1" max="200" value={f.maxCenters} onChange={set('maxCenters')} /></Field>
    <Field label="Max candidates"><Input type="number" min="10" max="100000" value={f.maxCandidates} onChange={set('maxCandidates')} /></Field>
    <Field label="Deployment model" className="span2"><Select value={f.deploymentModel} onChange={set('deploymentModel')} options={DEPLOYMENT_MODELS} placeholder={false} /></Field>
    <div className="form-actions span2"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>Save institution</button></div>
  </form>;
}

export function InstitutionsPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const tenants = useCol('tenants', false);
  const users = useCol('users', false);
  const exams = useCol('exams', false);
  const devices = useCol('devices', false);
  const { msg, run, busy, setMsg } = useFlash();
  const [create, setCreate] = useState(false);
  const [action, setAction] = useState(null);
  const canCreate = can(user.role, 'tenant.manage');
  return <Page title="Institutions" desc="Platform-wide tenants, their plans and operating status."
    actions={canCreate ? <button className="btn primary" onClick={() => setCreate(true)}><Icon name="plus" size={15} /> New institution</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={4}>
      <Stat label="Institutions" value={tenants.length} icon="building" />
      <Stat label="Active" value={tenants.filter((t) => t.status === 'active').length} tone="green" icon="check" />
      <Stat label="Suspended" value={tenants.filter((t) => t.status === 'suspended').length} tone="amber" icon="warn" />
      <Stat label="Accounts" value={users.length} tone="violet" icon="users" />
    </StatGrid>
    <DataTable rows={tenants} search={['name', 'code', 'region']} title="Institutions" desc="Select an institution to inspect campuses, centres and settings."
      filters={[{ key: 'status', label: 'Status', options: ['active', 'suspended', 'archived'] }, { key: 'plan', label: 'Plan', options: PLAN_OPTIONS }]}
      columns={[
        { key: 'name', label: 'Institution', sortable: true, render: (t) => <><Link to={`/admin/institutions/${t.id}`}><b>{t.name}</b></Link><br /><small className="muted">{t.code} · {t.region || '—'}</small></> },
        { key: 'plan', label: 'Plan', render: (t) => <Badge value={t.plan} /> },
        { key: 'status', label: 'Status', badge: true },
        { key: 'users', label: 'Accounts', render: (t) => users.filter((u) => u.tenantId === t.id).length },
        { key: 'exams', label: 'Exams', render: (t) => exams.filter((e) => e.tenantId === t.id).length },
        { key: 'devices', label: 'Devices', render: (t) => devices.filter((d) => d.tenantId === t.id).length },
        { key: 'createdAt', label: 'Created', render: (t) => fmt(t.createdAt) },
      ]}
      actions={(t) => [
        { label: 'Open', onClick: () => nav(`/admin/institutions/${t.id}`) },
        ...(canCreate ? [{ label: t.status === 'active' ? 'Suspend' : 'Activate', danger: t.status === 'active', onClick: () => setAction({ t, status: t.status === 'active' ? 'suspended' : 'active' }) }] : []),
      ]}
      onRow={(t) => nav(`/admin/institutions/${t.id}`)} />
    {create && <Modal title="Register institution" desc="Creates a tenant, default policy space and billing profile." onClose={() => setCreate(false)}>
      <InstitutionForm busy={busy} onClose={() => setCreate(false)} onSubmit={(f) => run(async () => { await createInstitution(user, f); setCreate(false); return 'Institution registered.'; }, 'Institution registered.')} />
    </Modal>}
    {action && <ActionDialog title={`${action.status === 'suspended' ? 'Suspend' : 'Activate'} ${action.t.name}`} desc="Suspension blocks publishing and starting exams. It is recorded in the audit trail." danger={action.status === 'suspended'} confirmLabel={action.status === 'suspended' ? 'Suspend institution' : 'Activate institution'} onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await setInstitutionStatus(user, action.t, action.status, reason); setAction(null); })} />}
  </Page>;
}

export function InstitutionDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const tenants = useCol('tenants', false);
  const campuses = useCol('campuses', false);
  const departments = useCol('departments', false);
  const centers = useCol('centers', false);
  const users = useCol('users', false);
  const exams = useCol('exams', false);
  const devices = useCol('devices', false);
  const candidates = useCol('candidates', false);
  const incidents = useCol('incidents', false);
  const { msg, run, busy, setMsg } = useFlash();
  const [tab, setTab] = useState('overview');
  const [edit, setEdit] = useState(false);
  const t = tenants.find((x) => x.id === id);
  const stats = useMemo(() => ({ campuses: campuses.filter((c) => c.tenantId === id).length, departments: departments.filter((d) => d.tenantId === id).length, centers: centers.filter((c) => c.tenantId === id).length, users: users.filter((u) => u.tenantId === id).length, devices: devices.filter((d) => d.tenantId === id).length, exams: exams.filter((e) => e.tenantId === id).length, candidates: candidates.filter((c) => c.tenantId === id).length, incidents: incidents.filter((i) => i.tenantId === id && ['open', 'investigating', 'contained'].includes(i.status)).length }), [id, campuses, departments, centers, users, devices, exams, candidates, incidents]);
  if (!t) return <Page title="Institution not found"><Empty icon="building" title="No such institution" action={<Link className="btn" to="/admin/institutions">Back to institutions</Link>} /></Page>;
  return <Page title={t.name} desc={`${t.code} · ${t.region || '—'} · ${t.timezone || '—'}`} breadcrumb={<div className="crumbs-inline"><Link to="/admin/institutions">Institutions</Link><Icon name="arrow" size={12} /><span>{t.code}</span></div>}
    actions={<>{can(user.role, 'inst.manage') && <button className="btn" onClick={() => setEdit(true)}>Edit settings</button>}<Badge value={t.status} /></>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={4}>
      <Stat label="Campuses" value={stats.campuses} icon="pin" /><Stat label="Exam centres" value={stats.centers} icon="building" />
      <Stat label="Accounts" value={stats.users} icon="users" /><Stat label="Devices" value={stats.devices} icon="device" />
      <Stat label="Exams" value={stats.exams} icon="exam" /><Stat label="Candidates" value={stats.candidates} icon="candidate" />
      <Stat label="Open incidents" value={stats.incidents} tone={stats.incidents ? 'amber' : 'green'} icon="alert" /><Stat label="Plan" value={t.plan} icon="card" />
    </StatGrid>
    <Tabs tabs={[{ key: 'overview', label: 'Overview' }, { key: 'campuses', label: 'Campuses', count: stats.campuses }, { key: 'centres', label: 'Centres', count: stats.centers }, { key: 'settings', label: 'Settings' }]} value={tab} onChange={setTab} />
    {tab === 'overview' && <div className="two">
      <Card title="Institution profile"><KeyValue items={[['Legal name', t.name], ['Code', t.code], ['Domains', (t.domains || []).join(', ') || '—'], ['Contact', t.contactEmail || '—'], ['Phone', t.contactPhone || '—'], ['Region', t.region], ['Timezone', t.timezone], ['Deployment', t.deploymentModel], ['Created', fmt(t.createdAt)], ['Plan', t.plan]]} /></Card>
      <Card title="Limits & security"><KeyValue items={[['Max centres', t.maxCenters], ['Max candidates', t.maxCandidates], ['Require TPM', t.security?.requireTpm ? 'Yes' : 'No'], ['Require Secure Boot', t.security?.requireSecureBoot ? 'Yes' : 'No'], ['USB storage', t.security?.allowUsbStorage ? 'Allowed' : 'Blocked'], ['Exam duration default', `${t.examDefaults?.durationMin || 60} min`], ['Late entry', `${t.examDefaults?.lateEntryMin || 0} min`], ['Attestation', t.examDefaults?.attestationLevel || 'tpm']]} /></Card>
      <Card title="Recent history" className="span2"><ul className="activity">{(t.history || []).slice().reverse().map((h, i) => <li key={i}><span className="act-dot" /><div><b>{h.action}</b><small className="muted">{h.by || 'system'} · {ago(h.at)} {h.reason ? '· ' + h.reason : ''}</small></div></li>)}</ul></Card>
    </div>}
    {tab === 'campuses' && <DataTable rows={campuses.filter((c) => c.tenantId === id)} search={['name', 'code', 'city']} columns={[{ key: 'name', label: 'Campus', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code}</small></> }, { key: 'city', label: 'City' }, { key: 'capacity', label: 'Capacity' }, { key: 'centers', label: 'Centres', render: (c) => centers.filter((x) => x.campusId === c.id).length }, { key: 'status', label: 'Status', badge: true }]} actions={(c) => [{ label: 'Open campuses', onClick: () => nav('/college/campuses') }]} />}
    {tab === 'centres' && <DataTable rows={centers.filter((c) => c.tenantId === id)} search={['name', 'code', 'city']} columns={[{ key: 'code', label: 'Code' }, { key: 'name', label: 'Centre' }, { key: 'city', label: 'City' }, { key: 'capacity', label: 'Seats' }, { key: 'devices', label: 'Devices', render: (c) => devices.filter((d) => d.centerId === c.id).length }, { key: 'status', label: 'Status', badge: true }]} />}
    {tab === 'settings' && <Card title="Operating settings" desc="These defaults are applied to new exams."><KeyValue items={[['Deployment', t.deploymentModel], ['Exam duration', `${t.examDefaults?.durationMin || 60} minutes`], ['Late entry', `${t.examDefaults?.lateEntryMin || 0} minutes`], ['Attestation', t.examDefaults?.attestationLevel], ['Notification email', t.notificationPrefs?.email ? 'On' : 'Off'], ['In-app notifications', t.notificationPrefs?.inApp ? 'On' : 'Off']]} /></Card>}
    {edit && <Modal title="Edit institution" wide onClose={() => setEdit(false)}><InstitutionForm value={t} busy={busy} onClose={() => setEdit(false)} onSubmit={(f) => run(async () => { await updateInstitution(user, t, f); setEdit(false); })} /></Modal>}
  </Page>;
}

export function CollegeOverviewPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
  const exams = useCol('exams');
  const centers = useCol('centers');
  const campuses = useCol('campuses');
  const departments = useCol('departments');
  const devices = useCol('devices');
  const candidates = useCol('candidates');
  const usbs = useCol('usbs');
  const incidents = useCol('incidents');
  const users = useCol('users', false);
  const live = exams.filter((e) => e.status === 'live');
  return <Page title={tenant?.name || 'Institution overview'} desc="Your institution at a glance, with the controls that matter before an exam window." actions={<><Link className="btn" to="/college/settings">Settings</Link>{can(user.role, 'exam.manage') && <Link className="btn primary" to="/college/exams/new">New exam</Link>}</>}>
    <StatGrid cols={4}>
      <Stat label="Live exams" value={live.length} icon="exam" to="/college/exams" />
      <Stat label="Centres" value={centers.length} icon="building" to="/college/campuses" />
      <Stat label="Devices" value={devices.length} icon="device" to="/devices" sub={`${devices.filter((d) => d.trust === 'attested').length} attested`} />
      <Stat label="Candidates" value={candidates.length} icon="candidate" to="/college/candidates" />
      <Stat label="Campuses" value={campuses.length} icon="pin" to="/college/campuses" />
      <Stat label="Departments" value={departments.length} icon="layers" to="/college/departments" />
      <Stat label="USBs" value={usbs.length} icon="usb" to="/usb-inventory" sub={`${usbs.filter((u) => u.status === 'issued').length} issued`} />
      <Stat label="Open incidents" value={incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status)).length} icon="alert" tone="amber" to="/operator/incidents" />
    </StatGrid>
    <div className="two">
      <Card title="Exam readiness" desc="Live and published windows">
        <DataTable rows={exams.filter((e) => ['live', 'published', 'approved'].includes(e.status))} dense pageSize={5} columns={[{ key: 'code', label: 'Exam', render: (e) => <Link to={`/college/exams/${e.id}`}><b>{e.code}</b></Link> }, { key: 'status', label: 'Status', badge: true }, { key: 'startAt', label: 'Window', render: (e) => fmt(e.startAt) }, { key: 'assigned', label: 'Assigned', render: (e) => candidates.filter((c) => c.examId === e.id).length }]} />
      </Card>
      <Card title="Staff & access" desc="Accounts linked to this institution">
        <KeyValue items={[['Active accounts', users.filter((u) => u.tenantId === tenantId && u.status === 'active').length], ['Students', users.filter((u) => u.tenantId === tenantId && u.role === 'student').length], ['Exam controllers', users.filter((u) => u.tenantId === tenantId && u.role === 'exam_controller').length], ['Invigilators', users.filter((u) => u.tenantId === tenantId && u.role === 'invigilator').length], ['IT admins', users.filter((u) => u.tenantId === tenantId && u.role === 'it_admin').length], ['Support engineers', users.filter((u) => u.tenantId === tenantId && u.role === 'support').length]]} />
        <div className="quicklinks compact">{can(user.role, 'user.manage') && <Link to="/admin/users"><Icon name="users" size={16} /><span>Users</span></Link>}<Link to="/college/staff"><Icon name="badge" size={16} /><span>Staff</span></Link><Link to="/college/subscription"><Icon name="card" size={16} /><span>Subscription</span></Link></div>
      </Card>
    </div>
  </Page>;
}

export function CampusesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const campuses = useCol('campuses');
  const centers = useCol('centers');
  const devices = useCol('devices');
  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(null);
  const [action, setAction] = useState(null);
  const [f, setF] = useState({ name: '', code: '', city: '', address: '', capacity: 100 });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const canManage = can(user.role, 'campus.manage');
  return <Page title="Campuses" desc="Physical locations that group exam centres, departments and staff."
    actions={canManage ? <button className="btn primary" onClick={() => { setF({ name: '', code: '', city: '', address: '', capacity: 100 }); setModal({ mode: 'create' }); }}><Icon name="plus" size={15} /> New campus</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={3}>
      <Stat label="Campuses" value={campuses.length} icon="pin" /><Stat label="Centres" value={centers.length} icon="building" /><Stat label="Devices" value={devices.length} icon="device" />
    </StatGrid>
    <DataTable rows={campuses} search={['name', 'code', 'city', 'address']} title="Campus list" filters={[{ key: 'status', label: 'Status', options: ['active', 'inactive', 'archived'] }]}
      columns={[
        { key: 'name', label: 'Campus', sortable: true, render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code} · {c.address || '—'}</small></> },
        { key: 'city', label: 'City' }, { key: 'capacity', label: 'Capacity' },
        { key: 'centers', label: 'Centres', render: (c) => centers.filter((x) => x.campusId === c.id).length },
        { key: 'devices', label: 'Devices', render: (c) => devices.filter((d) => centers.some((x) => x.id === d.centerId && x.campusId === c.id)).length },
        { key: 'status', label: 'Status', badge: true },
      ]}
      actions={(c) => canManage ? [
        { label: 'Edit', onClick: () => { setF(c); setModal({ mode: 'edit', c }); } },
        { label: c.status === 'active' ? 'Deactivate' : 'Activate', danger: c.status === 'active', onClick: () => setAction({ c, status: c.status === 'active' ? 'inactive' : 'active' }) },
      ] : []} />
    {modal && <Modal title={modal.mode === 'create' ? 'New campus' : `Edit ${modal.c.name}`} onClose={() => setModal(null)} footer={<><button className="btn" onClick={() => setModal(null)}>Cancel</button><button className="btn primary" form="campus-form" disabled={busy}>{modal.mode === 'create' ? 'Create campus' : 'Save changes'}</button></>}>
      <form id="campus-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { if (modal.mode === 'create') await createCampus(user, { tenantId, ...f }); else await updateCampus(user, modal.c, f); setModal(null); }); }}>
        <Field label="Campus name" required className="span2"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
        <Field label="Code"><Input value={f.code} onChange={set('code')} maxLength={10} placeholder="Auto" /></Field>
        <Field label="City"><Input value={f.city} onChange={set('city')} maxLength={40} /></Field>
        <Field label="Address" className="span2"><Input value={f.address} onChange={set('address')} maxLength={160} /></Field>
        <Field label="Capacity"><Input type="number" min="1" max="5000" value={f.capacity} onChange={set('capacity')} /></Field>
      </form>
    </Modal>}
    {action && <ActionDialog title={`${action.status === 'active' ? 'Activate' : 'Deactivate'} ${action.c.name}`} confirmLabel={action.status === 'active' ? 'Activate' : 'Deactivate'} danger={action.status !== 'active'} onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await setCampusStatus(user, action.c, action.status, reason); setAction(null); })} />}
  </Page>;
}

export function DepartmentsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const departments = useCol('departments');
  const campuses = useCol('campuses');
  const users = useCol('users', false);
  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(false);
  const [f, setF] = useState({ name: '', code: '', campusId: '', type: 'academic' });
  const [action, setAction] = useState(null);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return <Page title="Departments" desc="Academic, examination and laboratory units used to scope staff and exams."
    actions={can(user.role, 'dept.manage') ? <button className="btn primary" onClick={() => { setF({ name: '', code: '', campusId: '', type: 'academic' }); setModal(true); }}><Icon name="plus" size={15} /> New department</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <DataTable rows={departments} search={['name', 'code']} title="Departments" filters={[{ key: 'type', label: 'Type', options: DEPT_TYPES }, { key: 'status', label: 'Status', options: ['active', 'inactive'] }]}
      columns={[{ key: 'name', label: 'Department', render: (d) => <><b>{d.name}</b><br /><small className="muted">{d.code}</small></> }, { key: 'type', label: 'Type', badge: true }, { key: 'campus', label: 'Campus', render: (d) => campuses.find((c) => c.id === d.campusId)?.name || '—' }, { key: 'staff', label: 'Staff', render: (d) => users.filter((u) => u.departmentId === d.id).length }, { key: 'status', label: 'Status', badge: true }]}
      actions={(d) => can(user.role, 'dept.manage') ? [{ label: d.status === 'active' ? 'Deactivate' : 'Activate', danger: d.status === 'active', onClick: () => setAction({ d, status: d.status === 'active' ? 'inactive' : 'active' }) }] : []} />
    {modal && <Modal title="New department" onClose={() => setModal(false)} footer={<><button className="btn" onClick={() => setModal(false)}>Cancel</button><button className="btn primary" form="dept-form" disabled={busy}>Create</button></>}>
      <form id="dept-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await createDepartment(user, { tenantId, ...f }); setModal(false); }); }}>
        <Field label="Name" required className="span2"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
        <Field label="Code"><Input value={f.code} onChange={set('code')} maxLength={12} /></Field>
        <Field label="Type"><Select value={f.type} onChange={set('type')} options={DEPT_TYPES} placeholder={false} /></Field>
        <Field label="Campus" className="span2"><Select value={f.campusId} onChange={set('campusId')} options={campuses.map((c) => ({ v: c.id, l: c.name }))} placeholder="No campus" /></Field>
      </form>
    </Modal>}
    {action && <ActionDialog title={`${action.status === 'active' ? 'Activate' : 'Deactivate'} ${action.d.name}`} onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await setDepartmentStatus(user, action.d, action.status, reason); setAction(null); })} />}
  </Page>;
}

export function StaffPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const staff = useCol('staff');
  const users = useCol('users', false);
  const campuses = useCol('campuses');
  const departments = useCol('departments');
  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(false);
  const [action, setAction] = useState(null);
  const [f, setF] = useState({ userId: '', campusId: '', departmentId: '', roleTitle: '' });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const pool = users.filter((u) => u.tenantId === tenantId && u.role !== 'student' && u.status === 'active');
  return <Page title="Staff" desc="Assign institution staff to campuses and departments. Roles themselves are managed under Users."
    actions={can(user.role, 'staff.manage') ? <button className="btn primary" onClick={() => { setF({ userId: '', campusId: '', departmentId: '', roleTitle: '' }); setModal(true); }}><Icon name="plus" size={15} /> Assign staff</button> : undefined}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <DataTable rows={staff} search={['name', 'userId', 'roleTitle']} title="Staff assignments" filters={[{ key: 'status', label: 'Status', options: ['active', 'inactive'] }]}
      columns={[{ key: 'name', label: 'Staff', render: (s) => <><b>{s.name}</b><br /><small className="muted">{s.userId}</small></> }, { key: 'roleTitle', label: 'Title' }, { key: 'campus', label: 'Campus', render: (s) => campuses.find((c) => c.id === s.campusId)?.name || 'All campuses' }, { key: 'department', label: 'Department', render: (s) => departments.find((d) => d.id === s.departmentId)?.name || '—' }, { key: 'status', label: 'Status', badge: true }, { key: 'updatedAt', label: 'Updated', render: (s) => ago(s.updatedAt) }]}
      actions={(s) => can(user.role, 'staff.manage') ? [{ label: 'Remove', danger: true, onClick: () => setAction(s) }] : []} />
    {modal && <Modal title="Assign staff" onClose={() => setModal(false)} footer={<><button className="btn" onClick={() => setModal(false)}>Cancel</button><button className="btn primary" form="staff-form" disabled={busy}>Save assignment</button></>}>
      <form id="staff-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await assignStaff(user, { tenantId, ...f }); setModal(false); }); }}>
        <Field label="Staff account" required className="span2"><Select value={f.userId} onChange={set('userId')} options={pool.map((u) => ({ v: u.id, l: `${u.name} · ${u.role}` }))} /></Field>
        <Field label="Campus"><Select value={f.campusId} onChange={set('campusId')} options={campuses.map((c) => ({ v: c.id, l: c.name }))} placeholder="All campuses" /></Field>
        <Field label="Department"><Select value={f.departmentId} onChange={set('departmentId')} options={departments.map((d) => ({ v: d.id, l: d.name }))} placeholder="None" /></Field>
        <Field label="Role title" className="span2"><Input value={f.roleTitle} onChange={set('roleTitle')} maxLength={60} placeholder="e.g. Chief invigilator" /></Field>
      </form>
    </Modal>}
    {action && <ActionDialog title={`Remove ${action.name}`} desc="The account is not deleted; only the staff assignment is retired." danger confirmLabel="Remove assignment" onClose={() => setAction(null)} onConfirm={(reason) => run(async () => { await removeStaff(user, action, reason); setAction(null); })} />}
  </Page>;
}

export function CollegeSettingsPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
  const { msg, run, busy, setMsg } = useFlash();
  const [f, setF] = useState(() => ({
    name: tenant?.name || '', contactEmail: tenant?.contactEmail || '', contactPhone: tenant?.contactPhone || '',
    region: tenant?.region || '', timezone: tenant?.timezone || 'Asia/Kolkata', deploymentModel: tenant?.deploymentModel || 'usb-boot',
    maxCandidates: tenant?.maxCandidates || 500, domains: (tenant?.domains || []).join(' '),
    requireTpm: tenant?.security?.requireTpm ?? true, requireSecureBoot: tenant?.security?.requireSecureBoot ?? true, allowUsbStorage: tenant?.security?.allowUsbStorage ?? false,
    durationMin: tenant?.examDefaults?.durationMin || 60, lateEntryMin: tenant?.examDefaults?.lateEntryMin || 0, attestationLevel: tenant?.examDefaults?.attestationLevel || 'tpm',
    email: tenant?.notificationPrefs?.email ?? true, inApp: tenant?.notificationPrefs?.inApp ?? true,
  }));
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  if (!tenant) return <Page title="Institution settings"><Empty icon="settings" title="No institution selected">Choose an institution in the top bar.</Empty></Page>;
  const save = () => run(async () => {
    await updateInstitution(user, tenant, { name: f.name, contactEmail: f.contactEmail, contactPhone: f.contactPhone, region: f.region, timezone: f.timezone, deploymentModel: f.deploymentModel, maxCandidates: f.maxCandidates, domains: f.domains, security: { requireTpm: f.requireTpm, requireSecureBoot: f.requireSecureBoot, allowUsbStorage: f.allowUsbStorage }, notificationPrefs: { email: f.email, inApp: f.inApp } });
    await saveExamDefaults(user, tenant, { durationMin: Number(f.durationMin), lateEntryMin: Number(f.lateEntryMin), attestationLevel: f.attestationLevel });
    return 'Institution settings saved.';
  });
  return <Page title="Institution settings" desc="Branding, defaults, security posture and notification preferences." actions={<button className="btn primary" disabled={busy || !can(user.role, 'settings.inst')} onClick={save}>{busy ? 'Saving…' : 'Save settings'}</button>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <div className="two">
      <Card title="Profile"><div className="formgrid one">
        <Field label="Institution name"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
        <Field label="Email domains" help="Space separated"><Input value={f.domains} onChange={set('domains')} /></Field>
        <Field label="Contact email"><Input type="email" value={f.contactEmail} onChange={set('contactEmail')} /></Field>
        <Field label="Contact phone"><Input value={f.contactPhone} onChange={set('contactPhone')} /></Field>
        <Field label="Region"><Input value={f.region} onChange={set('region')} /></Field>
        <Field label="Timezone"><Select value={f.timezone} onChange={set('timezone')} options={TIMEZONES} placeholder={false} /></Field>
        <Field label="Deployment model"><Select value={f.deploymentModel} onChange={set('deploymentModel')} options={DEPLOYMENT_MODELS} placeholder={false} /></Field>
        <Field label="Candidate capacity"><Input type="number" value={f.maxCandidates} onChange={set('maxCandidates')} /></Field>
      </div></Card>
      <div>
        <Card title="Security defaults"><div className="stack">
          <Checkbox label="Require TPM 2.0 attestation" checked={f.requireTpm} onChange={set('requireTpm')} />
          <Checkbox label="Require Secure Boot" checked={f.requireSecureBoot} onChange={set('requireSecureBoot')} />
          <Checkbox label="Allow USB storage during exams" checked={f.allowUsbStorage} onChange={set('allowUsbStorage')} />
          <Field label="Default exam duration (minutes)"><Input type="number" min="15" max="300" value={f.durationMin} onChange={set('durationMin')} /></Field>
          <Field label="Default late entry (minutes)"><Input type="number" min="0" max="60" value={f.lateEntryMin} onChange={set('lateEntryMin')} /></Field>
          <Field label="Attestation level"><Select value={f.attestationLevel} onChange={set('attestationLevel')} options={[{ v: 'none', l: 'None' }, { v: 'tpm', l: 'TPM quote' }, { v: 'tpm-secureboot', l: 'TPM + Secure Boot' }]} placeholder={false} /></Field>
        </div></Card>
        <Card title="Notifications"><div className="stack"><Checkbox label="Email notifications" checked={f.email} onChange={set('email')} /><Checkbox label="In-app notifications" checked={f.inApp} onChange={set('inApp')} /></div></Card>
      </div>
    </div>
    <Card title="Institution identifiers"><div className="two-inline"><CopyField label="Institution ID" value={tenant.id} /><CopyField label="Code" value={tenant.code} /></div></Card>
  </Page>;
}
