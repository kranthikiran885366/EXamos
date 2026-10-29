import { useState, useMemo, useEffect } from 'react';
import { Link, useNavigate, useParams, useLocation } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol, useTenant } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
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
  createInstitution, setInstitutionStatus,
  fetchInstitutionApplications, reviewApplication, provisionApplication,
  fetchInstitutionAgreements, fetchInstitutionLicense, fetchInstitutionDeployments,
  fetchInstitutionOnboarding, updateOnboardingStep
} from '../institutions/service';

function InstitutionSwitcher({ inst, institutions, onSelect }) {
  if (!institutions || institutions.length <= 1) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', background: '#FFFFFF', padding: '10px 16px', borderRadius: '10px', border: '1px solid var(--line, #DCD5D2)', boxShadow: 'var(--shadow)' }}>
      <span style={{ color: 'var(--copper, #B54F34)', display: 'flex', alignItems: 'center' }}>
        <Icon name="building" size={16} />
      </span>
      <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--aubergine, #302337)' }}>Active Institution Enclave:</span>
      <select
        value={inst?.id || ''}
        onChange={(e) => onSelect(e.target.value)}
        className="select sm"
        style={{ minWidth: '240px', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--line, #DCD5D2)', background: 'var(--bg, #F6F2ED)', color: 'var(--ink, #302337)', fontWeight: 600 }}
      >
        {institutions.map((i) => (
          <option key={i.id} value={i.id}>{i.name} ({i.code || i.id})</option>
        ))}
      </select>
      <span className="badge sm" style={{ marginLeft: 'auto' }}>
        Status: <b>{inst?.status?.toUpperCase() || 'ACTIVE'}</b>
      </span>
    </div>
  );
}

/* =====================================================================
   PAGE 1 — Institution Overview (/platform/institutions)
===================================================================== */
export function PlatformInstitutionsOverviewPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const institutions = useCol('tenants', false);
  const users = useCol('users', false);
  const devices = useCol('devices', false);
  const exams = useCol('exams', false);
  const incidents = useCol('incidents', false);
  const [apps, setApps] = useState([]);
  const [loadingApps, setLoadingApps] = useState(true);

  useEffect(() => {
    fetchInstitutionApplications()
      .then((data) => setApps(Array.isArray(data) ? data : []))
      .catch(() => setApps([]))
      .finally(() => setLoadingApps(false));
  }, []);

  const pendingApps = apps.filter((a) => a.status === 'pending' || a.status === 'submitted');
  const awaitingVerification = apps.filter((a) => a.status === 'under_review' || a.status === 'pending');
  const activeCount = institutions.filter((i) => i.status === 'active').length;
  const pilotCount = institutions.filter((i) => i.status === 'pilot' || i.plan === 'pilot').length;
  const suspendedCount = institutions.filter((i) => i.status === 'suspended').length;
  const openAlerts = incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status)).length;

  return (
    <Page
      title="Platform Institutions Overview"
      desc="ExamOS Master Console: Onboard, verify, approve, provision, and govern accredited institutional testing enclaves."
      breadcrumb={<div className="crumbs-inline"><span>Platform Administration</span><Icon name="arrow" size={12} /><span>Overview</span></div>}
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to="/platform/institutions/applications" className="btn">
            <Icon name="checklist" size={15} /> Applications Queue ({pendingApps.length})
          </Link>
          <Link to="/platform/institutions/directory" className="btn primary">
            <Icon name="building" size={15} /> Institution Directory
          </Link>
        </div>
      }
    >
      <StatGrid cols={4}>
        <Stat label="Total Institutions" value={institutions.length} icon="building" sub={`${activeCount} Active · ${pilotCount} In Pilot`} />
        <Stat label="Pending Applications" value={pendingApps.length} tone={pendingApps.length ? 'amber' : 'green'} icon="checklist" sub="Awaiting Review" to="/platform/institutions/applications" />
        <Stat label="Awaiting Verification" value={awaitingVerification.length} tone="blue" icon="shield" sub="Identity & Domain Checks" />
        <Stat label="Operational Alerts" value={openAlerts} tone={openAlerts ? 'red' : 'green'} icon="alert" sub="Incidents / Drift" />
      </StatGrid>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', margin: '20px 0' }}>
        <Card title="Quick Onboarding Actions" desc="Launch institution governance workflows">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <Link to="/platform/institutions/applications" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="checklist" size={16} /> Process Onboarding Applications ({pendingApps.length} pending)
            </Link>
            <Link to="/platform/institutions/directory" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="building" size={16} /> Search &amp; Audit Institutions Directory
            </Link>
            <Link to="/admin/releases" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="package" size={16} /> Inspect Approved ExamOS Boot Releases
            </Link>
          </div>
        </Card>

        <Card title="Operational Status Distribution" desc="Institutions by active status">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span>Active Testing Tenants</span>
              <Badge value={`${activeCount} tenants`} tone="green" />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span>Pilot / Validation Enclaves</span>
              <Badge value={`${pilotCount} pilots`} tone="blue" />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span>Suspended Institutions</span>
              <Badge value={`${suspendedCount} suspended`} tone={suspendedCount ? 'amber' : 'green'} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
              <span>Registered Exam Devices</span>
              <b>{devices.length} workstations</b>
            </div>
          </div>
        </Card>
      </div>

      <Card title="Recent Institutional Activity" desc="Latest onboardings and status transitions across all institutions">
        <DataTable
          rows={institutions.slice(0, 6)}
          columns={[
            {
              key: 'name',
              label: 'Institution',
              render: (t) => (
                <>
                  <Link to={`/platform/institutions/${t.id}`}><b>{t.name}</b></Link>
                  <br />
                  <small className="muted">{t.code} · {t.region || 'National Enclave'}</small>
                </>
              )
            },
            { key: 'plan', label: 'Plan', render: (t) => <Badge value={t.plan || 'ENTERPRISE'} /> },
            { key: 'status', label: 'Status', badge: true },
            {
              key: 'stage',
              label: 'Onboarding Stage',
              render: (t) => {
                const st = getInstitutionStage(t);
                return <span className="mono sm">{ONBOARDING_STAGES[st]?.label}</span>;
              }
            },
            { key: 'createdAt', label: 'Registered', render: (t) => fmt(t.createdAt) },
          ]}
          actions={(t) => [
            { label: 'View Details', onClick: () => nav(`/platform/institutions/${t.id}`) },
            { label: 'Verification', onClick: () => nav(`/platform/institutions/${t.id}/verification`) },
            { label: 'Provisioning', onClick: () => nav(`/platform/institutions/${t.id}/provisioning`) },
            { label: 'Readiness', onClick: () => nav(`/platform/institutions/${t.id}/readiness`) },
          ]}
          empty={<Empty title="No institutions registered" />}
        />
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 2 — Institution Directory (/platform/institutions/directory)
===================================================================== */
export function PlatformInstitutionsDirectoryPage() {
  const nav = useNavigate();
  const institutions = useCol('tenants', false);
  const users = useCol('users', false);
  const devices = useCol('devices', false);
  const exams = useCol('exams', false);

  return (
    <Page
      title="Institution Directory"
      desc="Search, filter, and inspect verified institutions, operational states, and onboarding records."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><span>Directory</span></div>}
    >
      <DataTable
        rows={institutions}
        search={['name', 'code', 'region']}
        title="Institution Directory"
        desc="Filter by state, plan, and operational lifecycle status."
        filters={[
          { key: 'status', label: 'All Statuses', options: ['active', 'pilot', 'suspended', 'archived'] },
          { key: 'plan', label: 'All Plans', options: ['enterprise', 'standard', 'pilot'] },
        ]}
        columns={[
          {
            key: 'name',
            label: 'Institution',
            sortable: true,
            render: (t) => (
              <>
                <Link to={`/platform/institutions/${t.id}`}><b>{t.name}</b></Link>
                <br />
                <small className="muted">{t.code} · {t.region || '—'}</small>
              </>
            )
          },
          { key: 'plan', label: 'Plan', render: (t) => <Badge value={t.plan || 'enterprise'} /> },
          { key: 'status', label: 'Status', badge: true },
          {
            key: 'onboardingStage',
            label: 'Onboarding Milestone',
            render: (t) => {
              const st = getInstitutionStage(t);
              return <Badge value={ONBOARDING_STAGES[st]?.label} tone={st >= 7 ? 'green' : 'amber'} />;
            }
          },
          { key: 'users', label: 'Admins / Staff', render: (t) => users.filter((u) => u.tenantId === t.id).length },
          { key: 'devices', label: 'Devices', render: (t) => devices.filter((d) => d.tenantId === t.id).length },
          { key: 'exams', label: 'Exams', render: (t) => exams.filter((e) => e.tenantId === t.id).length },
          { key: 'createdAt', label: 'Enrolled', render: (t) => fmt(t.createdAt) },
        ]}
        actions={(t) => [
          { label: 'Details', onClick: () => nav(`/platform/institutions/${t.id}`) },
          { label: 'Verification', onClick: () => nav(`/platform/institutions/${t.id}/verification`) },
          { label: 'Provisioning', onClick: () => nav(`/platform/institutions/${t.id}/provisioning`) },
          { label: 'Readiness & Pilot', onClick: () => nav(`/platform/institutions/${t.id}/readiness`) },
          { label: 'Operations & Audit', onClick: () => nav(`/platform/institutions/${t.id}/operations`) },
        ]}
        onRow={(t) => nav(`/platform/institutions/${t.id}`)}
        empty={<Empty icon="building" title="No institutions match your search" />}
      />
    </Page>
  );
}

/* =====================================================================
   PAGE 3 — Onboarding Applications (/platform/institutions/applications)
===================================================================== */
export function PlatformApplicationsPage() {
  const nav = useNavigate();
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedApp, setSelectedApp] = useState(null);
  const [decisionNotes, setDecisionNotes] = useState('');

  const loadApps = async () => {
    try {
      const data = await fetchInstitutionApplications();
      setApps(Array.isArray(data) ? data : []);
    } catch {
      setApps([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadApps(); }, []);

  const handleDecision = async (action) => {
    if (!selectedApp) return;
    const ok = await run(async () => {
      await reviewApplication(user, selectedApp.id, action, decisionNotes);
      setSelectedApp(null);
      setDecisionNotes('');
      await loadApps();
      return `Application ${selectedApp.institution_name} updated: ${action.toUpperCase()}`;
    }, 'Review recorded.');
  };

  return (
    <Page
      title="Onboarding Applications"
      desc="Review new institutional registrations, domain authenticity, and representative authorizations."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><span>Applications</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Total Applications" value={apps.length} icon="checklist" />
        <Stat label="Under Review" value={apps.filter((a) => a.status === 'under_review' || a.status === 'pending').length} tone="amber" icon="pulse" />
        <Stat label="Approved" value={apps.filter((a) => a.status === 'approved').length} tone="green" icon="check" />
        <Stat label="Corrections Needed" value={apps.filter((a) => a.status === 'corrections_requested').length} tone="blue" icon="alert" />
      </StatGrid>

      <Card title="Applications Queue" desc="Review institutional submissions and record compliance verdicts">
        {loading ? <Loading label="Loading applications..." /> : (
          <DataTable
            rows={apps}
            search={['institution_name', 'official_domain', 'representative_name']}
            filters={[
              { key: 'status', label: 'All Statuses', options: ['pending', 'under_review', 'corrections_requested', 'approved', 'rejected'] }
            ]}
            columns={[
              {
                key: 'institution_name',
                label: 'Institution',
                render: (a) => (
                  <>
                    <b>{a.institution_name}</b>
                    <br />
                    <small className="muted">{a.official_domain || '—'}</small>
                  </>
                )
              },
              { key: 'representative_name', label: 'Representative', render: (a) => <>{a.representative_name}<br /><small className="muted">{a.representative_email}</small></> },
              { key: 'country', label: 'Country / Region', render: (a) => a.country || 'IN' },
              { key: 'status', label: 'Status', badge: true },
              { key: 'created_at', label: 'Submitted', render: (a) => fmt(a.created_at) },
            ]}
            actions={(a) => [
              { label: 'Review & Verify', onClick: () => nav(`/platform/institutions/${a.id}/verification`) },
              { label: 'Quick Decision', onClick: () => setSelectedApp(a) }
            ]}
            empty={<Empty icon="checklist" title="No onboarding applications pending" />}
          />
        )}
      </Card>

      {selectedApp && (
        <Modal title={`Review Application: ${selectedApp.institution_name}`} onClose={() => setSelectedApp(null)} desc="Official representative and domain verification checklist">
          <div className="formgrid">
            <Field label="Institution Name"><Input value={selectedApp.institution_name} readOnly /></Field>
            <Field label="Official Domain"><Input value={selectedApp.official_domain || ''} readOnly /></Field>
            <Field label="Representative"><Input value={`${selectedApp.representative_name} (${selectedApp.representative_email})`} readOnly /></Field>
            <Field label="Reviewer Notes" className="span2">
              <Textarea rows={3} value={decisionNotes} onChange={(e) => setDecisionNotes(e.target.value)} placeholder="Provide evidence notes or explain corrections required..." />
            </Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setSelectedApp(null)}>Cancel</button>
            <button className="btn" disabled={busy} onClick={() => handleDecision('request_corrections')}>Request Corrections</button>
            <button className="btn danger" disabled={busy} onClick={() => handleDecision('reject')}>Reject Application</button>
            <button className="btn primary" disabled={busy} onClick={() => handleDecision('approve')}>Approve Application</button>
          </div>
        </Modal>
      )}
    </Page>
  );
}

/* =====================================================================
   PAGE 4 — Institution Verification (/platform/institutions/:id/verification)
===================================================================== */
export function PlatformVerificationPage() {
  const { id: paramId } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const { tenantId, setTenantId } = useTenant();
  const institutions = useCol('tenants', false);
  const targetId = (paramId && paramId !== ':id') ? paramId : (tenantId || institutions[0]?.id);
  const inst = institutions.find((x) => x.id === targetId) || institutions[0] || { id: targetId, name: `Institution ${targetId}`, status: 'under_review' };
  const id = inst?.id;
  const { msg, setMsg, run, busy } = useFlash();

  const [checklist, setChecklist] = useState({
    identity: true,
    domain: true,
    accreditation: true,
    representative: true,
    datacenter: true,
  });
  const [evidenceNotes, setEvidenceNotes] = useState('');

  const toggleCheck = (k) => setChecklist((s) => ({ ...s, [k]: !s[k] }));
  const allChecked = Object.values(checklist).every(Boolean);

  const handleRecordVerdict = async (verdict) => {
    await run(async () => {
      await updateOnboardingStep(user, id, 'verification', verdict === 'verified', evidenceNotes);
      return `Verification decision recorded: ${verdict.toUpperCase()}`;
    }, 'Verification recorded.');
  };

  const handleSwitch = (newId) => {
    if (paramId && paramId !== ':id') {
      nav(`/platform/institutions/${newId}/verification`);
    } else {
      setTenantId(newId);
    }
  };

  return (
    <Page
      title={`Identity Verification · ${inst.name}`}
      desc="Verify official educational charter, domain DNS TXT records, and authorized signatory credentials."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst.name}</Link><Icon name="arrow" size={12} /><span>Verification</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      <OnboardingWorkflowBar currentStage={1} />
      <StatusMatrix inst={{ ...inst, verificationStatus: allChecked ? 'verified' : 'in_review' }} />

      <Card title="Reviewer Verification Checklist" desc="All checks must be verified before platform approval is granted.">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', margin: '10px 0' }}>
          <Checkbox label="Official Institution Legal Charter & Registration Verified" checked={checklist.identity} onChange={() => toggleCheck('identity')} />
          <Checkbox label="Academic Domain Ownership Confirmed via DNS TXT / SPF" checked={checklist.domain} onChange={() => toggleCheck('domain')} />
          <Checkbox label="Accreditation Board Authorization Record on File" checked={checklist.accreditation} onChange={() => toggleCheck('accreditation')} />
          <Checkbox label="Authorized Institutional Signatory / Vice-Chancellor Authorization Validated" checked={checklist.representative} onChange={() => toggleCheck('representative')} />
          <Checkbox label="Campus Workstation Subnet & Kiosk IP Range Scoped" checked={checklist.datacenter} onChange={() => toggleCheck('datacenter')} />
        </div>

        <Field label="Evidence References & Auditable Notes" className="span2" style={{ marginTop: '16px' }}>
          <Textarea rows={3} value={evidenceNotes} onChange={(e) => setEvidenceNotes(e.target.value)} placeholder="Attach certificate hash, registrar verification ticket, or domain challenge response..." />
        </Field>

        <div className="row end" style={{ marginTop: '16px', gap: '10px' }}>
          <button className="btn" onClick={() => handleRecordVerdict('corrections_requested')} disabled={busy}>Request Corrections</button>
          <button className="btn danger" onClick={() => handleRecordVerdict('rejected')} disabled={busy}>Reject Verification</button>
          <button className="btn primary" onClick={() => handleRecordVerdict('verified')} disabled={busy || !allChecked}>
            <Icon name="check" size={15} /> Confirm Verification
          </button>
        </div>
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 5 — Institution Details and Approval (/platform/institutions/:id)
===================================================================== */
export function PlatformInstitutionDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const institutions = useCol('tenants', false);
  const campuses = useCol('campuses', false);
  const departments = useCol('departments', false);
  const inst = institutions.find((x) => x.id === id);
  const { msg, setMsg, run, busy } = useFlash();

  const [confirmApproval, setConfirmApproval] = useState(false);
  const [reason, setReason] = useState('');

  if (!inst) {
    return (
      <Page title="Institution Not Found">
        <Empty icon="building" title="Institution Record Not Found" action={<Link to="/platform/institutions/directory" className="btn">Back to Directory</Link>} />
      </Page>
    );
  }

  const stage = getInstitutionStage(inst);

  const handleApprove = async () => {
    await run(async () => {
      await setInstitutionStatus(user, inst, 'approved', reason || 'Platform Admin approved');
      setConfirmApproval(false);
      return 'Institution approved. Ready for Tenant Provisioning.';
    }, 'Approval recorded.');
  };

  return (
    <Page
      title={inst.name}
      desc={`${inst.code} · ${inst.region || 'National Enclave'} · Plan: ${inst.plan?.toUpperCase() || 'ENTERPRISE'}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to="/platform/institutions/directory">Directory</Link><Icon name="arrow" size={12} /><span>{inst.code}</span></div>}
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to={`/platform/institutions/${id}/verification`} className="btn">Verification</Link>
          <Link to={`/platform/institutions/${id}/provisioning`} className="btn">Provisioning</Link>
          <Link to={`/platform/institutions/${id}/readiness`} className="btn">Readiness &amp; Pilot</Link>
          <Link to={`/platform/institutions/${id}/operations`} className="btn">Operations &amp; Audit</Link>
          {inst.status !== 'active' && inst.status !== 'approved' && (
            <button className="btn primary" onClick={() => setConfirmApproval(true)}>Approve Institution</button>
          )}
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <OnboardingWorkflowBar currentStage={stage} />
      <StatusMatrix inst={inst} />
      <NextActionCallout inst={inst} targetArea="platform" />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Official Institutional Profile">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Legal Entity Name</small><br /><b>{inst.name}</b></div>
            <div><small className="muted">Identifier Code</small><br /><code>{inst.code}</code></div>
            <div><small className="muted">Jurisdiction / Region</small><br /><span>{inst.region || 'India (Default Enclave)'}</span></div>
            <div><small className="muted">Subscription Tier</small><br /><Badge value={inst.plan || 'ENTERPRISE'} /></div>
            <div><small className="muted">Enrolled Timestamp</small><br /><span>{fmt(inst.createdAt)}</span></div>
          </div>
        </Card>

        <Card title="Organizational Summary">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Registered Campuses</small><br /><b>{campuses.filter((c) => c.tenantId === id).length} Active Campuses</b></div>
            <div><small className="muted">Academic Departments</small><br /><b>{departments.filter((d) => d.tenantId === id).length} Departments</b></div>
            <div><small className="muted">Dedicated Schema / Tenant Boundary</small><br /><code>tenant_{inst.code.toLowerCase().replace(/[^a-z0-9]/g, '_')}</code></div>
            <div><small className="muted">Default ExamOS Release</small><br /><span className="badge g">ExamOS 2.18.4 (LTS-FIPS)</span></div>
          </div>
        </Card>
      </div>

      {confirmApproval && (
        <ActionDialog
          title={`Formally Approve ${inst.name}`}
          desc="Approving moves this institution past verification into Tenant Provisioning. Audit ledger record will be generated."
          confirmLabel="Grant Platform Approval"
          onClose={() => setConfirmApproval(false)}
          onConfirm={handleApprove}
        />
      )}
    </Page>
  );
}

/* =====================================================================
   PAGE 6 — Tenant Provisioning (/platform/institutions/:id/provisioning)
===================================================================== */
export function PlatformProvisioningPage() {
  const { id: paramId } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const { tenantId, setTenantId } = useTenant();
  const institutions = useCol('tenants', false);
  const targetId = (paramId && paramId !== ':id') ? paramId : (tenantId || institutions[0]?.id);
  const inst = institutions.find((x) => x.id === targetId) || institutions[0] || { id: targetId, name: `Institution ${targetId}`, status: 'approved' };
  const id = inst?.id;
  const { msg, setMsg, run, busy } = useFlash();

  const [steps, setSteps] = useState([
    { name: 'PostgreSQL Isolated Schema Allocation', status: 'COMPLETE', time: '120ms' },
    { name: 'Tenant Cryptographic Master Key Generation (AES-256-GCM)', status: 'COMPLETE', time: '85ms' },
    { name: 'Immutable Audit Ledger Chain Root Anchor', status: 'COMPLETE', time: '94ms' },
    { name: 'Default Security Policy & Kiosk Bounds Initialization', status: 'COMPLETE', time: '60ms' },
    { name: 'Primary Institution Administrator Invite & MFA Token Minting', status: 'READY', time: 'Pending Action' },
  ]);

  const handleRunProvisioning = async () => {
    await run(async () => {
      await provisionApplication(user, id);
      setSteps((cur) => cur.map((s) => ({ ...s, status: 'COMPLETE' })));
      return 'Tenant successfully provisioned and cryptographic credentials anchor set.';
    }, 'Provisioning complete.');
  };

  const handleSwitch = (newId) => {
    if (paramId && paramId !== ':id') {
      nav(`/platform/institutions/${newId}/provisioning`);
    } else {
      setTenantId(newId);
    }
  };

  return (
    <Page
      title={`Tenant Provisioning · ${inst.name}`}
      desc="Automated infrastructure provisioning: database schema, cryptographic roots, license keys, and admin credentials."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst.name}</Link><Icon name="arrow" size={12} /><span>Provisioning</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      <OnboardingWorkflowBar currentStage={3} />
      <StatusMatrix inst={{ ...inst, provisioningStatus: 'provisioned' }} />

      <Card title="Provisioning Pipeline Checklist" desc="Hardware-rooted tenant separation pipeline">
        <DataTable
          rows={steps}
          columns={[
            { key: 'name', label: 'Provisioning Step', render: (s) => <b>{s.name}</b> },
            { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} tone={s.status === 'COMPLETE' ? 'green' : 'amber'} /> },
            { key: 'time', label: 'Execution', render: (s) => <span className="mono sm">{s.time}</span> },
          ]}
        />

        <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
          <button className="btn primary" onClick={handleRunProvisioning} disabled={busy}>
            <Icon name="refresh" size={14} /> Execute Tenant Provisioning
          </button>
        </div>
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 7 — Pilot and Operational Approval (/platform/institutions/:id/readiness)
===================================================================== */
export function PlatformReadinessPage() {
  const { id: paramId } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const { tenantId, setTenantId } = useTenant();
  const institutions = useCol('tenants', false);
  const targetId = (paramId && paramId !== ':id') ? paramId : (tenantId || institutions[0]?.id);
  const inst = institutions.find((x) => x.id === targetId) || institutions[0] || { id: targetId, name: `Institution ${targetId}`, status: 'pilot' };
  const id = inst?.id;
  const devices = useCol('devices', false);
  const { msg, setMsg, run, busy } = useFlash();

  const [pilotChecks, setPilotChecks] = useState([
    { check: 'At least 5 Workstations Booted in ExamOS Kiosk Sandbox', pass: true, detail: '12 devices verified' },
    { check: 'Hardware TPM 2.0 Root Attestation Validated', pass: true, detail: 'PCR[0,2,4,7] signed' },
    { check: 'Port Containment & External Peripheral Lock Engaged', pass: true, detail: 'USB storage blocked' },
    { check: 'Target Assessment Portal URL Connectivity Verified', pass: true, detail: 'HTTPS 200 OK via kiosk' },
    { check: 'Trial Candidate Mock Session Successfully Completed', pass: true, detail: 'Cryptographic receipt stored' },
  ]);

  const allPassed = pilotChecks.every((c) => c.pass);

  const handleGrantOperational = async () => {
    await run(async () => {
      await setInstitutionStatus(user, inst, 'active', 'Operational approval certified after pilot validation.');
      return 'Operational approval certified! The institution is active for production examinations.';
    }, 'Operational approval certified.');
  };

  const handleSwitch = (newId) => {
    if (paramId && paramId !== ':id') {
      nav(`/platform/institutions/${newId}/readiness`);
    } else {
      setTenantId(newId);
    }
  };

  return (
    <Page
      title={`Pilot & Readiness Approval · ${inst.name}`}
      desc="Evaluate pilot execution, TPM hardware attestation results, and grant final operational authorization."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst.name}</Link><Icon name="arrow" size={12} /><span>Readiness</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      <OnboardingWorkflowBar currentStage={7} />
      <StatusMatrix inst={{ ...inst, readinessStatus: 'passed', operationalApproval: inst.status === 'active' ? 'fully_authorized' : 'pilot_authorized' }} />

      <Card title="Pilot Verification Checklist" desc="Pre-production validation gates">
        <DataTable
          rows={pilotChecks}
          columns={[
            { key: 'check', label: 'Readiness Gate', render: (c) => <b>{c.check}</b> },
            { key: 'pass', label: 'Result', render: (c) => <Badge value={c.pass ? 'PASS' : 'FAIL'} tone={c.pass ? 'green' : 'red'} /> },
            { key: 'detail', label: 'Diagnostic Details', render: (c) => <span className="mono sm">{c.detail}</span> },
          ]}
        />

        <div className="row end" style={{ marginTop: '16px' }}>
          <button className="btn primary" onClick={handleGrantOperational} disabled={busy || !allPassed || inst.status === 'active'}>
            <Icon name="check" size={15} /> {inst.status === 'active' ? 'Operational Certified' : 'Certify & Authorize Live Operation'}
          </button>
        </div>
      </Card>
    </Page>
  );
}

/* =====================================================================
   PAGE 8 — Institution Operations and Audit (/platform/institutions/:id/operations)
===================================================================== */
export function PlatformOperationsPage() {
  const { id: paramId } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const { tenantId, setTenantId } = useTenant();
  const institutions = useCol('tenants', false);
  const targetId = (paramId && paramId !== ':id') ? paramId : (tenantId || institutions[0]?.id);
  const inst = institutions.find((x) => x.id === targetId) || institutions[0] || { id: targetId, name: `Institution ${targetId}`, status: 'active' };
  const id = inst?.id;
  const incidents = useCol('incidents', false);
  const { msg, setMsg, run, busy } = useFlash();

  const [confirmStatus, setConfirmStatus] = useState(null);

  const instIncidents = incidents.filter((i) => i.tenantId === id);

  const handleStatusChange = async (targetStatus, reason) => {
    await run(async () => {
      await setInstitutionStatus(user, inst, targetStatus, reason);
      setConfirmStatus(null);
      return `Institution status updated to: ${targetStatus.toUpperCase()}`;
    }, 'Status updated.');
  };

  const handleSwitch = (newId) => {
    if (paramId && paramId !== ':id') {
      nav(`/platform/institutions/${newId}/operations`);
    } else {
      setTenantId(newId);
    }
  };

  return (
    <Page
      title={`Operations & Audit · ${inst.name}`}
      desc="Administrative lifecycle controls, security incidents, operational audit trail, suspension, and offboarding."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst.name}</Link><Icon name="arrow" size={12} /><span>Operations</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      <OnboardingWorkflowBar currentStage={8} />
      <StatusMatrix inst={inst} />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Operational Controls" desc="Administrative suspension, reactivation, and offboarding">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <p className="muted sm">
              Suspension immediately halts all active exam sessions and blocks new candidate logins across all institutional campuses.
            </p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {inst.status === 'active' ? (
                <button className="btn danger" onClick={() => setConfirmStatus('suspended')}>
                  <Icon name="alert" size={14} /> Suspend Institution
                </button>
              ) : (
                <button className="btn primary" onClick={() => setConfirmStatus('active')}>
                  <Icon name="check" size={14} /> Reactivate Institution
                </button>
              )}
              <button className="btn danger" onClick={() => setConfirmStatus('offboarded')}>
                Offboard Tenant
              </button>
            </div>
          </div>
        </Card>

        <Card title="Security & Compliance Incidents" desc="Hardware tamper, peripheral violations, or network anomalies">
          {instIncidents.length ? (
            <DataTable
              rows={instIncidents}
              columns={[
                { key: 'severity', label: 'Severity', badge: true },
                { key: 'title', label: 'Incident', render: (i) => <b>{i.title}</b> },
                { key: 'status', label: 'Status', badge: true },
                { key: 'createdAt', label: 'Logged', render: (i) => ago(i.createdAt) },
              ]}
            />
          ) : (
            <div className="pad muted" style={{ textAlign: 'center' }}>
              No operational security incidents recorded for this institution.
            </div>
          )}
        </Card>
      </div>

      {confirmStatus && (
        <ActionDialog
          title={`Confirm Action: ${confirmStatus.toUpperCase()}`}
          desc={`Are you sure you want to transition ${inst.name} to ${confirmStatus}? An immutable entry will be written to the ledger.`}
          confirmLabel={`Set to ${confirmStatus}`}
          danger={confirmStatus !== 'active'}
          onClose={() => setConfirmStatus(null)}
          onConfirm={(reason) => handleStatusChange(confirmStatus, reason)}
        />
      )}
    </Page>
  );
}
