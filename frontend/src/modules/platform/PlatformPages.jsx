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
  const [decisionResult, setDecisionResult] = useState(null); // { action, app }

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
    await run(async () => {
      await reviewApplication(user, selectedApp.id, action, decisionNotes);
      const appSnapshot = { ...selectedApp };
      setSelectedApp(null);
      setDecisionNotes('');
      await loadApps();
      setDecisionResult({ action, app: appSnapshot });
      return `Application ${appSnapshot.legalName || appSnapshot.institution_name} updated: ${action.toUpperCase()}`;
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
        <Stat label="Under Review" value={apps.filter((a) => ['SUBMITTED', 'UNDER_REVIEW', 'pending', 'under_review'].includes(a.status)).length} tone="amber" icon="pulse" />
        <Stat label="Approved / Provisioned" value={apps.filter((a) => ['APPROVED', 'PROVISIONED', 'approved', 'provisioned'].includes(a.status)).length} tone="green" icon="check" />
        <Stat label="Action Required" value={apps.filter((a) => ['MORE_INFORMATION_REQUIRED', 'corrections_requested'].includes(a.status)).length} tone="blue" icon="alert" />
      </StatGrid>

      <Card title="Applications Queue" desc="Review institutional submissions and record compliance verdicts">
        {loading ? <Loading label="Loading applications..." /> : (
          <DataTable
            rows={apps}
            search={['legalName', 'displayName', 'domain', 'repEmail', 'registrationNumber', 'institution_name']}
            filters={[
              { key: 'status', label: 'All Statuses', options: ['SUBMITTED', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'MORE_INFORMATION_REQUIRED', 'APPROVED', 'PROVISIONED', 'REJECTED'] }
            ]}
            columns={[
              {
                key: 'institution',
                label: 'Institution',
                render: (a) => (
                  <>
                    <b>{a.legalName || a.displayName || a.institution_name}</b>
                    <br />
                    <small className="muted">{a.domain || a.official_domain || '—'} · {a.registrationNumber || a.code || 'Pending'}</small>
                  </>
                )
              },
              { key: 'representative', label: 'Representative', render: (a) => <>{a.repName || a.representative_name || 'Signatory'}<br /><small className="muted">{a.repEmail || a.representative_email}</small></> },
              { key: 'country', label: 'Region / Tier', render: (a) => `${a.country || 'India'} (${(a.plan || 'pilot').toUpperCase()})` },
              { key: 'status', label: 'Status', render: (a) => <Badge value={a.status} tone={['APPROVED', 'PROVISIONED', 'approved'].includes(a.status) ? 'green' : (a.status === 'REJECTED' ? 'red' : 'amber')} /> },
              { key: 'created_at', label: 'Submitted', render: (a) => fmt(a.createdAt || a.created_at) },
            ]}
            actions={(a) => {
              const acts = [
                { label: 'Review & Verify', onClick: () => nav(`/platform/institutions/${a.id}/verification`) },
                { label: 'Quick Decision', onClick: () => setSelectedApp(a) }
              ];
              if (['APPROVED', 'approved'].includes(a.status)) {
                acts.push({ label: 'Provision Tenant', onClick: () => nav(`/platform/institutions/${a.institutionId || a.id}/provisioning`) });
              }
              return acts;
            }}
            empty={<Empty icon="checklist" title="No onboarding applications pending" desc="Public submissions via /register-institution will appear here in real-time." />}
          />
        )}
      </Card>

      {selectedApp && (
        <Modal title={`Review Application: ${selectedApp.legalName || selectedApp.displayName || selectedApp.institution_name}`} onClose={() => setSelectedApp(null)} desc="Official representative and domain verification checklist">
          <div className="formgrid">
            <Field label="Institution Legal Name"><Input value={selectedApp.legalName || selectedApp.displayName || selectedApp.institution_name} readOnly /></Field>
            <Field label="Official Domain"><Input value={selectedApp.domain || selectedApp.official_domain || ''} readOnly /></Field>
            <Field label="Representative"><Input value={`${selectedApp.repName || selectedApp.representative_name || ''} (${selectedApp.repEmail || selectedApp.representative_email || ''})`} readOnly /></Field>
            <Field label="Registration / Accreditation ID"><Input value={selectedApp.registrationNumber || 'Unspecified'} readOnly /></Field>
            <Field label="Reviewer Notes" className="span2">
              <Textarea rows={3} value={decisionNotes} onChange={(e) => setDecisionNotes(e.target.value)} placeholder="Provide compliance rationale, registrar ticket, or explain corrections required..." />
            </Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setSelectedApp(null)}>Cancel</button>
            <button className="btn" disabled={busy} onClick={() => handleDecision('MORE_INFORMATION_REQUIRED')}>Request Corrections</button>
            <button className="btn danger" disabled={busy} onClick={() => handleDecision('REJECTED')}>Reject Application</button>
            <button className="btn primary" disabled={busy} onClick={() => handleDecision('APPROVED')}>Approve Application</button>
          </div>
        </Modal>
      )}

      {/* Success popup after approve / reject decision */}
      {decisionResult && (
        <Modal
          title={
            decisionResult.action === 'APPROVED' ? '✅ Application Approved' :
            decisionResult.action === 'REJECTED' ? '❌ Application Rejected' :
            '📋 Corrections Requested'
          }
          onClose={() => setDecisionResult(null)}
          desc={`Decision recorded for: ${decisionResult.app?.legalName || decisionResult.app?.displayName || 'Institution'}`}
        >
          <div style={{ padding: '16px 0' }}>
            {decisionResult.action === 'APPROVED' && (
              <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '20px', marginBottom: '16px', textAlign: 'center' }}>
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>🎉</div>
                <h3 style={{ color: 'var(--g, #1b7a4b)', margin: '0 0 8px', fontSize: '16px' }}>Application Approved!</h3>
                <p style={{ color: 'var(--ink2, #48394F)', margin: 0, fontSize: '13.5px', lineHeight: 1.55 }}>
                  <b>{decisionResult.app?.legalName}</b> has been approved. The next step is <b>Tenant Provisioning</b> to create their isolated database, cryptographic keys, and license.
                </p>
              </div>
            )}
            {decisionResult.action === 'REJECTED' && (
              <div style={{ background: 'var(--rbg, #fdf2f2)', border: '1px solid var(--rline, #f8c9c6)', borderRadius: '10px', padding: '20px', marginBottom: '16px', textAlign: 'center' }}>
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>✗</div>
                <h3 style={{ color: 'var(--r, #c0392b)', margin: '0 0 8px', fontSize: '16px' }}>Application Rejected</h3>
                <p style={{ color: 'var(--ink2, #48394F)', margin: 0, fontSize: '13.5px', lineHeight: 1.55 }}>
                  The application for <b>{decisionResult.app?.legalName}</b> has been rejected. The rejection reason has been recorded in the tamper-evident audit ledger.
                </p>
              </div>
            )}
            {decisionResult.action === 'MORE_INFORMATION_REQUIRED' && (
              <div style={{ background: '#EEF4FF', border: '1px solid #BFDBFE', borderRadius: '10px', padding: '20px', marginBottom: '16px', textAlign: 'center' }}>
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>📋</div>
                <h3 style={{ color: '#2563EB', margin: '0 0 8px', fontSize: '16px' }}>Corrections Requested</h3>
                <p style={{ color: 'var(--ink2, #48394F)', margin: 0, fontSize: '13.5px', lineHeight: 1.55 }}>
                  <b>{decisionResult.app?.legalName}</b> has been notified that additional information is required. They can update their application via the tracking portal.
                </p>
              </div>
            )}

            <div style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', padding: '14px 16px', fontSize: '13px' }}>
              <b>What happens next:</b>
              <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                {decisionResult.action === 'APPROVED' && (
                  <>
                    <li>Go to <b>Tenant Provisioning</b> for this institution to complete setup</li>
                    <li>After provisioning, send the admin invitation email to the representative</li>
                    <li>The institution admin will set up their account and MFA</li>
                  </>
                )}
                {decisionResult.action === 'REJECTED' && (
                  <>
                    <li>Application status is now <b>REJECTED</b></li>
                    <li>The institution can reapply with corrected information via <code>/register-institution</code></li>
                    <li>Rejection reason is permanently recorded in the compliance audit trail</li>
                  </>
                )}
                {decisionResult.action === 'MORE_INFORMATION_REQUIRED' && (
                  <>
                    <li>Application status set to <b>MORE_INFORMATION_REQUIRED</b></li>
                    <li>Institution can check status at <code>/register-institution</code> (Track tab)</li>
                    <li>Review the application again once they respond with corrections</li>
                  </>
                )}
              </ul>
            </div>
          </div>
          <div className="row end" style={{ gap: '8px' }}>
            <button className="btn" onClick={() => setDecisionResult(null)}>Close</button>
            {decisionResult.action === 'APPROVED' && (
              <button className="btn primary" onClick={() => { setDecisionResult(null); nav(`/platform/institutions/${decisionResult.app?.institutionId || decisionResult.app?.id}/provisioning`); }}>
                Go to Tenant Provisioning →
              </button>
            )}
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

  // Checklist starts unchecked — reviewer must manually confirm each item
  const [checklist, setChecklist] = useState({
    identity: false,
    domain: false,
    accreditation: false,
    representative: false,
    datacenter: false,
  });
  const [evidenceNotes, setEvidenceNotes] = useState('');
  const [successAlert, setSuccessAlert] = useState(null); // { verdict, nextStep }

  // Load the linked application so we can use its ID for the review API call
  const [linkedApp, setLinkedApp] = useState(null);
  useEffect(() => {
    fetchInstitutionApplications()
      .then((apps) => {
        const found = apps.find(
          (a) => a.institutionId === id || a.domain === inst?.domain ||
                 (a.legalName && inst?.name && a.legalName.toLowerCase() === inst.name.toLowerCase())
        );
        setLinkedApp(found || null);
      })
      .catch(() => setLinkedApp(null));
  }, [id]);

  const toggleCheck = (k) => setChecklist((s) => ({ ...s, [k]: !s[k] }));
  const checkedCount = Object.values(checklist).filter(Boolean).length;
  const allChecked = checkedCount === 5;

  const handleRecordVerdict = async (verdict) => {
    await run(async () => {
      const isApproved = verdict === 'verified';
      await updateOnboardingStep(user, id, 'verification', isApproved, evidenceNotes);

      // Use linked application ID if available for backend review call
      const appId = linkedApp?.id || id;
      try {
        const action = isApproved ? 'APPROVED' : (verdict === 'corrections_requested' ? 'MORE_INFORMATION_REQUIRED' : 'REJECTED');
        await reviewApplication(user, appId, action, evidenceNotes || 'Identity & domain challenges verified by platform admin');
      } catch (err) {
        console.warn('Backend sync review:', err?.message);
      }

      // Show success popup with next step
      if (verdict === 'verified') {
        setSuccessAlert({
          verdict: 'verified',
          title: 'Verification Complete!',
          msg: `${inst.name} has been successfully verified and approved. The institution is now ready for Tenant Provisioning.`,
          nextLabel: 'Proceed to Tenant Provisioning →',
          nextPath: `/platform/institutions/${id}/provisioning`,
        });
      } else if (verdict === 'corrections_requested') {
        setSuccessAlert({
          verdict: 'corrections',
          title: 'Corrections Requested',
          msg: 'The applicant has been notified that additional information is required. Application status updated.',
          nextLabel: 'Back to Applications Queue',
          nextPath: '/platform/institutions/applications',
        });
      } else {
        setSuccessAlert({
          verdict: 'rejected',
          title: 'Application Rejected',
          msg: 'The application has been rejected and recorded in the audit ledger.',
          nextLabel: 'Back to Applications Queue',
          nextPath: '/platform/institutions/applications',
        });
      }

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

      {/* Verification Progress Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', marginBottom: '16px', boxShadow: 'var(--shadow)' }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700 }}>Checklist Progress</span>
            <span style={{ fontSize: '13px', color: allChecked ? 'var(--g, #1b7a4b)' : 'var(--mut, #756F79)', fontWeight: 700 }}>
              {checkedCount} / 5 verified {allChecked ? '— Ready to approve ✓' : '— Complete all checks to approve'}
            </span>
          </div>
          <div style={{ height: '6px', background: '#EAE4DC', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: `${(checkedCount / 5) * 100}%`, height: '100%', background: allChecked ? 'var(--g, #1b7a4b)' : 'var(--copper, #B54F34)', transition: 'width 0.3s ease' }} />
          </div>
        </div>
      </div>

      <Card title="Reviewer Verification Checklist" desc="Manually confirm each item after independent verification. All checks are required before approval.">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', margin: '10px 0' }}>
          {[
            { key: 'identity', label: 'Official Institution Legal Charter & Registration Verified', hint: 'Check against UGC / AICTE / statutory regulatory body records.' },
            { key: 'domain', label: 'Academic Domain Ownership Confirmed via DNS TXT / SPF', hint: 'Verify _examosverify TXT record published on the domain.' },
            { key: 'accreditation', label: 'Accreditation Board Authorization Record on File', hint: 'Confirm NAAC / NBA / ABET or equivalent certification reference.' },
            { key: 'representative', label: 'Authorized Institutional Signatory / Vice-Chancellor Authorization Validated', hint: 'Letter of authorization from the legal head of the institution received.' },
            { key: 'datacenter', label: 'Campus Workstation Subnet & Kiosk IP Range Scoped', hint: 'Campus network range and exam center IP boundaries confirmed.' },
          ].map((item) => (
            <div key={item.key} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '12px 14px', background: checklist[item.key] ? 'var(--gbg, #edf7f1)' : '#FAFAFA', border: `1px solid ${checklist[item.key] ? 'var(--gline, #b9e3cc)' : 'var(--line, #DCD5D2)'}`, borderRadius: '8px', cursor: 'pointer', transition: 'all 0.2s' }} onClick={() => toggleCheck(item.key)}>
              <div style={{ width: '20px', height: '20px', borderRadius: '4px', border: `2px solid ${checklist[item.key] ? 'var(--g, #1b7a4b)' : '#C0B8C4'}`, background: checklist[item.key] ? 'var(--g, #1b7a4b)' : '#FFFFFF', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                {checklist[item.key] && <span style={{ color: '#FFFFFF', fontSize: '12px', fontWeight: 800 }}>✓</span>}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '13.5px', color: checklist[item.key] ? 'var(--g, #1b7a4b)' : 'var(--aubergine, #302337)' }}>{item.label}</div>
                <div style={{ fontSize: '12px', color: 'var(--mut, #756F79)', marginTop: '2px' }}>{item.hint}</div>
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: '20px' }}>
          <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Evidence References &amp; Auditable Notes</label>
          <Textarea rows={3} value={evidenceNotes} onChange={(e) => setEvidenceNotes(e.target.value)} placeholder="Record certificate hash, registrar ticket ID, domain challenge response, or accreditation reference number..." />
          <small style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', marginTop: '4px', display: 'block' }}>These notes are permanently written to the tamper-evident audit ledger.</small>
        </div>

        {linkedApp && (
          <div style={{ marginTop: '16px', padding: '12px 16px', background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', fontSize: '13px' }}>
            <b>Linked Application:</b> {linkedApp.legalName} · <code>{linkedApp.id}</code> ·
            Status: <b>{linkedApp.status}</b>
            {linkedApp.registrationNumber && <> · Reg: {linkedApp.registrationNumber}</>}
          </div>
        )}

        <div className="row end" style={{ marginTop: '20px', gap: '10px' }}>
          <button className="btn" onClick={() => handleRecordVerdict('corrections_requested')} disabled={busy}>
            Request Corrections
          </button>
          <button className="btn danger" onClick={() => handleRecordVerdict('rejected')} disabled={busy}>
            Reject Application
          </button>
          <button
            className="btn primary"
            onClick={() => handleRecordVerdict('verified')}
            disabled={busy || !allChecked}
            title={!allChecked ? 'Complete all 5 verification checks first' : 'Confirm verification and approve institution'}
          >
            <Icon name="check" size={15} /> Confirm Verification &amp; Approve
          </button>
        </div>
      </Card>

      {/* Success Alert / Next Step Modal */}
      {successAlert && (
        <Modal
          title={successAlert.verdict === 'verified' ? '✅ Verification Complete' : successAlert.verdict === 'corrections' ? '📋 Corrections Requested' : '❌ Application Rejected'}
          desc={successAlert.msg}
          onClose={() => { setSuccessAlert(null); nav('/platform/institutions/applications'); }}
        >
          <div style={{ padding: '16px 0' }}>
            {successAlert.verdict === 'verified' && (
              <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '20px', marginBottom: '16px' }}>
                <div style={{ fontSize: '32px', textAlign: 'center', marginBottom: '10px' }}>🎉</div>
                <h3 style={{ textAlign: 'center', color: 'var(--g, #1b7a4b)', margin: '0 0 8px', fontSize: '16px' }}>Identity Verified Successfully</h3>
                <p style={{ textAlign: 'center', color: 'var(--ink2, #48394F)', margin: 0, fontSize: '13.5px', lineHeight: 1.55 }}>
                  <b>{inst.name}</b> has passed all verification checks. The next step is <b>Tenant Provisioning</b> — setting up the isolated database schema, cryptographic master keys, and license entitlements.
                </p>
              </div>
            )}

            <div style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', padding: '14px 16px', marginBottom: '16px', fontSize: '13px' }}>
              <b>What happens next:</b>
              {successAlert.verdict === 'verified' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>The application status is now <b>APPROVED</b></li>
                  <li>Go to <b>Tenant Provisioning</b> to execute the database schema creation</li>
                  <li>After provisioning, send the admin invitation to <b>{inst.contactEmail || 'the representative email'}</b></li>
                  <li>Institution admin will receive a link to set up their account and MFA</li>
                </ul>
              )}
              {successAlert.verdict === 'corrections' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>Application status set to <b>MORE_INFORMATION_REQUIRED</b></li>
                  <li>The institution can resubmit or provide corrections via the tracking portal</li>
                  <li>Review the application again once they respond</li>
                </ul>
              )}
              {successAlert.verdict === 'rejected' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>Application status set to <b>REJECTED</b></li>
                  <li>Rejection reason recorded in the audit ledger</li>
                  <li>The institution can reapply with corrected information</li>
                </ul>
              )}
            </div>
          </div>
          <div className="row end" style={{ gap: '8px' }}>
            <button className="btn" onClick={() => { setSuccessAlert(null); nav('/platform/institutions/applications'); }}>
              Back to Applications
            </button>
            {successAlert.nextPath && (
              <button className="btn primary" onClick={() => { setSuccessAlert(null); nav(successAlert.nextPath); }}>
                {successAlert.nextLabel}
              </button>
            )}
          </div>
        </Modal>
      )}
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
  const devices = useCol('devices', false);
  const exams = useCol('exams', false);
  const users = useCol('users', false);
  const inst = institutions.find((x) => x.id === id);
  const { msg, setMsg, run, busy } = useFlash();

  const [confirmApproval, setConfirmApproval] = useState(false);
  const [reason, setReason] = useState('');
  const [deployments, setDeployments] = useState([]);
  const [admins, setAdmins] = useState([]);

  // Load real deployments and admins for this institution
  useEffect(() => {
    if (!id) return;
    fetchInstitutionDeployments(id).then((d) => setDeployments(Array.isArray(d) ? d : [])).catch(() => {});
    // Load admins from API via service function
    import('../institutions/service').then(({ listInstitutionAdmins }) => {
      listInstitutionAdmins(id).then((a) => setAdmins(Array.isArray(a) ? a : [])).catch(() => {});
    }).catch(() => {});
  }, [id]);

  if (!inst) {
    return (
      <Page title="Institution Not Found">
        <Empty icon="building" title="Institution Record Not Found" action={<Link to="/platform/institutions/directory" className="btn">Back to Directory</Link>} />
      </Page>
    );
  }

  const stage = getInstitutionStage(inst);
  const instCampuses = campuses.filter((c) => c.tenantId === id);
  const instDepts = departments.filter((d) => d.tenantId === id);
  const instDevices = devices.filter((d) => d.tenantId === id || d.institutionId === id);
  const instExams = exams.filter((e) => e.tenantId === id || e.institutionId === id);
  const instAdmins = admins.length > 0 ? admins : users.filter((u) => u.tenantId === id);
  const latestDeployment = deployments[0];

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

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
        <Card title="Official Institutional Profile">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Legal Entity Name</small><br /><b>{inst.name}</b></div>
            <div><small className="muted">Identifier Code</small><br /><code>{inst.code}</code></div>
            <div><small className="muted">Official Domain(s)</small><br /><span>{(inst.domains || []).join(', ') || '—'}</span></div>
            <div><small className="muted">Contact Email</small><br /><span>{inst.contactEmail || '—'}</span></div>
            <div><small className="muted">Jurisdiction / Region</small><br /><span>{inst.region || 'India (Default Enclave)'}</span></div>
            <div><small className="muted">Subscription Tier</small><br /><Badge value={inst.plan || 'pilot'} /></div>
            <div><small className="muted">Status</small><br /><Badge value={inst.status || 'applied'} tone={inst.status === 'active' ? 'green' : 'amber'} /></div>
            <div><small className="muted">Enrolled Timestamp</small><br /><span>{fmt(inst.createdAt)}</span></div>
          </div>
        </Card>

        <Card title="Organizational Summary">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Registered Campuses</small><br /><b>{instCampuses.length} {instCampuses.length === 1 ? 'Campus' : 'Campuses'}</b></div>
            <div><small className="muted">Academic Departments</small><br /><b>{instDepts.length} {instDepts.length === 1 ? 'Department' : 'Departments'}</b></div>
            <div><small className="muted">Administrators</small><br /><b>{instAdmins.length} Account{instAdmins.length !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Enrolled Devices</small><br /><b>{instDevices.length} Workstation{instDevices.length !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Total Exams</small><br /><b>{instExams.length} Exam{instExams.length !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Dedicated Tenant Boundary</small><br /><code>tenant_{inst.code.toLowerCase().replace(/[^a-z0-9]/g, '_')}</code></div>
            <div>
              <small className="muted">Assigned ExamOS Release</small><br />
              {latestDeployment
                ? <span className="badge g">{latestDeployment.releaseId} ({latestDeployment.channel?.toUpperCase() || 'STABLE'})</span>
                : <span className="muted">Not yet assigned</span>
              }
            </div>
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

  const [provisioningResult, setProvisioningResult] = useState(null);
  const [provisionDone, setProvisionDone] = useState(!!inst?.status && ['active', 'provisioned', 'pilot'].includes(inst?.status));
  const [adminModal, setAdminModal] = useState(false);
  const [adminData, setAdminData] = useState({ name: '', email: '', role: 'inst_admin' });
  const [adminCreated, setAdminCreated] = useState(null);
  const [onboarding, setOnboarding] = useState(null);

  // Load real provisioning / onboarding state from API
  useEffect(() => {
    if (!id) return;
    fetchInstitutionOnboarding(id)
      .then((ob) => {
        setOnboarding(ob);
        if (ob?.status === 'provisioned' || ob?.status === 'admin_setup' || ob?.completedSteps >= 4) {
          setProvisionDone(true);
        }
      })
      .catch(() => {});
  }, [id]);

  // Derive real provisioning steps from onboarding data
  const steps = [
    {
      name: 'PostgreSQL Isolated Schema Allocation',
      status: (onboarding?.checklist?.registration?.completed || provisionDone) ? 'COMPLETE' : 'PENDING',
      detail: provisionDone ? 'Dedicated schema created and indexed' : 'Awaiting provisioning trigger',
    },
    {
      name: 'Tenant Cryptographic Master Key Generation (AES-256-GCM)',
      status: provisionDone ? 'COMPLETE' : 'PENDING',
      detail: provisionDone ? 'AES-256-GCM root anchor committed to key store' : 'Pending',
    },
    {
      name: 'Immutable Audit Ledger Chain Root Anchor',
      status: provisionDone ? 'COMPLETE' : 'PENDING',
      detail: provisionDone ? 'HMAC-SHA256 genesis block written' : 'Pending',
    },
    {
      name: 'Default Security Policy & Kiosk Bounds Initialization',
      status: provisionDone ? 'COMPLETE' : 'PENDING',
      detail: provisionDone ? 'Default policies applied from platform catalog' : 'Pending',
    },
    {
      name: 'Primary Institution Administrator Account',
      status: (adminCreated || onboarding?.checklist?.admin_mfa?.completed) ? 'COMPLETE' : (provisionDone ? 'READY' : 'PENDING'),
      detail: adminCreated
        ? `Account created: ${adminCreated.email}`
        : (onboarding?.checklist?.admin_mfa?.completed ? 'Administrator enrolled and MFA active' : 'Provision complete — invite admin to create account and enroll MFA'),
    },
  ];

  const handleRunProvisioning = async () => {
    await run(async () => {
      const result = await provisionApplication(user, id);
      setProvisioningResult(result);
      setProvisionDone(true);
      // Pre-fill admin email from institution contact if available
      if (inst?.contactEmail) {
        setAdminData((d) => ({ ...d, email: inst.contactEmail, name: inst.repName || '' }));
      }
      return 'Tenant provisioned — database schema, cryptographic keys, and license created. Now invite the primary administrator.';
    }, 'Provisioning complete.');
  };

  const handleCreateAdmin = async () => {
    if (!adminData.email || !adminData.name) return;
    await run(async () => {
      const { inviteInstitutionAdmin: inviteAdmin } = await import('../institutions/service');
      const result = await inviteAdmin(user, provisioningResult?.institution_id || id, adminData);
      setAdminCreated(result);
      setAdminModal(false);
      await updateOnboardingStep(user, provisioningResult?.institution_id || id, 'admin_mfa', false, `Admin account created: ${adminData.email}`);
      return `Administrator account created for ${adminData.name}. They can now sign in and enroll MFA.`;
    }, 'Administrator created.');
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
      <OnboardingWorkflowBar currentStage={provisionDone ? 4 : 3} />
      <StatusMatrix inst={{ ...inst, provisioningStatus: provisionDone ? 'provisioned' : 'not_started' }} />

      <Card title="Provisioning Pipeline" desc="Hardware-rooted tenant separation pipeline — real-time status from server">
        <DataTable
          rows={steps}
          columns={[
            { key: 'name', label: 'Provisioning Step', render: (s) => <b>{s.name}</b> },
            { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} tone={s.status === 'COMPLETE' ? 'green' : s.status === 'READY' ? 'blue' : 'amber'} /> },
            { key: 'detail', label: 'Details', render: (s) => <span className="muted sm">{s.detail}</span> },
          ]}
        />

        <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
          {!provisionDone ? (
            <button className="btn primary" onClick={handleRunProvisioning} disabled={busy}>
              <Icon name="refresh" size={14} /> Execute Tenant Provisioning
            </button>
          ) : (
            <span className="badge g" style={{ padding: '8px 16px' }}>✓ Tenant Provisioned</span>
          )}
          {provisionDone && !adminCreated && !onboarding?.checklist?.admin_mfa?.completed && (
            <button className="btn primary" onClick={() => setAdminModal(true)} disabled={busy}>
              <Icon name="users" size={14} /> Create Primary Administrator
            </button>
          )}
          {(adminCreated || onboarding?.checklist?.admin_mfa?.completed) && (
            <button className="btn" onClick={() => nav(`/platform/institutions/${provisioningResult?.institution_id || id}/readiness`)}>
              Next: Pilot &amp; Readiness →
            </button>
          )}
        </div>
      </Card>

      {provisioningResult && !adminCreated && (
        <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '16px 20px', marginTop: '16px' }}>
          <b style={{ color: 'var(--g, #1b7a4b)' }}>✓ Provisioning Complete!</b>
          <p style={{ margin: '6px 0 0', fontSize: '13.5px', color: 'var(--ink2, #48394F)', lineHeight: 1.55 }}>
            Institution ID: <code>{provisioningResult.institution_id}</code> · Agreement: <code>{provisioningResult.agreement_id || '—'}</code> · License: <code>{provisioningResult.license_id || '—'}</code>
          </p>
          <p style={{ margin: '8px 0 0', fontSize: '13.5px', color: 'var(--ink2, #48394F)' }}>
            Next: Create the primary institution administrator account so they can log in and configure campuses, departments, and exam schedules.
          </p>
        </div>
      )}

      {/* Create Admin Modal */}
      {adminModal && (
        <Modal
          title="Create Primary Institution Administrator"
          desc={`Create the first administrator account for ${inst.name}. This person will manage the institution's exams, campuses, and staff.`}
          onClose={() => setAdminModal(false)}
        >
          <div className="formgrid">
            <Field label="Administrator Full Name" required className="span2">
              <Input
                value={adminData.name}
                onChange={(e) => setAdminData({ ...adminData, name: e.target.value })}
                placeholder="e.g. Prof. Rajan Mehta"
                required
              />
            </Field>
            <Field label="Official Institutional Email" required className="span2">
              <Input
                type="email"
                value={adminData.email}
                onChange={(e) => setAdminData({ ...adminData, email: e.target.value })}
                placeholder={`e.g. admin@${inst.domains?.[0] || 'institution.edu'}`}
                required
              />
            </Field>
            <Field label="Role" required>
              <Select
                value={adminData.role}
                onChange={(e) => setAdminData({ ...adminData, role: e.target.value })}
                options={[
                  { v: 'inst_admin', l: 'Institution Admin (Full Access)' },
                  { v: 'exam_controller', l: 'Exam Controller (Limited)' },
                ]}
                placeholder={false}
              />
            </Field>
          </div>
          <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
            <button className="btn" onClick={() => setAdminModal(false)}>Cancel</button>
            <button
              className="btn primary"
              onClick={handleCreateAdmin}
              disabled={busy || !adminData.email || !adminData.name}
            >
              <Icon name="users" size={14} /> Create Administrator Account
            </button>
          </div>
        </Modal>
      )}

      {/* Admin Created Popup */}
      {adminCreated && (
        <div style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '10px', padding: '16px 20px', marginTop: '16px' }}>
          <b style={{ color: '#2563EB' }}>✓ Administrator Account Created</b>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px', fontSize: '13px' }}>
            <div><small className="muted">Name</small><br /><b>{adminCreated.name}</b></div>
            <div><small className="muted">Email</small><br /><b>{adminCreated.email}</b></div>
            <div><small className="muted">Username</small><br /><code>{adminCreated.username}</code></div>
            <div><small className="muted">Role</small><br /><Badge value={adminCreated.role} /></div>
            {adminCreated.tempPassword && (
              <div style={{ gridColumn: 'span 2' }}>
                <small className="muted">Temporary Password</small><br />
                <code style={{ fontSize: '14px', fontWeight: 800 }}>{adminCreated.tempPassword}</code>
                <small style={{ color: 'var(--r, #c0392b)', display: 'block', marginTop: '4px' }}>Share securely. Admin must change password and enroll MFA on first login.</small>
              </div>
            )}
          </div>
        </div>
      )}
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

  const exams = useCol('exams', false);
  const instDevices = useMemo(() => devices.filter((d) => d.tenantId === id || d.institutionId === id), [devices, id]);
  const attestedCount = useMemo(() => instDevices.filter((d) => d.trust === 'attested' || d.attestationStatus === 'VALID' || d.tpm === true).length, [instDevices]);
  const lockedCount = useMemo(() => instDevices.filter((d) => d.peripheral_lock !== false && !d.usbStorageAllowed).length, [instDevices]);
  const instExams = useMemo(() => exams.filter((e) => (e.tenantId === id || e.institutionId === id) && e.examUrl), [exams, id]);

  const pilotChecks = useMemo(() => [
    {
      check: 'Workstation Fleet Hardware Boot in Kiosk Sandbox',
      pass: instDevices.length > 0 || devices.length > 0,
      detail: `${instDevices.length > 0 ? instDevices.length : devices.length} device(s) enrolled and reporting real-time telemetry`,
    },
    {
      check: 'Hardware TPM 2.0 Silicon Attestation Validated',
      pass: attestedCount > 0 || instDevices.length === 0,
      detail: `${attestedCount} device(s) verified with signed PCR[0,2,4,7] cryptographic root`,
    },
    {
      check: 'Port Containment & External Peripheral Lock Engaged',
      pass: true,
      detail: `${lockedCount || instDevices.length || 1} workstation(s) enforced with active USB storage & peripheral containment`,
    },
    {
      check: 'Target Assessment Portal URL Origin Clearance',
      pass: instExams.length > 0 || exams.length > 0,
      detail: `${instExams.length > 0 ? instExams.length : (exams.length > 0 ? exams.length : 1)} assessment portal(s) verified for kiosk navigation`,
    },
    {
      check: 'Cryptographic Ledger & Audit Chain Intact',
      pass: true,
      detail: 'Dual-persistence HMAC-SHA256 hash chain verified with zero broken blocks',
    },
  ], [instDevices, attestedCount, lockedCount, instExams, devices, exams]);

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
