import { useState, useMemo, useEffect } from 'react';
import { Link, useNavigate, useParams, useLocation } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import * as Api from '../../core/api/services';
import { can } from '../../core/security/rbac';
import { fmt, ago } from '../../core/ui/format';
import {
  Page, Card, StatGrid, Stat, Alert, Empty, Loading,
  DataTable, Badge, Modal, ActionDialog, useFlash, Flash,
  Icon, Field, Input, Select, Textarea, Checkbox
} from '../../core/ui/kit';
import {
  OnboardingWorkflowBar
} from '../institutions/onboardingWorkflow';
import { getApplicationLifecycle } from '../institutions/applicationLifecycle';
import {
  createInstitution, setInstitutionStatus,
  fetchInstitutionApplications, fetchInstitutionApplication, reviewApplication, provisionApplication,
  fetchInstitutionAgreements, fetchInstitutionLicense, fetchInstitutionDeployments,
  fetchInstitutionOnboarding, updateOnboardingStep, fetchInstitutionPilotReadiness
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
        Status: <b>{inst?.status?.toUpperCase() || 'UNKNOWN'}</b>
      </span>
    </div>
  );
}

function useInstitutionStats(institutions, enabled = true) {
  const [statsByInstitution, setStatsByInstitution] = useState({});
  const [loadingStats, setLoadingStats] = useState(false);
  const [statsError, setStatsError] = useState('');
  const institutionIds = institutions.map((institution) => institution.id).filter(Boolean).join(',');

  useEffect(() => {
    const ids = enabled && institutionIds ? institutionIds.split(',') : [];
    if (!ids.length) {
      setStatsByInstitution({});
      setStatsError('');
      setLoadingStats(false);
      return undefined;
    }

    let active = true;
    setLoadingStats(true);
    setStatsError('');
    Promise.all(ids.map(async (id) => {
      const stats = await Api.getInstitutionStats(id);
      const countFields = ['campuses', 'users', 'devices', 'exams', 'openIncidents'];
      if (!stats || countFields.some((field) => typeof stats[field] !== 'number')) {
        throw new Error(`The backend returned invalid institution metrics for ${id}.`);
      }
      return [id, stats];
    }))
      .then((entries) => {
        if (active) setStatsByInstitution(Object.fromEntries(entries));
      })
      .catch((error) => {
        if (active) {
          setStatsByInstitution({});
          setStatsError(error?.message || 'Failed to load institution metrics from the backend.');
        }
      })
      .finally(() => {
        if (active) setLoadingStats(false);
      });

    return () => { active = false; };
  }, [enabled, institutionIds]);

  return { statsByInstitution, loadingStats, statsError };
}

/* =====================================================================
   PAGE 1 — Institution Overview (/platform/institutions)
===================================================================== */
export function PlatformInstitutionsOverviewPage() {
  const nav = useNavigate();
  const { user } = useAuth();
  const isPlatformOwner = user?.role === 'superadmin';
  const { tenants: institutions, loading: institutionsLoading, error: institutionsError } = useTenant();
  const { statsByInstitution, loadingStats, statsError } = useInstitutionStats(institutions, isPlatformOwner);
  const [apps, setApps] = useState([]);
  const [loadingApps, setLoadingApps] = useState(true);
  const [appsError, setAppsError] = useState('');

  useEffect(() => {
    if (!isPlatformOwner) {
      setApps([]);
      setAppsError('Platform owner authorization is required to review institution applications.');
      setLoadingApps(false);
      return undefined;
    }
    let active = true;
    fetchInstitutionApplications()
      .then((data) => {
        if (!Array.isArray(data)) throw new Error('The backend returned an unexpected applications response.');
        if (active) setApps(data);
      })
      .catch((error) => {
        if (active) {
          setApps([]);
          setAppsError(error?.message || 'Failed to load institution applications.');
        }
      })
      .finally(() => { if (active) setLoadingApps(false); });
    return () => { active = false; };
  }, [isPlatformOwner]);

  if (!isPlatformOwner) {
    return <Page title="Platform Institutions Overview"><Alert tone="danger" title="Access restricted">Platform owner authorization is required for this page.</Alert></Page>;
  }

  const pendingApps = apps.filter((a) => ['pending', 'submitted'].includes(a.status?.toLowerCase()));
  const awaitingVerification = apps.filter((a) => ['under_review', 'pending'].includes(a.status?.toLowerCase()));
  const activeCount = institutions.filter((i) => i.status?.toLowerCase() === 'active').length;
  const pilotCount = institutions.filter((i) => i.status?.toLowerCase() === 'pilot' || i.plan?.toLowerCase() === 'pilot').length;
  const suspendedCount = institutions.filter((i) => i.status?.toLowerCase() === 'suspended').length;
  const openAlerts = Object.values(statsByInstitution).reduce((total, stats) => total + stats.openIncidents, 0);

  return (
    <Page
      title="Platform Institutions Overview"
      desc="ExamOS Master Console: Onboard, verify, approve, provision, and govern accredited institutional testing enclaves."
      breadcrumb={<div className="crumbs-inline"><span>Platform Administration</span><Icon name="arrow" size={12} /><span>Overview</span></div>}
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to="/platform/institutions/applications" className="btn">
            <Icon name="checklist" size={15} /> Applications Queue ({appsError ? 'Unavailable' : pendingApps.length})
          </Link>
          <Link to="/platform/institutions/directory" className="btn primary">
            <Icon name="building" size={15} /> Institution Directory
          </Link>
        </div>
      }
    >
      <StatGrid cols={4}>
        <Stat label="Total Institutions" value={institutions.length} icon="building" sub={`${activeCount} Active · ${pilotCount} In Pilot`} />
        <Stat label="Pending Applications" value={loadingApps ? '…' : appsError ? 'Unavailable' : pendingApps.length} tone={pendingApps.length ? 'amber' : 'green'} icon="checklist" sub="Awaiting Review" to="/platform/institutions/applications" />
        <Stat label="Awaiting Verification" value={loadingApps ? '…' : appsError ? 'Unavailable' : awaitingVerification.length} tone="blue" icon="shield" sub="Identity & Domain Checks" />
        <Stat label="Operational Alerts" value={loadingStats ? '…' : statsError ? 'Unavailable' : openAlerts} tone={openAlerts ? 'red' : 'green'} icon="alert" sub="Open incidents reported by institution APIs" />
      </StatGrid>
      {(institutionsError || statsError || appsError) && (
        <Alert tone="danger" title="Platform data unavailable">
          {[institutionsError, statsError, appsError].filter(Boolean).join(' ')}
        </Alert>
      )}
      {institutionsLoading && <Loading label="Loading institutions from backend..." />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', margin: '20px 0' }}>
        <Card title="Quick Onboarding Actions" desc="Launch institution governance workflows">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <Link to="/platform/institutions/applications" className="btn" style={{ justifyContent: 'flex-start' }}>
              <Icon name="checklist" size={16} /> Process Onboarding Applications ({appsError ? 'count unavailable' : `${pendingApps.length} pending`})
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
              <b>{loadingStats ? '…' : statsError ? 'Unavailable' : Object.values(statsByInstitution).reduce((total, stats) => total + stats.devices, 0)}</b>
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
  const { tenants: institutions, loading: institutionsLoading, error: institutionsError } = useTenant();
  const { statsByInstitution, loadingStats, statsError } = useInstitutionStats(institutions);

  return (
    <Page
      title="Institution Directory"
      desc="Search, filter, and inspect verified institutions, operational states, and onboarding records."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><span>Directory</span></div>}
    >
      {(institutionsError || statsError) && <Alert tone="danger" title="Directory data unavailable">{institutionsError || statsError}</Alert>}
      {institutionsLoading && <Loading label="Loading institutions from backend..." />}
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
          { key: 'users', label: 'Users', render: (t) => loadingStats ? '…' : statsByInstitution[t.id]?.users ?? '—' },
          { key: 'devices', label: 'Devices', render: (t) => loadingStats ? '…' : statsByInstitution[t.id]?.devices ?? '—' },
          { key: 'exams', label: 'Exams', render: (t) => loadingStats ? '…' : statsByInstitution[t.id]?.exams ?? '—' },
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
  const isPlatformOwner = user?.role === 'superadmin';
  const { msg, setMsg, run, busy } = useFlash();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [appsError, setAppsError] = useState('');

  const loadApps = async () => {
    if (!isPlatformOwner) {
      setApps([]);
      setAppsError('Platform owner authorization is required to review institution applications.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setAppsError('');
    try {
      const data = await fetchInstitutionApplications();
      if (!Array.isArray(data)) throw new Error('The backend returned an unexpected applications response.');
      setApps(data);
    } catch (error) {
      setApps([]);
      setAppsError(error?.message || 'Failed to load institution applications.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isPlatformOwner) loadApps();
    else {
      setAppsError('Platform owner authorization is required to review institution applications.');
      setLoading(false);
    }
  }, [isPlatformOwner]);

  if (!isPlatformOwner) {
    return <Page title="Onboarding Applications"><Alert tone="danger" title="Access restricted">Platform owner authorization is required to review institution applications.</Alert></Page>;
  }

  return (
    <Page
      title="Onboarding Applications"
      desc="Review new institutional registrations, domain authenticity, and representative authorizations."
      actions={<button className="btn" onClick={loadApps} disabled={loading}><Icon name="refresh" size={14} /> Retry / Refresh</button>}
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><span>Applications</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {appsError && <Alert tone="danger" title="Unable to load applications">{appsError}</Alert>}
      <StatGrid cols={4}>
        <Stat label="Total Applications" value={loading ? '…' : appsError ? 'Unavailable' : apps.length} icon="checklist" />
        <Stat label="Under Review" value={loading ? '…' : appsError ? 'Unavailable' : apps.filter((a) => ['SUBMITTED', 'UNDER_REVIEW', 'pending', 'under_review'].includes(a.status)).length} tone="amber" icon="pulse" />
        <Stat label="Approved / Provisioned" value={loading ? '…' : appsError ? 'Unavailable' : apps.filter((a) => ['APPROVED', 'PROVISIONED', 'approved', 'provisioned'].includes(a.status)).length} tone="green" icon="check" />
        <Stat label="Action Required" value={loading ? '…' : appsError ? 'Unavailable' : apps.filter((a) => ['MORE_INFORMATION_REQUIRED', 'corrections_requested'].includes(a.status)).length} tone="blue" icon="alert" />
      </StatGrid>

      <Card title="Applications Queue" desc="Review institutional submissions and record compliance verdicts">
        {loading ? <Loading label="Loading applications..." /> : appsError ? <Empty title="Applications unavailable" desc={appsError} /> : (
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
              { key: 'country', label: 'Region / Tier', render: (a) => `${a.country || '—'} (${(a.plan || '—').toUpperCase()})` },
              { key: 'status', label: 'Lifecycle stage', render: (a) => {
                const lifecycle = getApplicationLifecycle(a.status, a.institutionStatus, a.adminSetupComplete);
                const status = String(a.status || '').toUpperCase();
                return <Badge value={lifecycle.stage} tone={status === 'REJECTED' ? 'red' : lifecycle.stage === 'Authorized for live operations' ? 'green' : 'amber'} />;
              } },
              { key: 'created_at', label: 'Submitted', render: (a) => fmt(a.createdAt || a.created_at) },
            ]}
            actions={(a) => {
              const status = String(a.status || '').toUpperCase();
              const acts = ['PROVISIONED', 'REJECTED'].includes(status) ||
                (status === 'APPROVED' && a.verificationComplete)
                ? []
                : [{ label: 'Review & Verify', onClick: () => nav(`/platform/institutions/${a.id}/verification`) }];
              if (status === 'APPROVED' && a.verificationComplete) {
                acts.push({ label: 'Provision Tenant', onClick: () => nav(`/platform/institutions/${a.institutionId || a.id}/provisioning`) });
              }
              return acts;
            }}
            empty={<Empty icon="checklist" title="No institution applications found" />}
          />
        )}
      </Card>

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
  const { tenantId, tenants: institutions, setTenantId } = useTenant();
  const targetId = (paramId && paramId !== ':id') ? paramId : tenantId;
  const isApp = Boolean(targetId?.startsWith('app_'));

  const [appData, setAppData] = useState(null);
  const [institutionData, setInstitutionData] = useState(null);
  const [appLoading, setAppLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [dnsProbe, setDnsProbe] = useState(null);

  // Load the application or institution directly from its backend endpoint.
  useEffect(() => {
    let active = true;
    setAppLoading(true);
    setLoadError('');
    setAppData(null);
    setInstitutionData(null);
    if (!targetId) {
      setAppLoading(false);
      setLoadError('Institution or application ID is unavailable.');
      return () => { active = false; };
    }

    const request = isApp ? fetchInstitutionApplication(targetId) : Api.getInstitution(targetId);
    request
      .then((data) => {
        if (!data || !data.id) throw new Error(`The ${isApp ? 'application' : 'institution'} was not found.`);
        if (!active) return;
        if (isApp) setAppData(data);
        else setInstitutionData(data);
      })
      .catch((error) => {
        if (active) setLoadError(error?.message || `Failed to load the ${isApp ? 'application' : 'institution'} from the backend.`);
      })
      .finally(() => {
        if (active) setAppLoading(false);
      });

    return () => { active = false; };
  }, [targetId, isApp]);

  // Unified institution/applicant profile
  const inst = useMemo(() => {
    if (isApp) {
      if (appData) {
        const cleanDom = (appData.domain || '').replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
        return {
          id: appData.id,
          name: appData.legalName || appData.displayName || appData.id,
          legalName: appData.legalName || '',
          displayName: appData.displayName || '',
          code: appData.displayName || appData.id,
          domain: cleanDom,
          rawDomain: appData.domain || '',
          targetExamUrl: appData.targetExamUrl || '',
          registrationNumber: appData.registrationNumber || '',
          repEmail: appData.repEmail || '',
          repName: appData.repName || '',
          repRole: appData.repRole || '',
          repPhone: appData.repPhone || '',
          address: appData.address || '',
          country: appData.country || '',
          state: appData.state || '',
          campusCount: appData.campusCount ?? null,
          studentCount: appData.studentCount ?? null,
          deviceCount: appData.deviceCount ?? null,
          deploymentModel: appData.deploymentModel || '',
          hardwareProfile: appData.hardwareProfile || '',
          plan: appData.plan || '',
          status: (appData.status || '').toLowerCase(),
          entityType: appData.entityType || '',
          institutionId: appData.institutionId || '',
          reviewNotes: appData.reviewNotes || '',
          createdAt: appData.createdAt,
          isApplication: true,
        };
      }
      return null;
    }
    return institutionData || institutions.find((institution) => institution.id === targetId) || null;
  }, [isApp, appData, institutionData, institutions, targetId]);

  const id = targetId;
  const { msg, setMsg, run, busy } = useFlash();

  // One-time verification: detect if already approved or provisioned
  const [unlockedForEdit, setUnlockedForEdit] = useState(false);
  const isSuperAdmin = user?.role === 'superadmin' || user?.role === 'platform_owner';
  const isAlreadyApproved = (!unlockedForEdit) && ['approved', 'provisioned'].includes(inst?.status?.toLowerCase());
  const isRejected = isApp && inst?.status?.toLowerCase() === 'rejected';
  const isProvisioned = inst?.status?.toLowerCase() === 'provisioned' || !!inst?.institutionId;
  const [overrideModal, setOverrideModal] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [checklist, setChecklist] = useState({
    identity: false,
    domain: false,
    accreditation: false,
    representative: false,
    datacenter: false,
  });

  const [evidenceNotes, setEvidenceNotes] = useState(inst?.reviewNotes || '');
  const [successAlert, setSuccessAlert] = useState(null);
  const [decisionError, setDecisionError] = useState('');

  useEffect(() => {
    setEvidenceNotes(inst?.reviewNotes || '');
  }, [inst?.reviewNotes]);

  useEffect(() => {
    if (!isApp || !appData || !appData.reviewChecklist || typeof appData.reviewChecklist !== 'object') return;
    setChecklist({
      identity: appData.reviewChecklist.identity === true,
      domain: appData.reviewChecklist.domain === true,
      accreditation: appData.reviewChecklist.accreditation === true,
      representative: appData.reviewChecklist.representative === true,
      datacenter: appData.reviewChecklist.datacenter === true,
    });
  }, [isApp, appData?.id]);

  const toggleCheck = (k) => setChecklist((s) => ({ ...s, [k]: !s[k] }));
  const checkedCount = Object.values(checklist).filter(Boolean).length;
  const allChecked = checkedCount === 5;

  // Domain security analysis
  const repDomain = (inst?.repEmail || '').split('@')[1] || '';
  const isWebmail = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com'].includes(repDomain.toLowerCase());
  const isMatchingDomain = Boolean(inst?.domain && repDomain
    && (repDomain.toLowerCase() === inst.domain.toLowerCase()
      || repDomain.toLowerCase().endsWith(`.${inst.domain.toLowerCase()}`)));

  // Live DNS TXT Challenge Probe
  const handleRunDnsProbe = async () => {
    if (!inst?.domain) return;
    const probeHost = `_examosverify.${inst.domain}`;
    setDnsProbe({ probing: true, msg: `Querying DNS over HTTPS for ${probeHost}...` });
    try {
      const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(probeHost)}&type=TXT`, {
        headers: { Accept: 'application/dns-json' },
      });
      if (!resp.ok) throw new Error(`DNS query returned HTTP ${resp.status}.`);
      const data = await resp.json();
      if (data?.Status !== 0) throw new Error(`DNS lookup returned status ${data?.Status ?? 'unknown'}.`);
      const answers = Array.isArray(data.Answer) ? data.Answer : [];
      const expectedToken = `examos-verify=${id}`;
      const hasMatch = answers.some((a) => a.data && a.data.includes(expectedToken));
      if (hasMatch) {
        setDnsProbe({ probing: false, found: true, msg: `DNS TXT challenge verified on ${probeHost}!` });
        setChecklist((s) => ({ ...s, domain: true }));
      } else if (answers.length > 0) {
        setDnsProbe({
          probing: false,
          found: false,
          msg: `TXT record found (${answers[0].data}), but expected token '${expectedToken}' was missing.`,
        });
      } else {
        setDnsProbe({
          probing: false,
          found: false,
          msg: `No TXT records published at ${probeHost} yet. (DNS propagation may take 15m–24h).`,
        });
      }
    } catch (err) {
      setDnsProbe({ probing: false, found: false, msg: `Public DNS query failed: ${err.message}` });
    }
  };

  const handleRecordVerdict = async (verdict) => {
    setDecisionError('');
    if (!id) {
      setDecisionError('No institution reference is available. Reload the application and try again.');
      return;
    }
    if (typeof evidenceNotes !== 'string' || evidenceNotes.trim().length < 8) {
      setDecisionError('Add at least 8 characters of reviewer notes or an evidence reference.');
      return;
    }
    await run(async () => {
      const isApproved = verdict === 'verified';
      const action = isApproved ? 'APPROVED' : (verdict === 'corrections_requested' ? 'MORE_INFORMATION_REQUIRED' : 'REJECTED');

      try {
        if (isApp) {
          // Applications persist their checklist and verdict on the application record.
          await reviewApplication(user, id, action, evidenceNotes.trim(), isApproved ? checklist : undefined);
          setAppData((prev) => prev ? {
            ...prev,
            status: action,
            reviewNotes: evidenceNotes.trim(),
            reviewChecklist: isApproved ? checklist : {},
          } : null);
        } else {
          await updateOnboardingStep(user, id, 'identity_verification', isApproved, evidenceNotes.trim());
        }
      } catch (error) {
        setDecisionError(error?.message || 'The review action was not saved. Check access and try again.');
        throw error;
      }

      if (verdict === 'verified') {
        setSuccessAlert({
          verdict: 'verified',
          title: 'Review Decision Recorded',
          msg: `${inst.name} was approved by the platform reviewer. This decision records the submitted review notes; it does not independently prove each verification item.`,
          nextLabel: 'Proceed to Tenant Provisioning →',
          nextPath: `/platform/institutions/${id}/provisioning`,
        });
      } else if (verdict === 'corrections_requested') {
        setSuccessAlert({
          verdict: 'corrections',
          title: 'Corrections Requested',
          msg: 'The application is marked MORE_INFORMATION_REQUIRED. The reviewer notes contain the requested corrections; the applicant must contact the platform review team with the reference because self-service editing is not available in the public tracker.',
          nextLabel: 'Back to Applications Queue',
          nextPath: '/platform/institutions/applications',
        });
      } else {
        setSuccessAlert({
          verdict: 'rejected',
          title: 'Application Rejected',
          msg: 'The backend application status was updated to REJECTED.',
          nextLabel: 'Back to Applications Queue',
          nextPath: '/platform/institutions/applications',
        });
      }

      return `Verification decision recorded: ${action}`;
    }, 'Verification decision recorded.');
  };

  const handleSwitch = (newId) => {
    if (paramId && paramId !== ':id') {
      nav(`/platform/institutions/${newId}/verification`);
    } else {
      setTenantId(newId);
    }
  };

  if (appLoading) {
    return <Page title="Loading Verification Record"><Loading label="Loading the verification record from backend..." /></Page>;
  }
  if (loadError || !inst) {
    return (
      <Page title="Verification Record Unavailable">
        <Alert tone="danger" title="Unable to load verification record">{loadError || 'No institution or application record was returned.'}</Alert>
        <Link to="/platform/institutions/applications" className="btn">Back to Applications</Link>
      </Page>
    );
  }

  return (
    <Page
      title={`Identity Verification · ${inst.name}`}
      desc="Inspect applicant charter, verify domain DNS TXT challenge, audit authorized signatory credentials, and record compliance approval."
      breadcrumb={
        <div className="crumbs-inline">
          <Link to="/platform/institutions">Platform</Link>
          <Icon name="arrow" size={12} />
          <Link to="/platform/institutions/applications">Applications</Link>
          <Icon name="arrow" size={12} />
          <span>{inst.name}</span>
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {!isApp && <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />}

      {/* Backend status is a recorded decision, not proof of each evidence item. */}
      {isAlreadyApproved && (
        <div style={{ background: 'linear-gradient(135deg, #F0FDF4 0%, #ECFDF5 50%, #F0F9FF 100%)', border: '2px solid #86EFAC', borderRadius: '12px', padding: '24px', marginBottom: '20px', boxShadow: '0 4px 16px rgba(34,197,94,0.12)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: '#22C55E', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <span style={{ color: '#FFFFFF', fontSize: '22px', fontWeight: 800 }}>âœ“</span>
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <b style={{ color: '#15803D', fontSize: '16px' }}>Backend Review Decision</b>
                <Badge value={isProvisioned ? 'PROVISIONED' : 'APPROVED'} tone="green" />
                <span style={{ fontSize: '11.5px', color: '#6B7280', background: '#F3F4F6', padding: '2px 8px', borderRadius: '4px' }}>STATUS FROM BACKEND</span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#166534', lineHeight: 1.5 }}>
                The backend reports this record as {inst.status}. This status alone does not establish that each verification evidence item was independently validated.
              </p>
            </div>
          </div>

          {inst.reviewNotes && (
            <div style={{ padding: '10px 14px', background: '#FFFFFF', borderRadius: '8px', border: '1px solid #D1FAE5', marginBottom: '16px', fontSize: '12.5px' }}>
              <span style={{ fontWeight: 700, color: '#166534' }}>Auditor Notes: </span>
              <span style={{ color: '#374151' }}>{inst.reviewNotes}</span>
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', paddingTop: '14px', borderTop: '1px solid #BBF7D0', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '12px', color: '#6B7280' }}>
                Review status was returned by the backend.
              </span>
              {isSuperAdmin ? (
                <button
                  className="btn small"
                  onClick={() => setOverrideModal(true)}
                  style={{ fontSize: '12px', background: '#FEE2E2', color: '#991B1B', border: '1px solid #FCA5A5' }}
                  title="Unlock institution verification for re-evaluation (Super-Admin only)"
                >
                  <Icon name="shield" size={12} /> Unlock for Re-Evaluation (Super-Admin)
                </button>
              ) : (
                <span className="muted sm">Re-evaluation requires a platform owner; no request queue is available here.</span>
              )}
            </div>
            <button
              className="btn primary"
              onClick={() => nav(`/platform/institutions/${id}/provisioning`)}
              style={{ padding: '10px 20px', fontWeight: 700, fontSize: '13.5px' }}
            >
              {isProvisioned ? 'Go to Tenant Operations Enclave →' : 'Proceed to Tenant Provisioning →'}
            </button>
          </div></div>
      )}
      {isRejected && (
          <Alert tone="danger" title="Application rejected">
            Rejection is terminal. The application cannot be approved or provisioned; the applicant must submit a new application if they wish to reapply.
            {inst.reviewNotes && <div style={{ marginTop: '8px' }}><b>Reviewer reason:</b> {inst.reviewNotes}</div>}
          </Alert>
      )}
      {/* Applicant Dossier / Submitted Documents & Data Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '20px' }}>
        {/* Card 1: Statutory Charter & Registration */}
        <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', boxShadow: 'var(--shadow)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <span style={{ color: 'var(--copper, #B54F34)' }}><Icon name="building" size={18} /></span>
            <b style={{ fontSize: '13.5px', color: 'var(--aubergine, #302337)' }}>Legal Charter &amp; Accreditation</b>
          </div>
          <div style={{ fontSize: '12.5px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div><span className="muted">Legal Name:</span> <b>{inst.legalName || inst.name}</b></div>
            <div><span className="muted">Entity Type:</span> <Badge value={inst.entityType ? inst.entityType.toUpperCase() : 'Not provided'} tone="purple" /></div>
            <div>
              <span className="muted">Registration / Charter #:</span>{' '}
              <code style={{ background: '#F4EFEA', padding: '2px 6px', borderRadius: '4px', fontWeight: 700, color: '#B54F34' }}>
                {inst.registrationNumber || 'Not supplied'}
              </code>
            </div>
            <div><span className="muted">Registered Address:</span> {[inst.address, inst.state, inst.country].filter(Boolean).join(', ') || 'Not supplied'}</div>
            <div><span className="muted">Assessment URL:</span> {inst.targetExamUrl || 'Not supplied'}</div>
            <div style={{ marginTop: '4px', paddingTop: '6px', borderTop: '1px solid #F0ECE6' }}>
              <small className="muted">Statutory Verification: Confirm against UGC, AICTE, NAAC, NBA, or statutory portal.</small>
            </div>
          </div>
        </div>

        {/* Card 2: Academic Domain & DNS Challenge */}
        <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', boxShadow: 'var(--shadow)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <span style={{ color: 'var(--copper, #B54F34)' }}><Icon name="globe" size={18} /></span>
            <b style={{ fontSize: '13.5px', color: 'var(--aubergine, #302337)' }}>Domain &amp; DNS TXT Challenge</b>
          </div>
          <div style={{ fontSize: '12.5px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div>
              <span className="muted">Official Domain:</span>{' '}
              {inst.domain ? (
                <a href={inst.rawDomain?.startsWith('http') ? inst.rawDomain : `https://${inst.domain}`} target="_blank" rel="noreferrer" style={{ fontWeight: 700, color: 'var(--copper, #B54F34)' }}>
                  {inst.domain} ↗
                </a>
              ) : <b>Not provided</b>}
            </div>
            <div>
              <span className="muted">Required DNS Host:</span> <code>{inst.domain ? `_examosverify.${inst.domain}` : 'Unavailable without an institution domain'}</code>
            </div>
            <div>
              <span className="muted">Required TXT Value:</span> <code>examos-verify={id}</code>
            </div>
            <div style={{ marginTop: '6px' }}>
              <button
                className="btn small"
                onClick={handleRunDnsProbe}
                disabled={!inst.domain || dnsProbe?.probing}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
              >
                <Icon name="search" size={13} /> {dnsProbe?.probing ? 'Probing Public DNS...' : 'Verify DNS TXT Record Now'}
              </button>
            </div>
            {dnsProbe && (
              <div style={{ marginTop: '4px', padding: '6px 8px', borderRadius: '6px', fontSize: '11.5px', background: dnsProbe.found ? 'var(--gbg, #edf7f1)' : '#FEF3C7', color: dnsProbe.found ? 'var(--g, #1b7a4b)' : '#92400E', border: `1px solid ${dnsProbe.found ? 'var(--gline, #b9e3cc)' : '#FDE68A'}` }}>
                {dnsProbe.msg}
              </div>
            )}
          </div>
        </div>

        {/* Card 3: Authorized Signatory */}
        <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', boxShadow: 'var(--shadow)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <span style={{ color: 'var(--copper, #B54F34)' }}><Icon name="users" size={18} /></span>
            <b style={{ fontSize: '13.5px', color: 'var(--aubergine, #302337)' }}>Authorized Signatory &amp; Contact</b>
          </div>
          <div style={{ fontSize: '12.5px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div><span className="muted">Representative:</span> <b>{inst.repName || 'Official Signatory'}</b></div>
            <div><span className="muted">Designation:</span> {inst.repRole || 'Vice-Chancellor / Dean / Director'}</div>
            <div><span className="muted">Official Email:</span> <code>{inst.repEmail || 'Not provided'}</code></div>
            <div><span className="muted">Contact Phone:</span> {inst.repPhone || 'Not provided'}</div>
            <div style={{ marginTop: '4px' }}>
              {isMatchingDomain ? (
                <span className="badge sm" style={{ background: 'var(--gbg, #edf7f1)', color: 'var(--g, #1b7a4b)' }}>Email domain matches supplied institution domain</span>
              ) : isWebmail ? (
                <span className="badge sm" style={{ background: '#FEF3C7', color: '#92400E' }}>⚠ Webmail Domain — Verify Official Letterhead</span>
              ) : (
                <span className="badge sm">Email domain does not match supplied institution domain</span>
              )}
            </div>
          </div>
        </div>

        {/* Card 4: Fleet & Examination Scope */}
        <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', boxShadow: 'var(--shadow)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <span style={{ color: 'var(--copper, #B54F34)' }}><Icon name="cpu" size={18} /></span>
            <b style={{ fontSize: '13.5px', color: 'var(--aubergine, #302337)' }}>Fleet &amp; Examination Scope</b>
          </div>
          <div style={{ fontSize: '12.5px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div><span className="muted">Testing Campuses / Centers:</span> <b>{inst.campusCount ?? 'Not supplied'}</b></div>
            <div><span className="muted">Workstation Fleet:</span> <b>{inst.deviceCount ?? 'Not supplied'}</b></div>
            <div><span className="muted">Annual Candidate Volume:</span> <b>{inst.studentCount ?? 'Not supplied'}</b></div>
            <div><span className="muted">Deployment Model:</span> <Badge value={inst.deploymentModel?.toUpperCase() || 'Not supplied'} tone="amber" /></div>
            <div><span className="muted">Hardware Profile:</span> <code>{inst.hardwareProfile || 'Not supplied'}</code></div>
            <div><span className="muted">Enclave Tier:</span> <b>{inst.plan?.toUpperCase() || 'Not assigned'}</b></div>
          </div>
        </div>
      </div>

      {!isAlreadyApproved && !isRejected && (<>
      {/* Checklist Progress */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', marginBottom: '16px', boxShadow: 'var(--shadow)' }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700 }}>Reviewer Verification Progress</span>
            <span style={{ fontSize: '13px', color: allChecked ? 'var(--g, #1b7a4b)' : 'var(--mut, #756F79)', fontWeight: 700 }}>
              {checkedCount} / 5 verified {allChecked ? '— Ready to approve ✓' : '— Complete all 5 checks to record approval'}
            </span>
          </div>
          <div style={{ height: '6px', background: '#EAE4DC', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: `${(checkedCount / 5) * 100}%`, height: '100%', background: allChecked ? 'var(--g, #1b7a4b)' : 'var(--copper, #B54F34)', transition: 'width 0.3s ease' }} />
          </div>
        </div>
      </div>

      {/* Reviewer Verification Checklist Card */}
      <Card
        title="Reviewer Evidence Checklist"
        desc="Inspect the dossier above and independently verify each item before recording official platform accreditation."
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', margin: '10px 0' }}>
          {[
            {
              key: 'identity',
              label: '1. Official Educational Charter & Statutory Registration Verified',
              hint: `Registration #${inst.registrationNumber || 'N/A'} for ${inst.name} confirmed against UGC / AICTE / Statutory Registry.`,
            },
            {
              key: 'domain',
              label: '2. Academic Domain Ownership & Control Confirmed',
              hint: `Control of ${inst.domain || 'domain'} validated via DNS TXT record or official institutional website.`,
            },
            {
              key: 'accreditation',
              label: '3. Accreditation & Institutional Letterhead on File',
              hint: `Official accreditation references and charter documents confirmed in compliance records.`,
            },
            {
              key: 'representative',
              label: '4. Authorized Institutional Signatory Authority Validated',
              hint: `Signatory ${inst.repName || 'representative'} (${inst.repEmail}) authorized by the institution's legal head.`,
            },
            {
              key: 'datacenter',
              label: '5. Workstation Fleet & Kiosk Deployment Architecture Scoped',
              hint: `Deployment profile (${inst.deviceCount} workstations across ${inst.campusCount} center(s), ${inst.deploymentModel}) confirmed feasible.`,
            },
          ].map((item) => (
            <div
              key={item.key}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                padding: '12px 14px',
                background: checklist[item.key] ? 'var(--gbg, #edf7f1)' : '#FAFAFA',
                border: `1px solid ${checklist[item.key] ? 'var(--gline, #b9e3cc)' : 'var(--line, #DCD5D2)'}`,
                borderRadius: '8px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
              onClick={() => toggleCheck(item.key)}
            >
              <div
                style={{
                  width: '20px',
                  height: '20px',
                  borderRadius: '4px',
                  border: `2px solid ${checklist[item.key] ? 'var(--g, #1b7a4b)' : '#C0B8C4'}`,
                  background: checklist[item.key] ? 'var(--g, #1b7a4b)' : '#FFFFFF',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  marginTop: '2px',
                }}
              >
                {checklist[item.key] && <span style={{ color: '#FFFFFF', fontSize: '12px', fontWeight: 800 }}>✓</span>}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '13.5px', color: checklist[item.key] ? 'var(--g, #1b7a4b)' : 'var(--aubergine, #302337)' }}>
                  {item.label}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--mut, #756F79)', marginTop: '2px' }}>{item.hint}</div>
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: '20px' }}>
          <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>
            Auditable Evidence References &amp; Reviewer Notes
          </label>
          <Textarea
            rows={3}
            value={evidenceNotes}
            onChange={(e) => setEvidenceNotes(e.target.value)}
            placeholder="Record certificate hash, statutory registry verification ticket ID, registrar notes, or reasoning..."
          />
          <small style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', marginTop: '4px', display: 'block' }}>
            These verification notes are permanently committed to the immutable HMAC-authenticated audit ledger.
          </small>
        </div>

        {decisionError && <Alert tone="danger" title="Review action was not saved">{decisionError}</Alert>}

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

      </>)}
            {/* Modal 1: Super-Admin Administrative Override / Unlock */}
      {overrideModal && (
        <Modal
          title="Super-Admin Administrative Override"
          desc="Authorize re-evaluation of statutory verification for this institution. This decision is permanently recorded in the immutable audit ledger."
          onClose={() => setOverrideModal(false)}
        >
          <div style={{ padding: '10px 0' }}>
            <div style={{ background: '#FEF2F2', border: '1px solid #FECACA', borderRadius: '8px', padding: '12px 16px', marginBottom: '16px', fontSize: '13px', color: '#991B1B' }}>
              <b>Governance Notice:</b> As Platform Super-Admin, unlocking this institution permits re-evaluating identity, domain, and statutory compliance checks. A verifiable compliance rationale is required.
            </div>
            <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, marginBottom: '6px' }}>
              Compliance &amp; Re-Evaluation Justification (Required)
            </label>
            <Textarea
              rows={3}
              value={overrideReason}
              onChange={(e) => setOverrideReason(e.target.value)}
              placeholder="e.g. Statutory regulatory authority issued revision notice, official registrar domain changed, or charter verification challenge re-requested..."
            />
          </div>
          <div className="row end" style={{ gap: '10px', marginTop: '16px' }}>
            <button className="btn" onClick={() => setOverrideModal(false)}>Cancel</button>
            <button
              className="btn danger"
              disabled={overrideReason.trim().length < 8 || busy}
              onClick={async () => {
                await run(async () => {
                  if (isApp) {
                    await reviewApplication(user, id, 'UNDER_REVIEW', `Re-opened for re-evaluation by Platform Owner ${user.name}: ${overrideReason}`);
                    setAppData((prev) => prev ? { ...prev, status: 'UNDER_REVIEW', reviewNotes: overrideReason, reviewChecklist: {} } : null);
                    setChecklist({ identity: false, domain: false, accreditation: false, representative: false, datacenter: false });
                  } else {
                    await updateOnboardingStep(user, id, 'identity_verification', false, overrideReason);
                  }
                  setUnlockedForEdit(true);
                  setOverrideModal(false);
                  return 'Verification milestone unlocked by Super-Admin. Review checklist is now editable.';
                }, 'Re-evaluation unlocked.');
              }}
            >
              Confirm &amp; Unlock for Re-Evaluation
            </button>
          </div>
        </Modal>
      )}

      {/* Success Alert / Next Step Modal */}
      {successAlert && (
        <Modal
          title={
            successAlert.verdict === 'verified'
              ? 'Review Decision Recorded'
              : successAlert.verdict === 'corrections'
              ? '📋 Corrections Requested'
              : '❌ Application Rejected'
          }
          desc={successAlert.msg}
          onClose={() => { setSuccessAlert(null); nav('/platform/institutions/applications'); }}
        >
          <div style={{ padding: '16px 0' }}>
            {successAlert.verdict === 'verified' && (
              <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '20px', marginBottom: '16px', textAlign: 'center' }}>
                <div style={{ fontSize: '36px', marginBottom: '8px' }}>🎉</div>
                <h3 style={{ color: 'var(--g, #1b7a4b)', margin: '0 0 8px', fontSize: '16px' }}>Institution Verified!</h3>
                <p style={{ color: 'var(--ink2, #48394F)', margin: 0, fontSize: '13.5px', lineHeight: 1.55 }}>
                  <b>{inst.name}</b> has passed all verification challenges. The application is now <b>APPROVED</b>. Next step: execute <b>Tenant Provisioning</b> to allocate their isolated database, cryptographic master keys, and license.
                </p>
              </div>
            )}

            <div style={{ background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', padding: '14px 16px', marginBottom: '16px', fontSize: '13px' }}>
              <b>What happens next:</b>
              {successAlert.verdict === 'verified' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>Application status recorded as <b>APPROVED</b> in compliance ledger</li>
                  <li>Proceed directly to <b>Tenant Provisioning</b> to create the isolated enclave</li>
                  <li>Invite the primary administrator to activate their account and enroll MFA</li>
                </ul>
              )}
              {successAlert.verdict === 'corrections' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>Application status set to <b>MORE_INFORMATION_REQUIRED</b></li>
                  <li>Reviewer notes are visible in the public tracker; the applicant must provide the requested information to the platform review team because self-service editing is not available.</li>
                </ul>
              )}
              {successAlert.verdict === 'rejected' && (
                <ul style={{ margin: '8px 0 0', paddingLeft: '20px', lineHeight: 1.7 }}>
                  <li>Application permanently marked as <b>REJECTED</b></li>
                  <li>Reason written to audit ledger</li>
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
  const [inst, setInst] = useState(null);
  const [instCampuses, setInstCampuses] = useState([]);
  const [instDepts, setInstDepts] = useState([]);
  const [instAdmins, setInstAdmins] = useState([]);
  const [institutionStats, setInstitutionStats] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(true);
  const [detailsError, setDetailsError] = useState('');
  const { msg, setMsg, run, busy } = useFlash();

  const [confirmApproval, setConfirmApproval] = useState(false);
  const [reason, setReason] = useState('');
  const [deployments, setDeployments] = useState([]);

  useEffect(() => {
    let active = true;
    setLoadingDetails(true);
    setDetailsError('');
    setInst(null);
    setInstCampuses([]);
    setInstDepts([]);
    setInstAdmins([]);
    setInstitutionStats(null);
    setDeployments([]);
    if (!id) {
      setLoadingDetails(false);
      setDetailsError('Institution ID is unavailable.');
      return () => { active = false; };
    }

    Promise.all([
      Api.getInstitution(id),
      Api.getInstitutionStats(id),
      Api.listCampuses(id),
      Api.listDepartments(id),
      Api.listInstitutionAdmins(id),
      fetchInstitutionDeployments(id),
    ])
      .then(([institution, stats, campusResponse, departmentResponse, institutionAdmins, institutionDeployments]) => {
        const campusRows = campusResponse?.campuses || campusResponse;
        const departmentRows = departmentResponse?.departments || departmentResponse;
        if (!institution || !stats || ['campuses', 'departments', 'users', 'devices', 'exams'].some((field) => typeof stats[field] !== 'number')
          || !Array.isArray(campusRows) || !Array.isArray(departmentRows)
          || !Array.isArray(institutionAdmins) || !Array.isArray(institutionDeployments)) {
          throw new Error('The backend returned an unexpected institution detail response.');
        }
        if (!active) return;
        setInst(institution);
        setInstitutionStats(stats);
        setInstCampuses(campusRows);
        setInstDepts(departmentRows);
        setInstAdmins(institutionAdmins);
        setDeployments(institutionDeployments);
      })
      .catch((error) => {
        if (active) setDetailsError(error?.message || 'Failed to load institution details from the backend.');
      })
      .finally(() => {
        if (active) setLoadingDetails(false);
      });
    return () => { active = false; };
  }, [id]);

  if (loadingDetails) {
    return <Page title="Loading Institution"><Loading label="Loading institution details from backend..." /></Page>;
  }

  if (detailsError || !inst) {
    return (
      <Page title="Institution Not Found">
        {detailsError && <Alert tone="danger" title="Unable to load institution details">{detailsError}</Alert>}
        {!detailsError && <Empty icon="building" title="Institution Record Not Found" />}
        <Link to="/platform/institutions/directory" className="btn">Back to Directory</Link>
      </Page>
    );
  }

  const latestDeployment = deployments[0];

  const handleApprove = async () => {
    await run(async () => {
      await setInstitutionStatus(user, inst, 'approved', reason || 'Platform Admin approved');
      setInst((current) => ({ ...current, status: 'approved' }));
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

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
        <Card title="Official Institutional Profile">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Legal Entity Name</small><br /><b>{inst.name}</b></div>
            <div><small className="muted">Identifier Code</small><br /><code>{inst.code}</code></div>
            <div><small className="muted">Official Domain(s)</small><br /><span>{(inst.domains || []).join(', ') || '—'}</span></div>
            <div><small className="muted">Contact Email</small><br /><span>{inst.contactEmail || '—'}</span></div>
            <div><small className="muted">Jurisdiction / Region</small><br /><span>{inst.region || 'Not provided'}</span></div>
            <div><small className="muted">Subscription Tier</small><br /><Badge value={inst.plan || 'Not assigned'} /></div>
            <div><small className="muted">Status</small><br /><Badge value={inst.status || 'Unknown'} tone={inst.status === 'active' ? 'green' : 'amber'} /></div>
            <div><small className="muted">Enrolled Timestamp</small><br /><span>{fmt(inst.createdAt)}</span></div>
          </div>
        </Card>

        <Card title="Organizational Summary">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div><small className="muted">Registered Sites</small><br /><b>{instCampuses.length} {instCampuses.length === 1 ? 'Campus' : 'Campuses'}</b></div>
            <div><small className="muted">Academic Departments</small><br /><b>{instDepts.length} {instDepts.length === 1 ? 'Department' : 'Departments'}</b></div>
            <div><small className="muted">Administrators</small><br /><b>{instAdmins.length} Account{instAdmins.length !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Enrolled Devices</small><br /><b>{institutionStats.devices} Workstation{institutionStats.devices !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Total Exams</small><br /><b>{institutionStats.exams} Exam{institutionStats.exams !== 1 ? 's' : ''}</b></div>
            <div><small className="muted">Tenant Boundary</small><br /><code>{inst.schemaName || inst.schema_name || 'Not exposed by institution API'}</code></div>
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
  const { tenantId, tenants: institutions, setTenantId } = useTenant();

  // CRITICAL: always use the URL param ID; never fall back to institutions[0]
  // which could be a different already-provisioned institution
  const targetId = (paramId && paramId !== ':id') ? paramId : tenantId;

  const [instLive, setInstLive] = useState(null);
  const inst = instLive || institutions.find((x) => x.id === targetId) || null;
  const id = targetId;

  const { msg, setMsg, run, busy } = useFlash();

  const [provisioningResult, setProvisioningResult] = useState(null);
  const [provisionDone, setProvisionDone] = useState(false);
  const [adminModal, setAdminModal] = useState(false);
  const [adminData, setAdminData] = useState({ name: '', email: '', role: 'inst_admin' });
  const [adminCreated, setAdminCreated] = useState(null);
  const [onboarding, setOnboarding] = useState(null);
  const [recordError, setRecordError] = useState('');
  const [recordLoading, setRecordLoading] = useState(true);
  const [existingAdmins, setExistingAdmins] = useState([]);
  const [loadingAdmins, setLoadingAdmins] = useState(true);
  const [adminLoadError, setAdminLoadError] = useState('');
  const [adminReload, setAdminReload] = useState(0);

  // Load existing admins to detect conflicts / prevent duplicate creation
  const adminTenantId = provisioningResult?.institution_id
    || instLive?.institutionId
    || (id?.startsWith('ins_') ? id : null);
  useEffect(() => {
    if (!adminTenantId) {
      setLoadingAdmins(false);
      setAdminLoadError('');
      setExistingAdmins([]);
      return undefined;
    }
    let active = true;
    setLoadingAdmins(true);
    setAdminLoadError('');
    setExistingAdmins([]);
    import('../institutions/service')
      .then(({ listInstitutionAdmins: listAdmins }) => listAdmins(adminTenantId))
      .then((admins) => {
        if (active) setExistingAdmins(Array.isArray(admins) ? admins : []);
      })
      .catch((error) => {
        if (active) {
          setAdminLoadError(error?.message || 'Failed to load institution administrators.');
          setExistingAdmins([]);
        }
      })
      .finally(() => {
        if (active) setLoadingAdmins(false);
      });
    return () => { active = false; };
  }, [adminTenantId, adminReload]);

  // Load institution/application and onboarding state from the backend.
  useEffect(() => {
    let active = true;
    setRecordLoading(true);
    setRecordError('');
    setInstLive(null);
    setOnboarding(null);
    setProvisionDone(false);
    if (!id) {
      setRecordLoading(false);
      setRecordError('Institution ID is unavailable.');
      return () => { active = false; };
    }

    const load = async () => {
      try {
        if (id.startsWith('app_')) {
          const app = await fetchInstitutionApplication(id);
          if (!active) return;
          if (!app) throw new Error('The application was not found.');
          setInstLive({
            id: app.id,
            name: app.legalName || app.displayName || app.id,
            code: app.displayName || app.id,
            status: app.status?.toLowerCase(),
            contactEmail: app.repEmail,
            repEmail: app.repEmail,
            repName: app.repName,
            entityType: app.entityType || '',
            institutionId: app.institutionId || '',
          });
          if (app.repEmail) {
            setAdminData((d) => ({
              ...d,
              email: d.email || app.repEmail || '',
              name: d.name || app.repName || '',
            }));
          }
          setProvisionDone(app.status === 'PROVISIONED' || Boolean(app.institutionId));
          if (app.institutionId) {
            const ob = await fetchInstitutionOnboarding(app.institutionId);
            if (!active) return;
            setOnboarding(ob);
          }
        } else {
          const [institution, ob] = await Promise.all([
            Api.getInstitution(id),
            fetchInstitutionOnboarding(id),
          ]);
          if (!active) return;
          if (!institution) throw new Error('The institution was not found.');
          setInstLive(institution);
          setOnboarding(ob);
          if (ob?.contactEmail || ob?.repEmail) {
            setAdminData((d) => ({
              ...d,
              email: d.email || ob.contactEmail || ob.repEmail || '',
              name: d.name || ob.repName || '',
            }));
          }
          setProvisionDone(true);
        }
      } catch (error) {
        if (active) setRecordError(error?.message || 'Failed to load provisioning state from the backend.');
      } finally {
        if (active) setRecordLoading(false);
      }
    };
    load();
    return () => { active = false; };
  }, [id]);

  const isApplication = Boolean(id?.startsWith('app_'));
  const primaryAdmin = onboarding?.firstAdminEmail
    ? existingAdmins.find((admin) => admin.email?.trim().toLowerCase() === onboarding.firstAdminEmail.trim().toLowerCase())
    : null;
  const primaryAdminMfaEnrolled = primaryAdmin?.status === 'active' && primaryAdmin.mfaEnabled === true;

  /* Removed fabricated provisioning progress. This page only reports states
     represented by persisted institution/application and onboarding records. */
  const steps = [
    {
      name: 'Institution record',
      status: inst?.id && !isApplication ? 'AVAILABLE' : (provisionDone ? 'CREATED' : 'PENDING'),
      detail: isApplication
        ? (provisionDone ? `Provisioned institution: ${inst?.institutionId || 'recorded by backend'}` : 'Application has not been provisioned.')
        : (inst?.id || 'No institution record loaded'),
    },
    {
      name: 'Primary administrator',
      status: loadingAdmins ? 'CHECKING' : adminLoadError ? 'UNAVAILABLE' : existingAdmins.length ? 'CONFIGURED' : (adminCreated ? 'INVITED' : 'NOT CONFIGURED'),
      detail: loadingAdmins ? 'Checking institution-scoped administrator records.'
        : adminLoadError ? 'Administrator state could not be verified.'
          : existingAdmins.length ? `${existingAdmins.length} institution administrator record(s) found.`
            : adminCreated ? `Invitation created for ${adminCreated.email}. MFA enrollment is not verified.`
              : 'No institution administrator records found.',
    },
    {
      name: 'MFA enrollment',
      status: loadingAdmins ? 'CHECKING' : adminLoadError ? 'UNAVAILABLE' : primaryAdminMfaEnrolled ? 'ENROLLED' : 'NOT VERIFIED',
      detail: loadingAdmins ? 'Checking the primary administrator MFA state persisted by the backend.'
        : adminLoadError ? 'Primary administrator MFA state could not be verified.'
          : primaryAdminMfaEnrolled ? `MFA enrollment is enabled for ${primaryAdmin.email}.`
            : !onboarding?.firstAdminEmail ? 'The primary administrator is not identified in the onboarding record.'
              : !primaryAdmin ? `No administrator account matches ${onboarding.firstAdminEmail}.`
                : primaryAdmin.status !== 'active' ? 'The primary administrator account is not active.'
                  : primaryAdmin.mfaEnabled === null ? 'The backend did not return an MFA enrollment state for the primary administrator.'
                    : 'The primary administrator account does not have MFA enabled in the backend.',
    },
  ];

  /*
   * Legacy local collection hydration and inferred provisioning status were
   * intentionally removed: neither is authoritative evidence of provisioning.
   */

  const handleRunProvisioning = async () => {
    if (!isApplication || provisionDone) {
      setMsg('Tenant provisioning can only be executed for an unprovisioned application.');
      return;
    }
    await run(async () => {
      const result = await provisionApplication(user, id);
      setProvisioningResult(result);
      setProvisionDone(true);
      if (result.institution_id) {
        fetchInstitutionOnboarding(result.institution_id)
          .then(setOnboarding)
          .catch((error) => setRecordError(error?.message || 'Institution was provisioned, but onboarding state could not be loaded.'));
      }
      setInstLive((current) => ({
        ...current,
        id: result.institution_id,
        institutionId: result.institution_id,
        status: 'provisioned',
      }));
      // Pre-fill admin data from institution contact info
      setAdminData((d) => ({
        ...d,
        email: d.email || inst?.contactEmail || inst?.repEmail || '',
        name: d.name || inst?.repName || '',
      }));
      return 'The backend provisioned the institution. Verify each associated resource before proceeding.';
    }, 'Provisioning complete.');
  };

  const handleCreateAdmin = async () => {
    if (!adminData.email || !adminData.name) return;
    const targetTenantId = provisioningResult?.institution_id || instLive?.institutionId || inst?.institutionId || (id.startsWith('ins_') ? id : null);
    if (!targetTenantId) {
      setMsg('Error: Tenant has not been provisioned yet. Please click "Execute Tenant Provisioning" first.');
      return;
    }
    await run(async () => {
      const { inviteInstitutionAdmin: inviteAdmin } = await import('../institutions/service');
      const result = await inviteAdmin(user, targetTenantId, adminData);
      setAdminCreated(result);
      setAdminModal(false);
      setAdminReload((n) => n + 1);
      return `Administrator invitation created for ${adminData.name}. MFA enrollment must be verified separately.`;
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
      title={`Tenant Provisioning · ${inst?.name || (recordLoading ? 'Loading...' : 'Institution unavailable')}`}
      desc="Review backend-persisted provisioning, administrator, and MFA verification state."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst?.name || id || 'Institution'}</Link><Icon name="arrow" size={12} /><span>Provisioning</span></div>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      {recordError && <Alert tone="danger" title="Unable to load provisioning state">{recordError}</Alert>}
      {recordLoading && <Loading />}

      <Card title="Provisioning state" desc="Status is limited to persisted backend records; unverified infrastructure claims are not inferred.">
        <DataTable
          rows={steps}
          columns={[
            { key: 'name', label: 'Provisioning Step', render: (s) => <b>{s.name}</b> },
            { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} tone={['AVAILABLE', 'CREATED', 'CONFIGURED', 'ATTESTED', 'ENROLLED'].includes(s.status) ? 'green' : s.status === 'INVITED' ? 'blue' : 'amber'} /> },
            { key: 'detail', label: 'Details', render: (s) => <span className="muted sm">{s.detail}</span> },
          ]}
        />

        <div className="row end" style={{ marginTop: '16px', gap: '8px' }}>
          {isApplication && !provisionDone ? (
            <button className="btn primary" onClick={handleRunProvisioning} disabled={busy || recordLoading || Boolean(recordError) || !['APPROVED', 'APPROVED_FOR_PROVISIONING'].includes(inst?.status?.toUpperCase())}>
              <Icon name="refresh" size={14} /> Execute Tenant Provisioning
            </button>
          ) : null}
          {provisionDone && !primaryAdminMfaEnrolled && (
            loadingAdmins ? (
              <span className="muted sm">Checking for existing administrators...</span>
            ) : adminLoadError ? (
              <button className="btn" onClick={() => setAdminReload((n) => n + 1)}>
                <Icon name="refresh" size={14} /> Retry administrator check
              </button>
            ) : existingAdmins.length > 0 ? (
              <span className="badge g" style={{ padding: '8px 16px' }}>
                ✓ {existingAdmins.length} Admin{existingAdmins.length > 1 ? 's' : ''} Already Configured
              </span>
            ) : (
              <button className="btn primary" onClick={() => setAdminModal(true)} disabled={busy}>
                <Icon name="users" size={14} /> Create Primary Administrator
              </button>
            )
          )}
          {adminCreated && !primaryAdminMfaEnrolled && (
            <span className="muted sm">Administrator invited; MFA enrollment is not yet verified.</span>
          )}
          {primaryAdminMfaEnrolled && (
            <button className="btn" onClick={() => nav(`/platform/institutions/${provisioningResult?.institution_id || id}/readiness`)}>
              Next: Pilot &amp; Readiness →
            </button>
          )}
        </div>
      </Card>

      {adminLoadError && (
        <Alert tone="danger" title="Unable to verify institution administrators">
          {adminLoadError} Retry the check before creating another administrator.
        </Alert>
      )}

      {provisioningResult && !adminCreated && (
        <div style={{ background: 'var(--gbg, #edf7f1)', border: '1px solid var(--gline, #b9e3cc)', borderRadius: '10px', padding: '16px 20px', marginTop: '16px' }}>
          <b style={{ color: 'var(--g, #1b7a4b)' }}>✓ Provisioning Complete!</b>
          <p style={{ margin: '6px 0 0', fontSize: '13.5px', color: 'var(--ink2, #48394F)', lineHeight: 1.55 }}>
            Institution ID: <code>{provisioningResult.institution_id}</code> · Agreement: <code>{provisioningResult.agreement_id || '—'}</code> · License: <code>{provisioningResult.license_id || '—'}</code>
          </p>
          <p style={{ margin: '8px 0 0', fontSize: '13.5px', color: 'var(--ink2, #48394F)' }}>
            Next: Create the primary institution administrator account so they can log in and configure sites, departments, and exam schedules.
          </p>
        </div>
      )}

      {/* Existing Admins Panel */}
      {existingAdmins.length > 0 && (
        <Card
          title={`Existing Administrators (${existingAdmins.length})`}
          desc="These administrator accounts are already configured for this institution. Creating another is optional."
        >
          <DataTable
            rows={existingAdmins}
            columns={[
              { key: 'name', label: 'Name', render: (a) => <b>{a.name || a.username}</b> },
              { key: 'email', label: 'Email', render: (a) => <span className="muted sm">{a.email}</span> },
              { key: 'role', label: 'Role', render: (a) => <Badge value={a.role} /> },
              { key: 'mfaEnabled', label: 'MFA', render: (a) => <Badge value={a.mfaEnabled ? 'Enrolled' : 'Pending'} tone={a.mfaEnabled ? 'green' : 'amber'} /> },
              { key: 'status', label: 'Status', render: (a) => <Badge value={a.status} tone={a.status === 'active' ? 'green' : 'red'} /> },
            ]}
            empty={<Empty icon="users" title="No admins found" />}
          />
          <div className="row end" style={{ marginTop: '12px' }}>
            <button className="btn" onClick={() => setAdminReload((n) => n + 1)} disabled={loadingAdmins}>
              <Icon name="refresh" size={14} /> {loadingAdmins ? 'Refreshing...' : 'Refresh MFA status'}
            </button>
            <button className="btn" onClick={() => setAdminModal(true)} disabled={busy}>
              <Icon name="users" size={14} /> Add Another Administrator
            </button>
          </div>
        </Card>
      )}

      {/* Create Admin Modal */}
      {adminModal && (
        <Modal
          title="Create Primary Institution Administrator"
          desc={`Create the first administrator account for ${inst.name}. This person will manage the institution's exams, sites, and staff.`}
          onClose={() => setAdminModal(false)}
        >
          <div className="formgrid">
            <Field label="Administrator Full Name" required className="span2">
              <Input
                value={adminData.name}
                onChange={(e) => setAdminData({ ...adminData, name: e.target.value })}
                placeholder={inst?.entityType && ['enterprise','technology','company'].includes(inst.entityType) ? 'e.g. John Smith (IT Director)' : 'e.g. Prof. Rajan Mehta'}
                required
              />
            </Field>
            <Field label="Official Institutional Email" required className="span2">
              <Input
                type="email"
                value={adminData.email}
                onChange={(e) => setAdminData({ ...adminData, email: e.target.value })}
                placeholder={`e.g. admin@${inst?.domains?.[0] || inst?.domain || (inst?.entityType === 'enterprise' ? 'company.com' : 'institution.edu')}`}
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
  const { tenantId, tenants: institutions, setTenantId } = useTenant();

  const targetId = (paramId && paramId !== ':id') ? paramId : tenantId;
  const [instLive, setInstLive] = useState(null);
  const inst = instLive || institutions.find((x) => x.id === targetId) || null;
  const id = targetId;

  const { msg, setMsg, run, busy } = useFlash();

  // All readiness data comes exclusively from the backend
  const [readiness, setReadiness] = useState(null);
  const [loading, setLoading] = useState(true);
  const [readinessError, setReadinessError] = useState('');
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchReadiness = async () => {
    if (!id) {
      setLoading(false);
      setReadinessError('Institution ID is unavailable.');
      return;
    }
    setLoading(true);
    setReadinessError('');
    try {
      const data = await fetchInstitutionPilotReadiness(id);
      if (!data || !Array.isArray(data.gates) || typeof data.allPassed !== 'boolean'
        || !data.gates.every((gate) => typeof gate.pass === 'boolean' && typeof gate.check === 'string')
        || !Array.isArray(data.examUrls)
        || !data.devices || typeof data.devices.total !== 'number'
        || typeof data.devices.attested !== 'number' || typeof data.devices.enrolled !== 'number'
        || !data.auditChain || typeof data.auditChain.total !== 'number'
        || typeof data.auditChain.linked !== 'number' || typeof data.auditChain.ok !== 'boolean'
        || !data.onboarding || typeof data.onboarding.status !== 'string'
        || typeof data.onboarding.completedSteps !== 'number' || typeof data.onboarding.totalSteps !== 'number') {
        throw new Error('The backend returned an unexpected readiness response.');
      }
      setReadiness(data);
      if (data.institutionName) {
        setInstLive((prev) => ({
          ...(prev || {}),
          id,
          name: data.institutionName,
          status: data.institutionStatus || prev?.status,
          plan: data.institutionPlan || prev?.plan,
        }));
      }
      setLastRefresh(new Date());
    } catch (err) {
      setReadiness(null);
      setReadinessError(err?.message || 'Failed to load readiness data from the backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReadiness();
    // Auto-refresh every 30 seconds for real-time updates
    const interval = setInterval(fetchReadiness, 30000);
    return () => clearInterval(interval);
  }, [id]);

  // Build gates from backend response
  const pilotChecks = useMemo(() => {
    if (!readiness?.gates) return [];
    return readiness.gates.map((g) => ({
      check: g.check,
      pass: g.pass,
      detail: g.detail,
    }));
  }, [readiness]);

  const allPassed = readiness?.allPassed === true;
  const devices = readiness?.devices;
  const examUrls = readiness?.examUrls || [];
  const auditChain = readiness?.auditChain;
  const onboarding = readiness?.onboarding;

  const handleGrantOperational = async () => {
    await run(async () => {
      if (!inst) throw new Error('Institution profile is unavailable; status cannot be changed.');
      await setInstitutionStatus(user, inst, 'active', 'Platform owner changed status after reviewing stored readiness markers.');
      setInst((current) => current ? { ...current, status: 'active' } : current);
      await fetchReadiness();
      return 'Institution status was changed to active.';
    }, 'Institution status updated.');
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
      title={`Pilot & Readiness Approval · ${inst?.name || 'Loading...'}`}
      desc="Review stored device, URL, and audit-reference markers. This view does not independently verify TPM quotes, URL reachability, policy enforcement, or cryptographic audit integrity."
      breadcrumb={<div className="crumbs-inline"><Link to="/platform/institutions">Platform</Link><Icon name="arrow" size={12} /><Link to={`/platform/institutions/${id}`}>{inst?.name}</Link><Icon name="arrow" size={12} /><span>Readiness</span></div>}
      actions={
        <button className="btn" onClick={fetchReadiness} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Icon name="pulse" size={14} /> {loading ? 'Refreshing...' : 'Refresh Live Data'}
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <InstitutionSwitcher inst={inst} institutions={institutions} onSelect={handleSwitch} />
      {readinessError && <Alert tone="danger" title="Unable to load readiness data">{readinessError}</Alert>}

      {/* Live stats from backend */}
      {readiness && (
        <StatGrid cols={4} style={{ marginBottom: '16px' }}>
          <Stat
            label="Device Records"
            value={devices.total}
            tone={devices.total > 0 ? 'green' : 'red'}
            icon="device"
            sub={`${devices.enrolled} enrollment records · ${devices.attested} attestation markers`}
          />
          <Stat
            label="Attestation Markers"
            value={`${devices.attested}/${devices.total}`}
            tone={devices.total > 0 && devices.attested === devices.total ? 'green' : 'amber'}
            icon="shield"
            sub="Stored device state; cryptographic quote verification is not performed by this view"
          />
          <Stat
            label="Configured Exam URLs"
            value={examUrls.length}
            tone={examUrls.length > 0 ? 'green' : 'red'}
            icon="link"
            sub={examUrls.length > 0 ? 'URL values are configured; reachability is not checked' : 'No exam URLs configured'}
          />
          <Stat
            label="Audit Event Records"
            value={auditChain.total}
            tone={auditChain.ok ? 'green' : 'amber'}
            icon="lock"
            sub={auditChain.ok ? 'Predecessor-reference count meets the stored-record threshold' : (auditChain.total === 0 ? 'No audit events recorded' : 'Predecessor-reference count is incomplete')}
          />
        </StatGrid>
      )}

      <Card
        title="Pilot Verification Checklist"
        desc={
          <span>
            Pre-production validation gates — live from backend
            {lastRefresh && <span className="muted" style={{ marginLeft: '10px', fontSize: '11px' }}>Last updated: {lastRefresh.toLocaleTimeString()}</span>}
          </span>
        }
      >
        {loading && !readiness ? (
          <Loading label="Fetching live readiness data from backend..." />
        ) : readinessError ? (
          <Empty title="Readiness data unavailable" desc={readinessError} />
        ) : (
          <>
            <DataTable
              rows={pilotChecks}
              columns={[
                { key: 'check', label: 'Readiness Gate', render: (c) => <b>{c.check}</b> },
                { key: 'pass', label: 'Result', render: (c) => <Badge value={c.pass ? 'PASS' : 'FAIL'} tone={c.pass ? 'green' : 'red'} /> },
                { key: 'detail', label: 'Diagnostic Details', render: (c) => <span className="mono sm">{c.detail}</span> },
              ]}
              empty={<Empty title="No readiness data" desc="Could not load readiness data from backend." />}
            />

            {readiness?.examUrls?.length > 0 && (
              <div style={{ marginTop: '12px', padding: '10px 14px', background: '#F8F6FF', border: '1px solid #C4B5FD', borderRadius: '8px', fontSize: '12px' }}>
                <b>Configured Assessment Portal URLs:</b>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '6px' }}>
                  {readiness.examUrls.map((u, i) => (
                    <code key={i} style={{ background: '#EDE9FE', padding: '2px 8px', borderRadius: '4px' }}>{u}</code>
                  ))}
                </div>
              </div>
            )}

            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12px', color: 'var(--mut, #756F79)' }}>
                Onboarding: <b>{onboarding.status}</b>
                {onboarding.totalSteps > 0 && <> · {onboarding.completedSteps}/{onboarding.totalSteps} recorded steps</>}
              </div>
              <button
                className="btn primary"
                onClick={handleGrantOperational}
                disabled={busy || !inst || !allPassed || inst?.status?.toLowerCase() === 'active'}
              >
                <Icon name="check" size={15} /> {inst?.status?.toLowerCase() === 'active' ? 'Institution Active' : 'Set Institution Status to Active'}
              </button>
            </div>
          </>
        )}
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
  const { tenantId, tenants: institutions, setTenantId } = useTenant();
  const targetId = (paramId && paramId !== ':id') ? paramId : tenantId;
  const [inst, setInst] = useState(null);
  const id = targetId;
  const { msg, setMsg, run, busy } = useFlash();

  const [confirmStatus, setConfirmStatus] = useState(null);
  const [instIncidents, setInstIncidents] = useState([]);
  const [loadingOperations, setLoadingOperations] = useState(true);
  const [operationsError, setOperationsError] = useState('');

  useEffect(() => {
    let active = true;
    setLoadingOperations(true);
    setOperationsError('');
    setInst(null);
    setInstIncidents([]);
    if (!id) {
      setLoadingOperations(false);
      setOperationsError('Institution ID is unavailable.');
      return () => { active = false; };
    }

    Promise.all([Api.getInstitution(id), Api.listIncidents()])
      .then(([institution, incidentResponse]) => {
        const rows = incidentResponse?.incidents || incidentResponse;
        if (!institution || !Array.isArray(rows)) {
          throw new Error('The backend returned an unexpected operations response.');
        }
        if (!active) return;
        setInst(institution);
        setInstIncidents(rows.filter((incident) => incident.tenantId === id || incident.institutionId === id));
      })
      .catch((error) => {
        if (active) setOperationsError(error?.message || 'Failed to load institution operations from the backend.');
      })
      .finally(() => {
        if (active) setLoadingOperations(false);
      });

    return () => { active = false; };
  }, [id]);

  const handleStatusChange = async (targetStatus, reason) => {
    await run(async () => {
      await setInstitutionStatus(user, inst, targetStatus, reason);
      setInst((current) => current ? { ...current, status: targetStatus } : current);
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
      {operationsError && <Alert tone="danger" title="Unable to load institution operations">{operationsError}</Alert>}
      {loadingOperations && <Loading label="Loading institution operations from backend..." />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        <Card title="Operational Controls" desc="Administrative suspension, reactivation, and offboarding">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <p className="muted sm">
              Status changes are sent to the institution backend. Verify their operational impact before applying them.
            </p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {inst?.status?.toLowerCase() === 'active' ? (
                <button className="btn danger" onClick={() => setConfirmStatus('suspended')}>
                  <Icon name="alert" size={14} /> Suspend Institution
                </button>
              ) : inst ? (
                <button className="btn primary" onClick={() => setConfirmStatus('active')}>
                  <Icon name="check" size={14} /> Reactivate Institution
                </button>
              ) : null}
            </div>
          </div>
        </Card>

        <Card title="Security & Compliance Incidents" desc="Hardware tamper, peripheral violations, or network anomalies">
          {loadingOperations ? <Loading label="Loading incidents from backend..." /> : instIncidents.length ? (
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
              No incidents were returned for this institution.
            </div>
          )}
        </Card>
      </div>

      {confirmStatus && (
        <ActionDialog
          title={`Confirm Action: ${confirmStatus.toUpperCase()}`}
          desc={`Are you sure you want to transition ${inst?.name} to ${confirmStatus}?`}
          confirmLabel={`Set to ${confirmStatus}`}
          danger={confirmStatus !== 'active'}
          onClose={() => setConfirmStatus(null)}
          onConfirm={(reason) => handleStatusChange(confirmStatus, reason)}
        />
      )}
    </Page>
  );
}
