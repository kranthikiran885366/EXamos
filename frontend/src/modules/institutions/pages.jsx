import { getOrgTerms, isCorporateEntity } from './service';
import { useMemo, useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import * as Api from '../../core/api/services';
import { Page, Card, Stat, StatGrid, Badge, DataTable, Modal, Field, Input, Select, Textarea, Checkbox, ActionDialog, Flash, useFlash, KeyValue, Tabs, Empty, Icon, CopyField } from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { canonicalPlan, formatExamSchedule } from '../../core/ui/normalizers';
import {
  createInstitution, updateInstitution, setInstitutionStatus,
  createCampus, updateCampus, setCampusStatus,
  createDepartment, setDepartmentStatus,
  assignStaff, removeStaff, saveExamDefaults, saveSecuritySettings, institutionStats,
  submitInstitutionApplication, fetchInstitutionApplications, fetchInstitutionApplication,
  provisionApplication, fetchInstitutionAgreements, createAgreementDraft,
  signAgreement, fetchInstitutionLicense, updateInstitutionLicense, checkEntitlements,
  fetchInstitutionDeployments, assignDeployment, pushDeployment, fetchInstitutionOnboarding, updateOnboardingStep,
  DEPLOYMENT_MODELS, TIMEZONES, DEPT_TYPES
} from './service';

const PLAN_OPTIONS = [
  { v: 'pilot', l: 'Pilot' },
  { v: 'standard', l: 'Standard' },
  { v: 'enterprise', l: 'Enterprise' }
];
const PLAN_FILTER_OPTIONS = [...PLAN_OPTIONS, { v: 'unassigned', l: 'Not assigned' }];

const CHANNEL_OPTIONS = [
  { v: 'stable', l: 'Stable release (production)' },
  { v: 'pilot', l: 'Pilot release (staging)' },
  { v: 'canary', l: 'Canary release (experimental)' }
];

const HARDWARE_PROFILES = [
  { v: 'standard-uefi', l: 'Standard UEFI (TPM 2.0 + Secure Boot)' },
  { v: 'legacy-tpm', l: 'Legacy TPM 1.2 / 2.0 compatible' },
  { v: 'secure-kiosk', l: 'Ultra-Secure Hardware Appliance' }
];

const SECURITY_PROFILES = [
  { v: 'high-assurance', l: 'High assurance (Strict attestation)' },
  { v: 'hardened', l: 'Hardened (Network isolation + memory lockdown)' },
  { v: 'air-gapped', l: 'Air-gapped (Local storage verification)' }
];

function InstitutionForm({ value = {}, onSubmit, onClose, busy }) {
  const [f, setF] = useState({
    name: '', code: '', contactEmail: '', contactPhone: '',
    region: '', timezone: '', plan: '',
    maxCenters: '', maxCandidates: '', deploymentModel: '',
    ...value,
    domains: Array.isArray(value.domains) ? value.domains.join(' ') : value.domains || ''
  });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  return (
    <form id="inst-form" onSubmit={(e) => { e.preventDefault(); onSubmit(f); }} className="formgrid">
      <Field label="Institution name" required><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
      <Field label="Code" help="Leave blank to generate"><Input value={f.code} onChange={set('code')} maxLength={20} /></Field>
      <Field label="Email domains" help="Space or comma separated"><Input value={f.domains} onChange={set('domains')} maxLength={300} /></Field>
      <Field label="Contact email"><Input type="email" value={f.contactEmail} onChange={set('contactEmail')} maxLength={120} /></Field>
      <Field label="Contact phone"><Input value={f.contactPhone} onChange={set('contactPhone')} maxLength={30} /></Field>
      <Field label="Region"><Input value={f.region} onChange={set('region')} maxLength={40} /></Field>
      <Field label="Timezone"><Select value={f.timezone} onChange={set('timezone')} options={TIMEZONES} placeholder="Select timezone" /></Field>
      <Field label="Plan"><Select value={f.plan} onChange={set('plan')} options={PLAN_OPTIONS} placeholder="Select plan" /></Field>
      <Field label="Max centres"><Input type="number" min="1" max="200" value={f.maxCenters} onChange={set('maxCenters')} /></Field>
      <Field label="Max candidates"><Input type="number" min="10" max="100000" value={f.maxCandidates} onChange={set('maxCandidates')} /></Field>
      <Field label="Deployment model" className="span2"><Select value={f.deploymentModel} onChange={set('deploymentModel')} options={DEPLOYMENT_MODELS} placeholder="Select deployment model" /></Field>
      <div className="form-actions span2">
        <button type="button" className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={busy}>Save institution</button>
      </div>
    </form>
  );
}

export function InstitutionsPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const [tenants, setTenants] = useState([]);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(true);
  const { msg, run, busy, setMsg } = useFlash();
  const [create, setCreate] = useState(false);
  const [action, setAction] = useState(null);
  const canCreate = can(user.role, 'tenant.manage');

  useEffect(() => {
    let cancelled = false;
    const fetchBackend = async () => {
      setLoading(true);
      try {
        const res = await Api.listInstitutions();
        const backendList = res?.institutions || res || [];
        if (!Array.isArray(backendList)) throw new Error('Unexpected institution response.');
        const mapped = backendList.map((t) => ({
          id: t.id || t.institution_id,
          name: t.name,
          code: t.code,
          /* Normalize status — backend may return 'active', 'ACTIVE', 'provisioned', etc. */
          status: (t.status || '').toLowerCase().replace('provisioned', 'active').replace('verified', 'active') || 'active',
          plan: canonicalPlan(t),
          region: t.region || '', timezone: t.timezone || '',
          maxCenters: t.maxCenters ?? null, maxCandidates: t.maxCandidates ?? null,
          deploymentModel: t.deploymentModel || '',
          contactEmail: t.contactEmail || '', contactPhone: t.contactPhone || '',
          domains: t.domains || [], examDefaults: t.examDefaults || null,
          security: t.security || null, notificationPrefs: t.notificationPrefs || null,
          createdAt: t.createdAt || null,
        })).filter((t) => t.id && t.name);
        if (!cancelled) {
          setTenants(mapped);
          setLoadError('');
        }
      } catch (err) {
        if (!cancelled) setLoadError(err.message || 'Unable to load institutions from the backend.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchBackend();
    return () => { cancelled = true; };
  }, []);

  // Live per-institution stats fetched from backend
  const [statsMap, setStatsMap] = useState({});
  const [statsErrors, setStatsErrors] = useState({});
  useEffect(() => {
    let active = true;
    setStatsMap({});
    setStatsErrors({});
    Promise.all(tenants.map(async (t) => {
      try {
        const stats = await institutionStats(t.id);
        if (active) setStatsMap((prev) => ({ ...prev, [t.id]: stats }));
      } catch (error) {
        if (active) setStatsErrors((prev) => ({ ...prev, [t.id]: error.message || 'Statistics unavailable.' }));
      }
    }));
    return () => { active = false; };
  }, [tenants]);

  return (
    <Page
      title="Institutions"
      desc="Enterprise institutional tenants, multi-campus governance, contracts, and OS assignments."
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          <Link to="/admin/institution-applications" className="btn">
            <Icon name="checklist" size={15} /> Applications queue
          </Link>
          {canCreate && (
            <button className="btn primary" onClick={() => setCreate(true)}>
              <Icon name="plus" size={15} /> New institution
            </button>
          )}
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Alert tone="danger" title="Failed to load institutions">{loadError}</Alert>}
      <StatGrid cols={4}>
        <Stat label="Institutions" value={loading ? '…' : tenants.length} icon="building" />
        <Stat label="Active" value={loading ? '…' : tenants.filter((t) => t.status === 'active').length} tone="green" icon="check" />
        <Stat label="Suspended" value={loading ? '…' : tenants.filter((t) => t.status === 'suspended').length} tone="amber" icon="warn" />
        <Stat
          label="Accounts"
          value={loading ? '…' : Object.keys(statsMap).length === tenants.length
            ? Object.values(statsMap).reduce((s, x) => s + x.users, 0)
            : '—'}
          tone="violet"
          icon="users"
        />
      </StatGrid>
      {Object.keys(statsErrors).length > 0 && (
        <Flash
          msg={{ tone: 'warning', text: `Live statistics are unavailable for ${Object.keys(statsErrors).length} institution(s).` }}
          onClose={() => setStatsErrors({})}
        />
      )}

      <DataTable
        rows={tenants}
        search={['name', 'code', 'region']}
        title="Institutional Tenants"
        desc="Select an institution to inspect sites, legal agreements, enforceable licenses, and assigned OS releases."
        filters={[
          { key: 'status', label: 'Status', options: ['active', 'suspended', 'archived'] },
          { key: 'plan', label: 'Plan', get: (t) => t.plan || 'unassigned', options: PLAN_FILTER_OPTIONS }
        ]}
        columns={[
          {
            key: 'name',
            label: 'Institution',
            sortable: true,
            render: (t) => (
              <>
                <Link to={`/admin/institutions/${t.id}`}><b>{t.name}</b></Link>
                <br />
                <small className="muted">{t.code} · {t.region || '—'}</small>
              </>
            )
          },
          { key: 'plan', label: 'Plan', render: (t) => <Badge value={t.plan || 'Not assigned'} /> },
          { key: 'status', label: 'Status', badge: true },
          { key: 'users', label: 'Accounts', render: (t) => statsMap[t.id]?.users ?? '—' },
          { key: 'exams', label: 'Exams', render: (t) => statsMap[t.id]?.exams ?? '—' },
          { key: 'devices', label: 'Devices', render: (t) => statsMap[t.id]?.devices ?? '—' },
          { key: 'createdAt', label: 'Created', render: (t) => fmt(t.createdAt) },
        ]}
        actions={(t) => [
          { label: 'Manage', onClick: () => nav(`/admin/institutions/${t.id}`) },
          ...(canCreate && ['active', 'suspended'].includes(t.status) ? [{
            label: t.status === 'active' ? 'Suspend' : 'Activate',
            danger: t.status === 'active',
            onClick: () => setAction({ t, status: t.status === 'active' ? 'suspended' : 'active' })
          }] : []),
        ]}
        onRow={(t) => nav(`/admin/institutions/${t.id}`)}
      />

      {create && (
        <Modal title="Register institution" desc="Provisions a tenant, cryptographic policy space, and default license." onClose={() => setCreate(false)}>
          <InstitutionForm
            busy={busy}
            onClose={() => setCreate(false)}
            onSubmit={(f) => run(async () => {
              await createInstitution(user, f);
              setCreate(false);
              return 'Institution registered successfully with full tenant ecosystem.';
            }, 'Institution registered.')}
          />
        </Modal>
      )}

      {action && (
        <ActionDialog
          title={`${action.status === 'suspended' ? 'Suspend' : 'Activate'} ${action.t.name}`}
          desc="Suspension blocks publishing and starting exams across all sites. Recorded in tamper-evident ledger."
          danger={action.status === 'suspended'}
          confirmLabel={action.status === 'suspended' ? 'Suspend institution' : 'Activate institution'}
          onClose={() => setAction(null)}
          onConfirm={(reason) => run(async () => {
            await setInstitutionStatus(user, action.t, action.status, reason);
            setAction(null);
          })}
        />
      )}
    </Page>
  );
}

const mapInstitution = (t) => ({
  id: t.id || t.institution_id,
  name: t.name,
  code: t.code,
  status: t.status || null,
  plan: canonicalPlan(t),
  region: t.region || '',
  timezone: t.timezone || '',
  maxCenters: t.maxCenters ?? null,
  maxCandidates: t.maxCandidates ?? null,
  deploymentModel: t.deploymentModel || '',
  contactEmail: t.contactEmail || '',
  contactPhone: t.contactPhone || '',
  domains: Array.isArray(t.domains) ? t.domains : [],
  examDefaults: t.examDefaults || null,
  security: t.security || null,
  notificationPrefs: t.notificationPrefs || null,
  createdAt: t.createdAt || null,
});

const INSTITUTION_DETAIL_TAB_KEYS = ['onboarding', 'agreements', 'license', 'deployments', 'overview', 'campuses', 'centres', 'settings'];

export function InstitutionDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const { msg, run, busy, setMsg } = useFlash();

  const requestedTab = searchParams.get('tab');
  const tab = INSTITUTION_DETAIL_TAB_KEYS.includes(requestedTab) ? requestedTab : 'onboarding';
  const tabsRef = useRef(null);
  const [edit, setEdit] = useState(false);
  const [signModal, setSignModal] = useState(null);
  const [draftModal, setDraftModal] = useState(false);
  const [deployModal, setDeployModal] = useState(false);
  const [onboardingAction, setOnboardingAction] = useState(null);
  const [entitlementCheckResult, setEntitlementCheckResult] = useState(null);

  // The backend is the source of truth for institution records and metrics.
  const [tenant, setTenant] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [agreements, setAgreements] = useState([]);
  const [license, setLicense] = useState(null);
  const [deployments, setDeployments] = useState([]);
  const [onboarding, setOnboarding] = useState(null);
  const [liveStats, setLiveStats] = useState(null);
  const [liveCampuses, setLiveCampuses] = useState([]);
  const [liveCenters, setLiveCenters] = useState([]);
  const [liveDevices, setLiveDevices] = useState([]);
  const [subErrors, setSubErrors] = useState([]);
  const { msg: flashMsg, setMsg: setFlashMsg } = useFlash();

  const flash = (tone, text) => setFlashMsg({ tone, text });

  const t = tenant;

  const loadDetails = async () => {
    if (!id) return;
    setLoading(true);
    setLoadError('');
    setSubErrors([]);
    setAgreements([]);
    setLicense(null);
    setDeployments([]);
    setOnboarding(null);
    setLiveStats(null);
    setLiveCampuses([]);
    setLiveCenters([]);
    setLiveDevices([]);
    try {
      const inst = await Api.getInstitution(id);
      if (!inst || !(inst.id || inst.institution_id)) {
        throw new Error('The backend did not return this institution.');
      }
      const mapped = mapInstitution(inst);
      setTenant(mapped);

      const results = await Promise.allSettled([
        fetchInstitutionAgreements(id),
        fetchInstitutionLicense(id),
        fetchInstitutionDeployments(id),
        fetchInstitutionOnboarding(id),
        institutionStats(id),
        Api.listCampuses(id),
        Api.listCenters(id),
        Api.listRegisteredDevices(),
      ]);
      const [agRes, licRes, depRes, onbRes, statsRes, campRes, centerRes, deviceRes] = results;
      const errors = [];
      const take = (r, label) => {
        if (r.status === 'fulfilled') return r.value;
        errors.push(`${label}: ${r.reason?.message || 'request failed'}`);
        return null;
      };
      const ag = take(agRes, 'Agreements');
      const lic = take(licRes, 'License');
      const dep = take(depRes, 'Deployments');
      const onb = take(onbRes, 'Onboarding');
      const st = take(statsRes, 'Statistics');
      const cp = take(campRes, 'Campuses');
      const ct = take(centerRes, 'Centres');
      const dv = take(deviceRes, 'Devices');
      setAgreements(Array.isArray(ag) ? ag : []);
      setLicense(lic || null);
      setDeployments(Array.isArray(dep) ? dep : []);
      setOnboarding(onb || null);
      setLiveStats(st || null);
      const campList = cp?.campuses || cp || [];
      if (Array.isArray(campList)) setLiveCampuses(campList
        .filter(c => (c.tenantId || c.tenant_id || c.institution_id) === id)
        .map(c => ({ ...c, id: c.id || c.campus_id, tenantId: c.tenantId || c.tenant_id || c.institution_id })));
      const centerList = ct?.centers || ct || [];
      if (Array.isArray(centerList)) setLiveCenters(centerList
        .filter(c => (c.tenantId || c.tenant_id || c.institution_id) === id)
        .map(c => ({ ...c, id: c.id || c.center_id, tenantId: c.tenantId || c.tenant_id || c.institution_id })));
      const deviceList = dv?.devices || dv || [];
      if (Array.isArray(deviceList)) {
        setLiveDevices(deviceList
          .filter(d => (d.tenantId || d.tenant_id || d.institution_id) === id)
          .map(d => ({
            ...d,
            tenantId: d.tenantId || d.tenant_id || d.institution_id,
            centerId: d.centerId || d.center_id,
          })));
      }
      setSubErrors(errors);
    } catch (e) {
      setLoadError(e.message || 'Unable to load institution from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const loadAll = loadDetails;

  useEffect(() => {
    setTenant(null);
    loadDetails();
  }, [id]);

  useEffect(() => {
    if (!loading && t) tabsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [tab, loading, t]);

  const selectTab = (nextTab) => {
    if (!INSTITUTION_DETAIL_TAB_KEYS.includes(nextTab)) return;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (nextTab === 'onboarding') next.delete('tab');
      else next.set('tab', nextTab);
      return next;
    }, { replace: true });
  };

  const stats = useMemo(() => ({
    campuses:    liveStats?.campuses    ?? '—',
    departments: liveStats?.departments ?? '—',
    centers:     liveStats?.centers     ?? '—',
    users:       liveStats?.users       ?? '—',
    devices:     liveStats?.devices     ?? '—',
    exams:       liveStats?.exams       ?? '—',
    candidates:  liveStats?.candidates  ?? '—',
    incidents:   liveStats?.openIncidents ?? '—',
  }), [liveStats]);

  if (loading) {
    return (
      <Page title="Loading institution">
        <Flash msg={{ tone: 'info', text: 'Loading institution from the backend…' }} onClose={() => {}} />
      </Page>
    );
  }

  if (!t) {
    return (
      <Page title="Institution unavailable">
        <Flash msg={{ tone: 'danger', text: loadError || 'No such institution.' }} onClose={() => {}} />
        <Empty icon="building" title="No such institution" action={<Link className="btn" to="/admin/institutions">Back to institutions</Link>} />
      </Page>
    );
  }

  const tabs = [
    { key: 'onboarding', label: 'Onboarding lifecycle' },
    { key: 'agreements', label: 'Agreements & signatures', count: agreements.length },
    { key: 'license', label: 'License & entitlements' },
    { key: 'deployments', label: 'OS deployments', count: deployments.length },
    { key: 'overview', label: 'Profile' },
    { key: 'campuses', label: 'Campuses', count: stats.campuses },
    { key: 'centres', label: 'Centres', count: stats.centers },
    { key: 'settings', label: 'Settings' }
  ];

  return (
    <Page
      title={t.name}
      desc={`${t.code} · ${t.region || '—'}${t.plan ? ` · Plan: ${t.plan.toUpperCase()}` : ''} · Multi-Campus Tenant`}
      breadcrumb={
        <div className="crumbs-inline">
          <Link to="/admin/institutions">Institutions</Link>
          <Icon name="arrow" size={12} />
          <span>{t.code}</span>
        </div>
      }
      actions={
        <div style={{ display: 'flex', gap: '8px' }}>
          {can(user.role, 'inst.manage') && (
            <button className="btn" onClick={() => setEdit(true)}>Edit settings</button>
          )}
          <Badge value={t.status} tone={t.status === 'active' ? 'green' : 'amber'} />
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {subErrors.length > 0 && (
        <Flash
          msg={{ tone: 'danger', text: `Some institution data could not be loaded from the backend: ${subErrors.join('; ')}` }}
          onClose={() => setSubErrors([])}
        />
      )}
      <StatGrid cols={4}>
        <Stat label="Campuses" value={stats.campuses} icon="pin" />
        <Stat label="Centres" value={stats.centers} icon="building" />
        <Stat label="Devices" value={stats.devices} icon="device" />
        <Stat label="Accounts" value={stats.users} icon="users" />
        <Stat label="Live / Total Exams" value={`${liveStats?.liveExams ?? '—'} / ${stats.exams}`} icon="exam" />
        <Stat label="Candidates" value={stats.candidates} icon="candidate" />
        <Stat label="License Status" value={license?.status || '—'} tone={license?.status === 'ACTIVE' ? 'green' : 'amber'} icon="shield" />
        <Stat label="Open Incidents" value={stats.incidents} tone={stats.incidents ? 'amber' : 'green'} icon="alert" />
      </StatGrid>

      <div ref={tabsRef} style={{ scrollMarginTop: '16px' }}>
        <Tabs tabs={tabs} value={tab} onChange={selectTab} />
      </div>

      {/* 1. Onboarding Lifecycle Tab */}
      {tab === 'onboarding' && (
        <div className="two">
          <Card title="Platform onboarding attestations" desc="Steps are operator-attested records, not automatic evidence of operational readiness.">
            <div style={{ marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <b>Lifecycle Stage: <Badge value={onboarding?.status || '—'} tone={onboarding?.status ? 'green' : 'amber'} /></b>
                <span><b>{onboarding?.completedSteps ?? '—'}</b> of {onboarding?.totalSteps ?? '—'} steps completed</span>
              </div>
              <div style={{ height: '8px', background: 'var(--border, #e2e8f0)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${onboarding?.totalSteps ? Math.min(100, (onboarding.completedSteps / onboarding.totalSteps) * 100) : 0}%`, height: '100%', background: 'var(--primary, #2f5bea)' }} />
              </div>
            </div>

            <ul className="activity">
              {[
                { k: 'registration', title: '1. Legal Entity Registration', desc: 'Capture name, official registration number, and operating addresses.' },
                { k: 'identity_verification', title: '2. Identity & Domain Verification', desc: 'Verification of authorized legal representative and official domain DNS.' },
                { k: 'agreement', title: '3. Master Services Agreement & E-Signature', desc: 'MSA & SLA covenants digitally signed with cryptographic SHA256 audit digest.' },
                { k: 'license', title: '4. License Entitlements Activation', desc: 'Enforceable limits assigned for sites, devices, candidates/examinees, and exam volume.' },
                { k: 'admin_mfa', title: '5. Primary Administrator MFA Setup', desc: 'First institutional administrator invited and multi-factor authentication enforced.' },
                { k: 'campus_hierarchy', title: '6. Sites & Org Structure', desc: 'Establish sites, departments / business units, examination centres, and seat allocation.' },
                { k: 'os_deployment', title: '7. ExamOS Release & Hardware Assignment', desc: 'Approved bootable OS releases, channels (stable/pilot), and security policies assigned.' },
                { k: 'production_readiness', title: '8. Operational Readiness & Go-Live', desc: 'Hardware health check, TPM attestation verification, and exam scheduling authorized.' },
              ].map((step) => {
                const isDone = onboarding?.checklist?.[step.k]?.completed === true;
                const stepMeta = onboarding?.checklist?.[step.k];
                return (
                  <li key={step.k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '10px 0', borderBottom: '1px solid var(--border, #eee)' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Icon name={isDone ? 'check' : 'circle'} size={16} />
                        <b>{step.title}</b>
                        {isDone ? <Badge value="Attested" tone="green" /> : <Badge value="Not attested" tone="amber" />}
                      </div>
                      <small className="muted" style={{ display: 'block', marginLeft: '24px', marginTop: '4px' }}>
                        {step.desc}
                        {stepMeta?.notes && <><br /><b>Operator notes:</b> {stepMeta.notes}</>}
                      </small>
                    </div>
                    {user.role === 'superadmin' && (
                      <button
                        className="btn small"
                        disabled={busy}
                        onClick={() => setOnboardingAction({ step, completed: !isDone })}
                      >
                        {isDone ? 'Revoke attestation' : 'Record attestation'}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          </Card>

          <div>
            <Card title="Tenant Isolation & Trust Posture" desc="Cryptographic isolation properties for this institutional boundary.">
              <KeyValue items={[
                ['Tenant Identifier', id],
                ['Database Scope', 'Institution-scoped backend records'],
                ['Tamper-Evident Ledger', 'See the institution audit page for current status'],
                ['MFA Policy', onboarding?.mfaEnforced ? 'Enforced' : 'Not confirmed'],
                ['Assigned Release', deployments[0]?.releaseId || '—'],
                ['Release Channel', deployments[0]?.channel?.toUpperCase() || '—'],
                ['Hardware Profile', deployments[0]?.hardwareProfile || '—'],
              ]} />
            </Card>
          </div>
        </div>
      )}

      {/* 2. Agreements & E-Signatures Tab */}
      {tab === 'agreements' && (
        <div>
          <DataTable
            rows={agreements}
            title="Legal Documents & Digital Signatures"
            desc="Master Services Agreements, Data Protection Addendums, and Service Level Agreements."
            actions={(ag) => [
              ...(ag.status !== 'EXECUTED' ? [{
                label: 'Sign digitally',
                onClick: () => setSignModal(ag)
              }] : [{
                label: 'View details',
                onClick: () => alert(`Agreement ${ag.title} is EXECUTED.\nDigest: ${ag.documentDigest}\nSigner: ${ag.signerName} (${ag.signerEmail})`)
              }])
            ]}
            columns={[
              {
                key: 'title',
                label: 'Agreement Document',
                render: (ag) => (
                  <>
                    <b>{ag.title}</b>
                    <br />
                    <small className="muted">Type: {ag.type.toUpperCase()} · Version: {ag.version}</small>
                  </>
                )
              },
              { key: 'status', label: 'Status', render: (ag) => <Badge value={ag.status} tone={ag.status === 'EXECUTED' ? 'green' : 'amber'} /> },
              { key: 'signer', label: 'Signer', render: (ag) => ag.signerName ? `${ag.signerName} (${ag.signerRole || 'Representative'})` : '—' },
              { key: 'digest', label: 'Signature Digest', render: (ag) => ag.documentDigest ? <code>{ag.documentDigest.slice(0, 16)}...</code> : '—' },
              { key: 'signedAt', label: 'Signed Date', render: (ag) => ag.signedAt ? fmt(ag.signedAt) : 'Pending' },
            ]}
          />

          {signModal && (
            <Modal
              title={`Sign ${signModal.title}`}
              desc="Enter authorized representative credentials to record a cryptographic digital signature."
              onClose={() => setSignModal(null)}
              footer={
                <>
                  <button className="btn" onClick={() => setSignModal(null)}>Cancel</button>
                  <button className="btn primary" form="sign-form" disabled={busy}>Execute Signature</button>
                </>
              }
            >
              <form
                id="sign-form"
                className="formgrid"
                onSubmit={(e) => {
                  e.preventDefault();
                  const form = e.target;
                  run(async () => {
                    await signAgreement(user, signModal.id, {
                      signerName: form.signerName.value,
                      signerEmail: form.signerEmail.value,
                      signerRole: form.signerRole.value,
                    });
                    setSignModal(null);
                    await loadDetails();
                    return 'Agreement executed and digital signature digest committed to ledger.';
                  });
                }}
              >
                <Field label="Signer legal name" required className="span2">
                  <Input name="signerName" defaultValue={user.name || ''} required />
                </Field>
                <Field label="Official representative email" required className="span2">
                  <Input type="email" name="signerEmail" defaultValue={user.email || t.contactEmail || ''} required />
                </Field>
                <Field label="Role / Authority title" required className="span2">
                  <Input name="signerRole" defaultValue="Authorized Representative" required />
                </Field>
                <div className="span2 muted" style={{ fontSize: '13px', background: 'var(--card-bg, #f8fafc)', padding: '10px', borderRadius: '6px' }}>
                  By signing, you certify legal authority to bind this institution to ExamOS Examination Covenants and SLA standards. A SHA256 document digest will be recorded permanently in the tamper-evident ledger.
                </div>
              </form>
            </Modal>
          )}
        </div>
      )}

      {/* 3. License & Entitlements Tab */}
      {tab === 'license' && (
        <div className="two">
          <Card
            title="Enforceable License Agreement"
            desc="Runtime limits enforced across sites, managed devices, candidates/examinees, and exam schedules."
            actions={
              <button
                className="btn small"
                disabled={busy}
                onClick={() => run(async () => {
                  const check = await checkEntitlements(id, 'campuses');
                  setEntitlementCheckResult(check);
                  return 'Entitlements verified live against license constraints.';
                })}
              >
                Verify Live Entitlements
              </button>
            }
          >
            <KeyValue items={[
              ['License Plan', canonicalPlan({ planId: license?.plan }) || canonicalPlan(t) || 'Not assigned'],
              ['Plan Version', license?.planVersion || '—'],
              ['License Status', license?.status ? <Badge key="st" value={license.status} tone={license.status === 'ACTIVE' ? 'green' : 'amber'} /> : '—'],
              ['Valid From', license?.validFrom ? fmt(license.validFrom) : '—'],
              ['Valid Until', license?.validUntil ? fmt(license.validUntil) : '—'],
              ['Grace Period', license?.gracePeriodDays != null ? `${license.gracePeriodDays} days` : '—'],
              ['Allowed OS Channels', (license?.allowedChannels || []).join(', ') || '—'],
              ['Enabled Modules', (license?.enabledModules || []).join(', ') || '—'],
            ]} />
          </Card>

          <Card title="Resource Quotas vs Live Usage" desc="Automatic server-enforced quotas.">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {[
                { label: 'Campuses', usage: license?.usage?.campuses ?? stats.campuses, limit: license?.maxCampuses ?? t.maxCenters ?? '—' },
                { label: 'Managed Devices', usage: license?.usage?.devices ?? stats.devices, limit: license?.maxDevices ?? '—' },
                { label: 'Candidate Capacity', usage: license?.usage?.candidates ?? stats.candidates, limit: license?.maxCandidates ?? t.maxCandidates ?? '—' },
                { label: 'Exam Windows', usage: license?.usage?.exams ?? stats.exams, limit: license?.maxExams ?? '—' },
              ].map((res) => {
                const pct = res.limit === '—' || !res.limit ? 0 : Math.min(100, Math.round((res.usage / res.limit) * 100));
                return (
                  <div key={res.label}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <b>{res.label}</b>
                      <span><b>{res.usage}</b> / {res.limit} ({pct}%)</span>
                    </div>
                    <div style={{ height: '8px', background: 'var(--border, #e2e8f0)', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: pct > 90 ? 'var(--danger, #e53e3e)' : 'var(--primary, #2f5bea)' }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {entitlementCheckResult && (
              <div style={{ marginTop: '16px', padding: '12px', background: entitlementCheckResult.allowed ? '#f0fdf4' : '#fef2f2', border: '1px solid var(--border)', borderRadius: '6px' }}>
                <b>Entitlement Check Result:</b> {entitlementCheckResult.allowed ? 'PASSED — Resource creation permitted' : 'RESTRICTED — Limit reached'}
                <br />
                <small className="muted">{entitlementCheckResult.reason}</small>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* 4. OS Deployments Tab */}
      {tab === 'deployments' && (
        <div>
          <DataTable
            rows={deployments}
            title="ExamOS Operating System Deployments"
            desc="Operating system release assignments, rollout channels, and hardware security profiles."
            actions={(dep) => [
              {
                label: 'Push to OS Kiosks',
                onClick: () => run(async () => {
                  await pushDeployment(user, dep.id);
                  await loadDetails();
                  return 'Deployment pushed and synchronized to live ExamOS kiosk fleet.';
                })
              },
              {
                label: 'Rollout policy',
                onClick: () => alert(`Deployment ${dep.releaseId} on ${dep.channel} channel.\nPolicy Hash: ${dep.policyHash || 'sha256-standard'}\nHardware Profile: ${dep.hardwareProfile}`)
              }
            ]}
            columns={[
              {
                key: 'releaseId',
                label: 'OS Release',
                render: (dep) => (
                  <>
                    <b>{dep.releaseId}</b>
                    <br />
                    <small className="muted">Target: {dep.campusId ? `Campus ${dep.campusId}` : 'All Campuses (Global)'}</small>
                  </>
                )
              },
              { key: 'channel', label: 'Rollout Channel', render: (dep) => <Badge value={dep.channel} tone={dep.channel === 'stable' ? 'green' : 'amber'} /> },
              { key: 'hardwareProfile', label: 'Hardware Profile' },
              { key: 'securityProfile', label: 'Security Profile' },
              { key: 'status', label: 'Status', render: (dep) => <Badge value={dep.status} /> },
              { key: 'devices', label: 'Devices Acknowledged', render: (dep) => `${dep.devicesAcknowledged || 0} / ${dep.devicesTargeted || 0}` },
              { key: 'updatedAt', label: 'Last Deployed', render: (dep) => fmt(dep.updatedAt || dep.createdAt) },
            ]}
          />
        </div>
      )}

      {/* 5. Profile Tab */}
      {tab === 'overview' && (
        <div className="two">
          <Card title="Institution profile">
            <KeyValue items={[
              ['Legal name', t.name],
              ['Code', t.code],
              ['Domains', (t.domains || []).join(', ') || '—'],
              ['Contact', t.contactEmail || '—'],
              ['Phone', t.contactPhone || '—'],
              ['Region', t.region],
              ['Timezone', t.timezone],
              ['Deployment', t.deploymentModel],
              ['Created', fmt(t.createdAt)],
              ['Plan', t.plan || 'Not assigned']
            ]} />
          </Card>
          <Card title="Limits & security">
            <KeyValue items={[
              ['Max centres', t.maxCenters],
              ['Max candidates', t.maxCandidates],
              ['Require TPM', t.security?.requireTpm ? 'Yes' : 'No'],
              ['Require Secure Boot', t.security?.requireSecureBoot ? 'Yes' : 'No'],
              ['USB storage', t.security?.allowUsbStorage ? 'Allowed' : 'Blocked'],
              ['Exam duration default', t.examDefaults?.durationMin != null ? `${t.examDefaults.durationMin} min` : '—'],
              ['Late entry', t.examDefaults?.lateEntryMin != null ? `${t.examDefaults.lateEntryMin} min` : '—'],
              ['Attestation', t.examDefaults?.attestationLevel || '—']
            ]} />
          </Card>
          <Card title="Recent history" className="span2">
            <ul className="activity">
              {(t.history || []).slice().reverse().map((h, i) => (
                <li key={i}>
                  <span className="act-dot" />
                  <div>
                    <b>{h.action}</b>
                    <small className="muted">{h.by || 'system'} · {ago(h.at)} {h.reason ? '· ' + h.reason : ''}</small>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      {tab === 'campuses' && (
        <DataTable
          rows={liveCampuses}
          search={['name', 'code', 'city']}
          columns={[
            { key: 'name', label: 'Campus', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code}</small></> },
            { key: 'city', label: 'City' },
            { key: 'capacity', label: 'Capacity' },
            { key: 'centers', label: 'Centres', render: (c) => liveCenters.filter((x) => (x.campusId || x.campus_id) === c.id).length },
            { key: 'status', label: 'Status', badge: true }
          ]}
          actions={(c) => [{ label: 'Open campuses', onClick: () => nav(`/admin/institutions/${id}?tab=campuses`) }]}
        />
      )}

      {tab === 'centres' && (
        <DataTable
          rows={liveCenters}
          search={['name', 'code', 'city']}
          columns={[
            { key: 'code', label: 'Code' },
            { key: 'name', label: 'Centre' },
            { key: 'city', label: 'City' },
            { key: 'capacity', label: 'Seats' },
            { key: 'devices', label: 'Devices', render: (c) => liveDevices.filter((d) => d.centerId === c.id).length },
            { key: 'status', label: 'Status', badge: true }
          ]}
        />
      )}

      {tab === 'settings' && (
        <Card title="Operating settings" desc="These defaults are applied to new exams.">
          <KeyValue items={[
            ['Deployment', t.deploymentModel || '—'],
            ['Exam duration', t.examDefaults?.durationMin != null ? `${t.examDefaults.durationMin} minutes` : '—'],
            ['Late entry', t.examDefaults?.lateEntryMin != null ? `${t.examDefaults.lateEntryMin} minutes` : '—'],
            ['Attestation', t.examDefaults?.attestationLevel || '—'],
            ['Notification email', t.notificationPrefs?.email ? 'On' : 'Off'],
            ['In-app notifications', t.notificationPrefs?.inApp ? 'On' : 'Off']
          ]} />
        </Card>
      )}

      {edit && (
        <Modal title="Edit institution" wide onClose={() => setEdit(false)}>
          <InstitutionForm
            value={t}
            busy={busy}
            onClose={() => setEdit(false)}
            onSubmit={(f) => run(async () => {
              await updateInstitution(user, t, f);
              setEdit(false);
              await loadDetails();
            })}
          />
        </Modal>
      )}
      {onboardingAction && (
        <Modal
          title={`${onboardingAction.completed ? 'Attest' : 'Revoke attestation'}: ${onboardingAction.step.title}`}
          desc="Record the evidence checked and the basis for this platform decision. This note is stored with the backend checklist event."
          onClose={() => setOnboardingAction(null)}
          footer={(
            <>
              <button className="btn" onClick={() => setOnboardingAction(null)}>Cancel</button>
              <button className="btn primary" form="onboarding-attestation-form" disabled={busy}>
                {onboardingAction.completed ? 'Save attestation' : 'Save revocation'}
              </button>
            </>
          )}
        >
          <form
            id="onboarding-attestation-form"
            className="formgrid"
            onSubmit={(event) => {
              event.preventDefault();
              const notes = event.currentTarget.elements.notes.value;
              run(async () => {
                await updateOnboardingStep(user, id, onboardingAction.step.k, onboardingAction.completed, notes);
                setOnboardingAction(null);
                await loadDetails();
                return 'Onboarding attestation updated on the backend.';
              });
            }}
          >
            <Field label="Evidence checked / reason" required className="span2">
              <Textarea name="notes" rows={4} minLength={8} maxLength={240} required placeholder="Describe the evidence reviewed or why the attestation is being revoked." />
            </Field>
          </form>
        </Modal>
      )}
    </Page>
  );
}

export function InstitutionApplicationsPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const { msg, run, busy, setMsg } = useFlash();

  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  const reloadApps = async () => {
    setLoading(true);
    try {
      const list = await fetchInstitutionApplications();
      setApps(list);
      setLoadError('');
    } catch (e) {
      setApps([]);
      setLoadError(e.message || 'Unable to load institution applications from the backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reloadApps();
  }, []);

  return (
    <Page
      title="Institution Onboarding Queue"
      desc="Applications submitted by enterprises, companies, universities, and institutions awaiting identity verification, contracting, and provisioning."
      actions={<button className="btn" onClick={reloadApps} disabled={loading}><Icon name="refresh" size={14} /> Retry / Refresh</button>}
      breadcrumb={
        <div className="crumbs-inline">
          <Link to="/admin/institutions">Institutions</Link>
          <Icon name="arrow" size={12} />
          <span>Applications</span>
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Flash msg={{ tone: 'danger', text: loadError }} onClose={() => setLoadError('')} />}
      <StatGrid cols={4}>
        <Stat label="Total Applications" value={loading ? '…' : loadError ? '—' : apps.length} icon="building" />
        <Stat label="Submitted" value={loading ? '…' : loadError ? '—' : apps.filter((a) => a.status === 'SUBMITTED').length} tone="blue" icon="inbox" />
        <Stat label="Under Review" value={loading ? '…' : loadError ? '—' : apps.filter((a) => a.status === 'UNDER_REVIEW' || a.status === 'VERIFICATION_PENDING').length} tone="amber" icon="pulse" />
        <Stat label="Approved / Provisioned" value={loading ? '…' : loadError ? '—' : apps.filter((a) => a.status === 'APPROVED' || a.status === 'PROVISIONED').length} tone="green" icon="check" />
      </StatGrid>

      <DataTable
        rows={apps}
        title="Application Registry"
        search={['legalName', 'displayName', 'registrationNumber', 'repEmail', 'domain']}
        filters={[
          { key: 'status', label: 'Status', options: ['SUBMITTED', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'APPROVED', 'PROVISIONED', 'REJECTED'] }
        ]}
        columns={[
          {
            key: 'legalName',
            label: 'Applicant Institution',
            render: (a) => (
              <>
                <Link to={`/admin/institution-applications/${a.id}`}><b>{a.legalName}</b></Link>
                <br />
                <small className="muted">{a.entityType.toUpperCase()} · Domain: {a.domain}</small>
              </>
            )
          },
          { key: 'registrationNumber', label: 'Registration No' },
          {
            key: 'rep',
            label: 'Representative',
            render: (a) => `${a.repName || ''} (${a.repEmail || '—'})`
          },
          {
            key: 'scale',
            label: 'Requested Scale',
            render: (a) => `${a.campusCount ?? '—'} sites · ${a.deviceCount ?? '—'} devices`
          },
          { key: 'plan', label: 'Plan', render: (a) => <Badge value={a.plan || '—'} /> },
          {
            key: 'status',
            label: 'Status',
            render: (a) => (
              <Badge
                value={a.status}
                tone={a.status === 'PROVISIONED' ? 'green' : (a.status === 'APPROVED' ? 'blue' : (a.status === 'REJECTED' ? 'red' : 'amber'))}
              />
            )
          },
          { key: 'createdAt', label: 'Submitted', render: (a) => fmt(a.createdAt) },
        ]}
        actions={(a) => [
          { label: 'View Details', onClick: () => nav(`/admin/institution-applications/${a.id}`) },
          ...(['SUBMITTED', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'MORE_INFORMATION_REQUIRED'].includes(a.status) ||
            (a.status === 'APPROVED' && !a.verificationComplete) ? [
            { label: 'Review & Verify', onClick: () => nav(`/platform/institutions/${a.id}/verification`) },
          ] : []),
          ...(a.status === 'APPROVED' && a.verificationComplete ? [{
            label: 'Provision Tenant Now',
            onClick: () => run(async () => {
              const res = await provisionApplication(user, a.id);
              await reloadApps();
              nav(`/admin/institutions/${res.institution_id}`);
              return `Institution ${a.legalName} successfully provisioned!`;
            })
          }] : [])
        ]}
        empty={<Empty icon="building" title={loading ? 'Loading applications…' : loadError ? 'Application data unavailable' : 'No institution applications'} />}
      />
    </Page>
  );
}

export function InstitutionApplicationDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const { msg, run, busy, setMsg } = useFlash();
  const [app, setApp] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  const loadApp = async () => {
    if (!id) {
      setLoadError('Application ID is missing.');
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await fetchInstitutionApplication(id);
      if (!data || !data.id) throw new Error('Backend returned an unexpected institution application.');
      setApp(data);
      setLoadError('');
    } catch (e) {
      setApp(null);
      setLoadError(e.message || 'Unable to load this application from the backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApp();
  }, [id]);

  if (!app) {
    return (
      <Page title="Application Details">
        {loading
          ? <Empty icon="building" title="Loading application details…" />
          : <Flash msg={{ tone: 'danger', text: loadError || 'Application is unavailable.' }} onClose={() => setLoadError('')} />}
        {!loading && <Link className="btn" to="/admin/institution-applications">Back to applications</Link>}
      </Page>
    );
  }

  return (
    <Page
      title={app.legalName}
      desc={`Registration No: ${app.registrationNumber} · Domain: ${app.domain}`}
      breadcrumb={
        <div className="crumbs-inline">
          <Link to="/admin/institution-applications">Applications</Link>
          <Icon name="arrow" size={12} />
          <span>{app.registrationNumber}</span>
        </div>
      }
      actions={
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {app.status === 'APPROVED' && (
            <button
              className="btn primary"
              disabled={busy}
              onClick={() => run(async () => {
                const res = await provisionApplication(user, app.id);
                nav(`/admin/institutions/${res.institution_id}`);
                return 'Institution provisioned successfully!';
              })}
            >
              Provision Tenant Now
            </button>
          )}
          <Badge value={app.status} tone={app.status === 'PROVISIONED' ? 'green' : app.status === 'APPROVED' ? 'blue' : app.status === 'REJECTED' ? 'red' : 'amber'} />
        </div>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />

      {/* Status & What's Next Banner */}
      {['SUBMITTED', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'MORE_INFORMATION_REQUIRED', 'APPROVED'].includes(app.status) && (
        <div style={{ padding: '14px 18px', background: 'rgba(37, 99, 235, 0.06)', border: '1px solid rgba(37, 99, 235, 0.2)', borderRadius: '10px', marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <b style={{ color: 'var(--aubergine, #302337)', fontSize: '14px' }}>
              {app.status === 'SUBMITTED' && '📥 Application received — Start identity & domain verification'}
              {app.status === 'UNDER_REVIEW' && '🔍 Under review — Complete the verification checklist'}
              {app.status === 'VERIFICATION_PENDING' && '⏳ Verification in progress — Check DNS records and signatory docs'}
              {app.status === 'MORE_INFORMATION_REQUIRED' && '📋 Additional information requested — Review the notes and respond to the platform review team'}
              {app.status === 'APPROVED' && '✅ Approved — Ready to provision isolated tenant environment'}
            </b>
            <p className="muted sm" style={{ margin: '3px 0 0' }}>
              {app.status === 'SUBMITTED' && 'Click "Full Verification" to open the detailed verification checklist for this institution.'}
              {app.status === 'UNDER_REVIEW' && 'Verify legal charter, domain ownership, and authorized signatory, then mark as Approved.'}
              {app.status === 'VERIFICATION_PENDING' && 'Awaiting DNS TXT record confirmation and authorization letter from the institution.'}
              {app.status === 'MORE_INFORMATION_REQUIRED' && 'Self-service application editing is not available; provide the requested information to the platform review team using your application reference.'}
              {app.status === 'APPROVED' && 'Click "Provision Tenant Now" above to create the isolated database, cryptographic keys, and license.'}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {(['SUBMITTED', 'UNDER_REVIEW', 'VERIFICATION_PENDING', 'MORE_INFORMATION_REQUIRED'].includes(app.status) ||
              (app.status === 'APPROVED' && !['identity', 'domain', 'accreditation', 'representative', 'datacenter'].every((key) => app.reviewChecklist?.[key] === true))) && (
              <Link to={`/platform/institutions/applications`} className="btn primary compact">Full Verification →</Link>
            )}
          </div>
        </div>
      )}

      <div className="two">
        <Card title="Legal Entity & Identity">
          <KeyValue items={[
            ['Legal Entity Name', app.legalName],
            ['Display Name', app.displayName || app.legalName],
            ['Entity Type', (app.entityType || '—').toUpperCase()],
            ['Official Registration No', app.registrationNumber],
            ['Official Domain', app.domain],
            ['Country / State', [app.country, app.state].filter(Boolean).join(' · ') || '—'],
            ['Registered Address', app.address],
            ['Submitted Date', fmt(app.createdAt)],
            ...(app.reviewNotes ? [['Reviewer Notes', app.reviewNotes]] : []),
          ]} />
        </Card>

        <Card title="Authorized Representatives & Contacts">
          <KeyValue items={[
            ['Authorized Representative', app.repName],
            ['Representative Role', app.repRole],
            ['Representative Email', app.repEmail],
            ['Representative Phone', app.repPhone || '—'],
            ['Exam Coordinator', `${app.coordName || '—'} (${app.coordEmail || '—'})`],
            ['Technical Administrator', `${app.techName || '—'} (${app.techEmail || '—'})`],
          ]} />
        </Card>

        <Card title="Requested Deployment & Scale" className="span2">
          <KeyValue items={[
            ['Campus Count', app.campusCount],
            ['Estimated Student Volume', app.studentCount],
            ['Target Device Fleet', app.deviceCount],
            ['Deployment Model', app.deploymentModel],
            ['Hardware Profile', app.hardwareProfile || '—'],
            ['Requested Plan', (app.plan || '—').toUpperCase()],
          ]} />
        </Card>
      </div>
    </Page>
  );
}

export function CollegeOverviewPage() {
  const { user } = useAuth();
  const { tenant, tenantId } = useTenant();
  const [exams, setExams] = useState([]);
  const [liveStats, setLiveStats] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [examError, setExamError] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadAttempt, setLoadAttempt] = useState(0);

  const retryExams = async () => {
    if (!tenantId) return;
    try {
      setExamError('');
      const raw = await Api.listExaminations();
      const rows = Array.isArray(raw) ? raw : (raw?.examinations ?? raw?.exams ?? []);
      setExams(rows
        .filter(e => e && (e.tenantId || e.tenant_id || e.institution_id) === tenantId)
        .map(e => ({
          ...e,
          id: e.id || e.exam_id,
          code: e.code || e.exam_code,
          status: String(e.status || '').toLowerCase(),
          startAt: e.startAt,
          startTimeState: e.startTimeState,
          timeZone: e.timeZone,
        })));
    } catch (err) {
      setExamError(err.message || 'Exams unavailable');
    }
  };

  useEffect(() => {
    if (!tenantId) {
      setExams([]);
      setLiveStats(null);
      setLoadError('Select an institution to load its overview.');
      setLoading(false);
      return;
    }

    let active = true;
    setLoading(true);
    setLoadError('');
    setExamError('');
    setExams([]);
    setLiveStats(null);
    Promise.allSettled([
      institutionStats(tenantId),
      Api.listExaminations(),
    ]).then(([statsResult, examsResult]) => {
      if (!active) return;
      if (statsResult.status === 'fulfilled') setLiveStats(statsResult.value);
      else setLoadError(`Institution statistics: ${statsResult.reason?.message || 'request failed'}`);

      if (examsResult.status === 'fulfilled') {
        const raw = examsResult.value;
        const rows = Array.isArray(raw) ? raw : (raw?.examinations ?? raw?.exams);
        if (Array.isArray(rows)) {
          setExams(rows
            .filter(e => e && (e.tenantId || e.tenant_id || e.institution_id) === tenantId)
            .map(e => ({
              ...e,
              id: e.id || e.exam_id,
              code: e.code || e.exam_code,
              status: String(e.status || '').toLowerCase(),
              startAt: e.startAt,
              startTimeState: e.startTimeState,
              timeZone: e.timeZone,
            })));
        } else {
          setExamError('Exams: backend returned an unexpected response.');
        }
      } else {
        setExamError(`Exams: ${examsResult.reason?.message || 'request failed'}`);
      }
    }).catch(error => {
      if (active) setLoadError(error?.message || 'Unable to load institution overview.');
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [tenantId, loadAttempt]);

  const examRows = exams.filter(e => ['live', 'published', 'approved'].includes(e.status));

  return (
    <Page
      title={tenant?.name || 'Institution overview'}
      desc="Your institution at a glance, with the controls that matter before an exam window."
      actions={
        <>
          <button className="btn" onClick={() => setLoadAttempt((value) => value + 1)} disabled={loading}><Icon name="refresh" size={14} /> {loading ? 'Loading…' : 'Retry data'}</button>
          <Link className="btn" to="/college/settings">Settings</Link>
          {can(user.role, 'exam.manage') && <Link className="btn primary" to="/college/exams/new">New exam</Link>}
        </>
      }
    >
      {loadError && <Flash msg={{ tone: 'danger', text: `Some overview data could not be loaded from the backend: ${loadError}` }} onClose={() => setLoadError('')} />}
      <StatGrid cols={4}>
        <Stat label="Live exams" value={liveStats?.liveExams ?? '—'} icon="exam" to="/college/exams" />
        <Stat label="Centres" value={liveStats?.centers ?? '—'} icon="building" to="/college/campuses" />
        <Stat label="Devices" value={liveStats?.devices ?? '—'} icon="device" to="/devices" />
        <Stat label="Candidates" value={liveStats?.candidates ?? '—'} icon="candidate" to="/college/candidates" />
        <Stat label="Campuses" value={liveStats?.campuses ?? '—'} icon="pin" to="/college/campuses" />
        <Stat label="Departments" value={liveStats?.departments ?? '—'} icon="layers" to="/college/departments" />
        <Stat label="USB inventory" value="—" icon="usb" to="/usb-inventory" sub="Backend metric unavailable" />
        <Stat label="Open incidents" value={liveStats?.openIncidents ?? '—'} icon="alert" tone="amber" to="/operator/incidents" />
      </StatGrid>
      <div className="two">
        <Card
          title="Exam readiness"
          desc="Live and published windows"
          actions={examError ? <button className="btn small" onClick={retryExams}><Icon name="refresh" size={13} /> Retry exams</button> : null}
        >
          {examError && <Alert tone="warn" title="Examinations notice">{examError}</Alert>}
          <DataTable
            rows={examRows}
            dense
            pageSize={5}
            columns={[
              { key: 'code', label: 'Exam', render: (e) => <Link to={`/college/exams/${e.id}`}><b>{e.code || e.name || e.title || '—'}</b></Link> },
              { key: 'status', label: 'Status', badge: true },
              { key: 'startAt', label: 'Window', render: (e) => formatExamSchedule(e) },
            ]}
            empty={<Empty icon="exam" title={loading ? 'Loading exams…' : examError ? 'Exam data unavailable' : 'No live or published exams'} />}
          />
        </Card>
        <Card title="Staff & access" desc="Accounts linked to this institution">
          <KeyValue items={[
            ['Active accounts', liveStats?.users ?? (loading ? '…' : '—')],
            ['Students', '—'],
            ['Exam controllers', '—'],
            ['Invigilators', '—'],
            ['IT admins', '—'],
            ['Support engineers', '—']
          ]} />
          <div className="quicklinks compact">
            {can(user.role, 'user.manage') && <Link to="/admin/users"><Icon name="users" size={16} /><span>Users</span></Link>}
            <Link to="/college/staff"><Icon name="badge" size={16} /><span>Staff</span></Link>
            <Link to="/college/subscription"><Icon name="card" size={16} /><span>Subscription</span></Link>
          </div>
        </Card>
      </div>
    </Page>
  );
}

export function CampusesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const [campuses, setCampuses] = useState(null);
  const [centers, setCenters] = useState(null);
  const [devices, setDevices] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(true);
  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(null);
  const [action, setAction] = useState(null);
  const [f, setF] = useState({ name: '', code: '', city: '', address: '', capacity: 100 });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const canManage = can(user.role, 'campus.manage');

  const loadCampuses = async () => {
    setLoading(true);
    setLoadError('');
    setCampuses(null);
    setCenters(null);
    setDevices(null);
    const results = await Promise.allSettled([
      Api.listCampuses(tenantId),
      Api.listCenters(tenantId),
      Api.listRegisteredDevices(),
    ]);
    const errors = [];
    const readList = (result, key, label) => {
      if (result.status === 'rejected') {
        errors.push(`${label}: ${result.reason?.message || 'request failed'}`);
        return null;
      }
      const list = result.value?.[key] || result.value || [];
      return Array.isArray(list) ? list : [];
    };
    const campusRows = readList(results[0], 'campuses', 'Campuses');
    const centerRows = readList(results[1], 'centers', 'Centres');
    const deviceRows = readList(results[2], 'devices', 'Devices');
    if (campusRows) setCampuses(campusRows
      .filter(c => (c.tenantId || c.tenant_id || c.institution_id) === tenantId)
      .map(c => ({ ...c, id: c.id || c.campus_id, tenantId: c.tenantId || c.tenant_id || c.institution_id })));
    if (centerRows) setCenters(centerRows
      .filter(c => (c.tenantId || c.tenant_id || c.institution_id) === tenantId)
      .map(c => ({ ...c, id: c.id || c.center_id, campusId: c.campusId || c.campus_id })));
    if (deviceRows) setDevices(deviceRows
      .filter(d => (d.tenantId || d.tenant_id || d.institution_id) === tenantId)
      .map(d => ({ ...d, centerId: d.centerId || d.center_id })));
    setLoadError(errors.join('; '));
    setLoading(false);
  };

  useEffect(() => { loadCampuses(); }, [tenantId]);

  return (
    <Page
      title="Campuses"
      desc="Physical locations that group exam centres, departments and staff."
      actions={
        canManage ? (
          <button className="btn primary" onClick={() => { setF({ name: '', code: '', city: '', address: '', capacity: 100 }); setModal({ mode: 'create' }); }}>
            <Icon name="plus" size={15} /> New campus
          </button>
        ) : undefined
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Flash msg={{ tone: 'danger', text: `Could not load all campus data: ${loadError}` }} onClose={() => setLoadError('')} />}
      <StatGrid cols={3}>
        <Stat label="Campuses" value={loading && campuses === null ? '…' : campuses?.length ?? '—'} icon="pin" />
        <Stat label="Centres" value={loading && centers === null ? '…' : centers?.length ?? '—'} icon="building" />
        <Stat label="Devices" value={loading && devices === null ? '…' : devices?.length ?? '—'} icon="device" />
      </StatGrid>
      <DataTable
        rows={campuses || []}
        search={['name', 'code', 'city', 'address']}
        title="Campus list"
        filters={[{ key: 'status', label: 'Status', options: ['active', 'inactive', 'archived'] }]}
        columns={[
          { key: 'name', label: 'Campus', sortable: true, render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.code} · {c.address || '—'}</small></> },
          { key: 'city', label: 'City' },
          { key: 'capacity', label: 'Capacity' },
          { key: 'centers', label: 'Centres', render: (c) => centers ? centers.filter((x) => x.campusId === c.id).length : '—' },
          { key: 'devices', label: 'Devices', render: (c) => centers && devices ? devices.filter((d) => centers.some((x) => x.id === d.centerId && x.campusId === c.id)).length : '—' },
          { key: 'status', label: 'Status', badge: true },
        ]}
        actions={(c) => canManage ? [
          { label: 'Edit', onClick: () => { setF(c); setModal({ mode: 'edit', c }); } },
          { label: c.status === 'active' ? 'Deactivate' : 'Activate', danger: c.status === 'active', onClick: () => setAction({ c, status: c.status === 'active' ? 'inactive' : 'active' }) },
        ] : []}
      />
      {modal && (
        <Modal
          title={modal.mode === 'create' ? 'New campus' : `Edit ${modal.c.name}`}
          onClose={() => setModal(null)}
          footer={<><button className="btn" onClick={() => setModal(null)}>Cancel</button><button className="btn primary" form="campus-form" disabled={busy}>{modal.mode === 'create' ? 'Create campus' : 'Save changes'}</button></>}
        >
          <form id="campus-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { if (modal.mode === 'create') await createCampus(user, { tenantId, ...f }); else await updateCampus(user, modal.c, f); setModal(null); await loadCampuses(); }); }}>
            <Field label="Campus name" required className="span2"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
            <Field label="Code"><Input value={f.code} onChange={set('code')} maxLength={10} placeholder="Auto" /></Field>
            <Field label="City"><Input value={f.city} onChange={set('city')} maxLength={40} /></Field>
            <Field label="Address" className="span2"><Input value={f.address} onChange={set('address')} maxLength={160} /></Field>
            <Field label="Capacity"><Input type="number" min="1" max="5000" value={f.capacity} onChange={set('capacity')} /></Field>
          </form>
        </Modal>
      )}
      {action && (
        <ActionDialog
          title={`${action.status === 'active' ? 'Activate' : 'Deactivate'} ${action.c.name}`}
          confirmLabel={action.status === 'active' ? 'Activate' : 'Deactivate'}
          danger={action.status !== 'active'}
          onClose={() => setAction(null)}
          onConfirm={(reason) => run(async () => { await setCampusStatus(user, action.c, action.status, reason); setAction(null); await loadCampuses(); })}
        />
      )}
    </Page>
  );
}

export function DepartmentsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const [departments, setDepartments] = useState([]);
  const [campuses, setCampuses] = useState([]);
  const [staff, setStaff] = useState(null);
  const [loadError, setLoadError] = useState('');

  const loadDepts = async () => {
    setLoadError('');
    setDepartments([]);
    setCampuses([]);
    setStaff(null);
    const results = await Promise.allSettled([
      Api.listDepartments(tenantId),
      Api.listCampuses(tenantId),
      Api.listStaff(tenantId),
    ]);
    const errors = [];
    const readList = (result, key, label) => {
      if (result.status === 'rejected') {
        errors.push(`${label}: ${result.reason?.message || 'request failed'}`);
        return null;
      }
      const list = result.value?.[key] || result.value || [];
      return Array.isArray(list) ? list : [];
    };
    const deptRows = readList(results[0], 'departments', 'Departments');
    const campusRows = readList(results[1], 'campuses', 'Campuses');
    const staffRows = readList(results[2], 'staff', 'Staff');
    if (deptRows) setDepartments(deptRows);
    if (campusRows) setCampuses(campusRows.map(c => ({ ...c, id: c.id || c.campus_id })));
    if (staffRows) setStaff(staffRows);
    setLoadError(errors.join('; '));
  };

  useEffect(() => { loadDepts(); }, [tenantId]);

  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(false);
  const [f, setF] = useState({ name: '', code: '', campusId: '', type: 'academic' });
  const [action, setAction] = useState(null);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  return (
    <Page
      title="Departments"
      desc="Business units, departments, and examination centres used to scope staff and exams."
      actions={
        can(user.role, 'dept.manage') ? (
          <button className="btn primary" onClick={() => { setF({ name: '', code: '', campusId: '', type: 'academic' }); setModal(true); }}>
            <Icon name="plus" size={15} /> New department
          </button>
        ) : undefined
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Flash msg={{ tone: 'danger', text: `Could not load all department data: ${loadError}` }} onClose={() => setLoadError('')} />}
      <DataTable
        rows={departments}
        search={['name', 'code']}
        title="Departments"
        filters={[{ key: 'type', label: 'Type', options: DEPT_TYPES }, { key: 'status', label: 'Status', options: ['active', 'inactive'] }]}
        columns={[
          { key: 'name', label: 'Department', render: (d) => <><b>{d.name}</b><br /><small className="muted">{d.code}</small></> },
          { key: 'type', label: 'Type', badge: true },
          { key: 'campus', label: 'Campus', render: (d) => campuses.find((c) => c.id === d.campusId)?.name || '—' },
          { key: 'staff', label: 'Staff', render: (d) => staff ? staff.filter((s) => (s.departmentId || s.department_id) === d.id).length : '—' },
          { key: 'status', label: 'Status', badge: true }
        ]}
        actions={(d) => can(user.role, 'dept.manage') ? [{ label: d.status === 'active' ? 'Deactivate' : 'Activate', danger: d.status === 'active', onClick: () => setAction({ d, status: d.status === 'active' ? 'inactive' : 'active' }) }] : []}
      />
      {modal && (
        <Modal
          title="New department"
          onClose={() => setModal(false)}
          footer={<><button className="btn" onClick={() => setModal(false)}>Cancel</button><button className="btn primary" form="dept-form" disabled={busy}>Create</button></>}
        >
          <form id="dept-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await createDepartment(user, { tenantId, ...f }); setModal(false); await loadDepts(); }); }}>
            <Field label="Name" required className="span2"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
            <Field label="Code"><Input value={f.code} onChange={set('code')} maxLength={12} /></Field>
            <Field label="Type"><Select value={f.type} onChange={set('type')} options={DEPT_TYPES} placeholder={false} /></Field>
            <Field label="Campus" className="span2"><Select value={f.campusId} onChange={set('campusId')} options={campuses.map((c) => ({ v: c.id, l: c.name }))} placeholder="No campus" /></Field>
          </form>
        </Modal>
      )}
      {action && (
        <ActionDialog
          title={`${action.status === 'active' ? 'Activate' : 'Deactivate'} ${action.d.name}`}
          onClose={() => setAction(null)}
          onConfirm={(reason) => run(async () => { await setDepartmentStatus(user, action.d, action.status, reason); setAction(null); await loadDepts(); })}
        />
      )}
    </Page>
  );
}

export function StaffPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const [staff, setStaff] = useState([]);
  const [users, setUsers] = useState([]);
  const [campuses, setCampuses] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [loadError, setLoadError] = useState('');

  const loadStaff = async () => {
    setLoadError('');
    setStaff([]);
    setUsers([]);
    setCampuses([]);
    setDepartments([]);
    const results = await Promise.allSettled([
      Api.listStaff(tenantId),
      Api.listCampuses(tenantId),
      Api.listDepartments(tenantId),
      Api.listInstitutionUsers(tenantId),
    ]);
    const errors = [];
    const readList = (result, key, label) => {
      if (result.status === 'rejected') {
        errors.push(`${label}: ${result.reason?.message || 'request failed'}`);
        return null;
      }
      const list = result.value?.[key] || result.value || [];
      return Array.isArray(list) ? list : [];
    };
    const staffRows = readList(results[0], 'staff', 'Staff');
    const campusRows = readList(results[1], 'campuses', 'Campuses');
    const deptRows = readList(results[2], 'departments', 'Departments');
    const userRows = readList(results[3], 'users', 'User accounts');
    if (staffRows) setStaff(staffRows);
    if (campusRows) setCampuses(campusRows.map(c => ({ ...c, id: c.id || c.campus_id })));
    if (deptRows) setDepartments(deptRows.map(d => ({ ...d, id: d.id || d.department_id })));
    if (userRows) setUsers(userRows
      .filter(u => (u.tenantId || u.tenant_id || u.institution_id) === tenantId)
      .map(u => ({
        ...u,
        id: u.id || u.user_id,
        name: u.name || u.full_name || u.username,
        role: u.role_name || u.role,
        status: u.status || (u.active === true || u.active === 1 ? 'active' : 'unknown'),
      })));
    setLoadError(errors.join('; '));
  };

  useEffect(() => { loadStaff(); }, [tenantId]);

  const { msg, run, busy, setMsg } = useFlash();
  const [modal, setModal] = useState(false);
  const [action, setAction] = useState(null);
  const [f, setF] = useState({ userId: '', campusId: '', departmentId: '', roleTitle: '' });
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const pool = users.filter((u) => u.tenantId === tenantId && u.role !== 'student' && u.status === 'active');

  return (
    <Page
      title="Staff"
      desc="Assign institution staff to campuses and departments. Roles themselves are managed under Users."
      actions={
        can(user.role, 'staff.manage') ? (
          <button className="btn primary" onClick={() => { setF({ userId: '', campusId: '', departmentId: '', roleTitle: '' }); setModal(true); }}>
            <Icon name="plus" size={15} /> Assign staff
          </button>
        ) : undefined
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {loadError && <Flash msg={{ tone: 'danger', text: `Could not load all staff data: ${loadError}` }} onClose={() => setLoadError('')} />}
      <DataTable
        rows={staff}
        search={['name', 'userId', 'roleTitle']}
        title="Staff assignments"
        filters={[{ key: 'status', label: 'Status', options: ['active', 'inactive'] }]}
        columns={[
          { key: 'name', label: 'Staff', render: (s) => <><b>{s.name}</b><br /><small className="muted">{s.userId}</small></> },
          { key: 'roleTitle', label: 'Title' },
          { key: 'campus', label: 'Campus', render: (s) => campuses.find((c) => c.id === s.campusId)?.name || 'All campuses' },
          { key: 'department', label: 'Department', render: (s) => departments.find((d) => d.id === s.departmentId)?.name || '—' },
          { key: 'status', label: 'Status', badge: true },
          { key: 'updatedAt', label: 'Updated', render: (s) => ago(s.updatedAt) }
        ]}
        actions={(s) => can(user.role, 'staff.manage') ? [{ label: 'Remove', danger: true, onClick: () => setAction(s) }] : []}
      />
      {modal && (
        <Modal
          title="Assign staff"
          onClose={() => setModal(false)}
          footer={<><button className="btn" onClick={() => setModal(false)}>Cancel</button><button className="btn primary" form="staff-form" disabled={busy}>Save assignment</button></>}
        >
          <form id="staff-form" className="formgrid" onSubmit={(e) => { e.preventDefault(); run(async () => { await assignStaff(user, { tenantId, ...f }); setModal(false); await loadStaff(); }); }}>
            <Field label="Staff account" required className="span2"><Select value={f.userId} onChange={set('userId')} options={pool.map((u) => ({ v: u.id, l: `${u.name} · ${u.role}` }))} /></Field>
            <Field label="Campus"><Select value={f.campusId} onChange={set('campusId')} options={campuses.map((c) => ({ v: c.id, l: c.name }))} placeholder="All campuses" /></Field>
            <Field label="Department"><Select value={f.departmentId} onChange={set('departmentId')} options={departments.map((d) => ({ v: d.id, l: d.name }))} placeholder="None" /></Field>
            <Field label="Role title" className="span2"><Input value={f.roleTitle} onChange={set('roleTitle')} maxLength={60} placeholder="e.g. Chief invigilator" /></Field>
          </form>
        </Modal>
      )}
      {action && (
        <ActionDialog
          title={`Remove ${action.name}`}
          desc="The account is not deleted; only the staff assignment is retired."
          danger
          confirmLabel="Remove assignment"
          onClose={() => setAction(null)}
          onConfirm={(reason) => run(async () => { await removeStaff(user, action, reason); setAction(null); await loadStaff(); })}
        />
      )}
    </Page>
  );
}

export function CollegeSettingsPage() {
  const { user } = useAuth();
  const { tenant, tenantId, loading: tenantLoading, error: tenantError } = useTenant();
  const { msg, run, busy, setMsg } = useFlash();
  const [f, setF] = useState(() => ({
    name: tenant?.name || '', contactEmail: tenant?.contactEmail || '', contactPhone: tenant?.contactPhone || '',
    region: tenant?.region || '', timezone: tenant?.timezone || '', deploymentModel: tenant?.deploymentModel || '',
    maxCandidates: tenant?.maxCandidates ?? '', domains: (tenant?.domains || []).join(' '),
    requireTpm: tenant?.security?.requireTpm ?? false, requireSecureBoot: tenant?.security?.requireSecureBoot ?? false, allowUsbStorage: tenant?.security?.allowUsbStorage ?? false,
    durationMin: tenant?.examDefaults?.durationMin ?? '', lateEntryMin: tenant?.examDefaults?.lateEntryMin ?? '', attestationLevel: tenant?.examDefaults?.attestationLevel || '',
    email: tenant?.notificationPrefs?.email ?? false, inApp: tenant?.notificationPrefs?.inApp ?? false,
  }));
  useEffect(() => {
    if (!tenant) return;
    setF({
      name: tenant.name || '', contactEmail: tenant.contactEmail || '', contactPhone: tenant.contactPhone || '',
      region: tenant.region || '', timezone: tenant.timezone || '', deploymentModel: tenant.deploymentModel || '',
      maxCandidates: tenant.maxCandidates ?? '', domains: (tenant.domains || []).join(' '),
      requireTpm: tenant.security?.requireTpm ?? false, requireSecureBoot: tenant.security?.requireSecureBoot ?? false, allowUsbStorage: tenant.security?.allowUsbStorage ?? false,
      durationMin: tenant.examDefaults?.durationMin ?? '', lateEntryMin: tenant.examDefaults?.lateEntryMin ?? '', attestationLevel: tenant.examDefaults?.attestationLevel || '',
      email: tenant.notificationPrefs?.email ?? false, inApp: tenant.notificationPrefs?.inApp ?? false,
    });
  }, [tenant]);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });

  if (!tenant) {
    return (
      <Page title="Institution settings">
        {tenantError
          ? <Flash msg={{ tone: 'danger', text: tenantError }} onClose={() => {}} />
          : <Empty icon="settings" title={tenantLoading ? 'Loading institution settings…' : 'No institution selected'}>Choose an institution in the top bar.</Empty>}
      </Page>
    );
  }

  const save = () => run(async () => {
    await updateInstitution(user, tenant, {
      name: f.name, contactEmail: f.contactEmail, contactPhone: f.contactPhone,
      region: f.region, timezone: f.timezone, deploymentModel: f.deploymentModel,
      maxCandidates: f.maxCandidates, domains: f.domains,
      security: { requireTpm: f.requireTpm, requireSecureBoot: f.requireSecureBoot, allowUsbStorage: f.allowUsbStorage },
      notificationPrefs: { email: f.email, inApp: f.inApp }
    });
    await saveExamDefaults(user, tenant, { durationMin: Number(f.durationMin), lateEntryMin: Number(f.lateEntryMin), attestationLevel: f.attestationLevel });
    await saveSecuritySettings(user, tenant, { requireTpm: f.requireTpm, requireSecureBoot: f.requireSecureBoot, allowUsbStorage: f.allowUsbStorage });
    return 'Institution settings saved.';
  });

  return (
    <Page
      title="Institution settings"
      desc="Branding, defaults, security posture and notification preferences."
      actions={
        <button className="btn primary" disabled={busy || !can(user.role, 'settings.inst')} onClick={save}>
          {busy ? 'Saving…' : 'Save settings'}
        </button>
      }
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <div className="two">
        <Card title="Profile">
          <div className="formgrid one">
            <Field label="Institution name"><Input value={f.name} onChange={set('name')} maxLength={80} /></Field>
            <Field label="Email domains" help="Space separated"><Input value={f.domains} onChange={set('domains')} /></Field>
            <Field label="Contact email"><Input type="email" value={f.contactEmail} onChange={set('contactEmail')} /></Field>
            <Field label="Contact phone"><Input value={f.contactPhone} onChange={set('contactPhone')} /></Field>
            <Field label="Region"><Input value={f.region} onChange={set('region')} /></Field>
            <Field label="Timezone"><Select value={f.timezone} onChange={set('timezone')} options={TIMEZONES} placeholder={false} /></Field>
            <Field label="Deployment model"><Select value={f.deploymentModel} onChange={set('deploymentModel')} options={DEPLOYMENT_MODELS} placeholder={false} /></Field>
            <Field label="Candidate capacity"><Input type="number" value={f.maxCandidates} onChange={set('maxCandidates')} /></Field>
          </div>
        </Card>
        <div>
          <Card title="Security defaults">
            <div className="stack">
              <Checkbox label="Require TPM 2.0 attestation" checked={f.requireTpm} onChange={set('requireTpm')} />
              <Checkbox label="Require Secure Boot" checked={f.requireSecureBoot} onChange={set('requireSecureBoot')} />
              <Checkbox label="Allow USB storage during exams" checked={f.allowUsbStorage} onChange={set('allowUsbStorage')} />
              <Field label="Default exam duration (minutes)"><Input type="number" min="15" max="300" value={f.durationMin} onChange={set('durationMin')} /></Field>
              <Field label="Default late entry (minutes)"><Input type="number" min="0" max="60" value={f.lateEntryMin} onChange={set('lateEntryMin')} /></Field>
              <Field label="Attestation level"><Select value={f.attestationLevel} onChange={set('attestationLevel')} options={[{ v: 'none', l: 'None' }, { v: 'tpm', l: 'TPM quote' }, { v: 'tpm-secureboot', l: 'TPM + Secure Boot' }]} placeholder={false} /></Field>
            </div>
          </Card>
          <Card title="Notifications">
            <div className="stack">
              <Checkbox label="Email notifications" checked={f.email} onChange={set('email')} />
              <Checkbox label="In-app notifications" checked={f.inApp} onChange={set('inApp')} />
            </div>
          </Card>
        </div>
      </div>
      <Card title="Institution identifiers">
        <div className="two-inline">
          <CopyField label="Institution ID" value={tenant.id} />
          <CopyField label="Code" value={tenant.code} />
        </div>
      </Card>
    </Page>
  );
}
