import { Link } from 'react-router-dom';
import { Badge, Steps, Card, Icon } from '../../core/ui/kit';

export const ONBOARDING_STAGES = [
  { key: 'registration', label: '1. Registration', desc: 'Application submitted' },
  { key: 'verification', label: '2. Verification', desc: 'Identity & domain check' },
  { key: 'approval', label: '3. Approval', desc: 'Platform admin sign-off' },
  { key: 'provisioning', label: '4. Provisioning', desc: 'Tenant database & keys' },
  { key: 'admin_setup', label: '5. Admin Setup', desc: 'Administrator MFA enrollment' },
  { key: 'organization_setup', label: '6. Organization', desc: 'Campuses & departments' },
  { key: 'security_config', label: '7. Security Policy', desc: 'OS release & trust policy' },
  { key: 'pilot', label: '8. Pilot Phase', desc: 'Device preflight testing' },
  { key: 'operational_approval', label: '9. Operational', desc: 'Live operation authorized' },
];

export function getInstitutionStage(inst = {}) {
  const status = inst.status || 'applied';
  const ver = inst.verificationStatus || 'pending';
  const prov = inst.provisioningStatus || 'not_started';
  const read = inst.readinessStatus || 'not_ready';
  const opApp = inst.operationalApproval || 'pending';

  if (status === 'active' || opApp === 'fully_authorized') return 8; // operational_approval
  if (status === 'pilot' || opApp === 'pilot_authorized') return 7; // pilot
  if (read === 'passed' || inst.securityConfigured) return 6; // security_config
  if (inst.campusCount > 0 || inst.organizationConfigured) return 5; // organization_setup
  if (inst.adminEnrolled) return 4; // admin_setup
  if (prov === 'provisioned') return 4; // admin_setup
  if (status === 'approved') return 3; // provisioning
  if (ver === 'verified') return 2; // approval
  if (status === 'under_review' || ver === 'in_review') return 1; // verification
  return 0; // registration
}

export function OnboardingWorkflowBar({ currentStage = 0 }) {
  const stepLabels = ONBOARDING_STAGES.map((s) => s.label);
  return (
    <Card pad className="onboarding-flow-card" style={{ marginBottom: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <div>
          <b style={{ fontSize: '14px', color: 'var(--aubergine, #302337)' }}>Onboarding Journey Progression</b>
          <span className="muted sm" style={{ marginLeft: '12px' }}>
            Current Milestone: <strong>{ONBOARDING_STAGES[currentStage]?.desc || 'In Progress'}</strong>
          </span>
        </div>
        <span className="badge g" style={{ fontSize: '11px' }}>
          Stage {currentStage + 1} of 9
        </span>
      </div>
      <Steps steps={stepLabels} current={currentStage} />
    </Card>
  );
}

export function StatusMatrix({ inst = {} }) {
  const opStatus = inst.status || 'applied';
  const verStatus = inst.verificationStatus || 'pending';
  const provStatus = inst.provisioningStatus || 'not_started';
  const readStatus = inst.readinessStatus || 'not_ready';
  const opApproval = inst.operationalApproval || 'pending';

  return (
    <div className="status-matrix-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', margin: '14px 0' }}>
      <div className="matrix-pill-card" style={{ padding: '12px 14px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', boxShadow: 'var(--shadow)' }}>
        <small style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--mut, #756F79)', fontWeight: 600 }}>1. Operational Status</small>
        <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Badge value={opStatus} tone={opStatus === 'active' ? 'green' : opStatus === 'suspended' ? 'red' : 'blue'} />
        </div>
      </div>

      <div className="matrix-pill-card" style={{ padding: '12px 14px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', boxShadow: 'var(--shadow)' }}>
        <small style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--mut, #756F79)', fontWeight: 600 }}>2. Verification State</small>
        <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Badge value={verStatus} tone={verStatus === 'verified' ? 'green' : verStatus === 'corrections_requested' ? 'amber' : verStatus === 'rejected' ? 'red' : 'blue'} />
        </div>
      </div>

      <div className="matrix-pill-card" style={{ padding: '12px 14px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', boxShadow: 'var(--shadow)' }}>
        <small style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--mut, #756F79)', fontWeight: 600 }}>3. Provisioning State</small>
        <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Badge value={provStatus} tone={provStatus === 'provisioned' ? 'green' : provStatus === 'failed' ? 'red' : 'amber'} />
        </div>
      </div>

      <div className="matrix-pill-card" style={{ padding: '12px 14px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', boxShadow: 'var(--shadow)' }}>
        <small style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--mut, #756F79)', fontWeight: 600 }}>4. Readiness State</small>
        <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Badge value={readStatus} tone={readStatus === 'passed' ? 'green' : readStatus === 'issues_detected' ? 'red' : 'amber'} />
        </div>
      </div>

      <div className="matrix-pill-card" style={{ padding: '12px 14px', background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', boxShadow: 'var(--shadow)' }}>
        <small style={{ display: 'block', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--mut, #756F79)', fontWeight: 600 }}>5. Operational Approval</small>
        <div style={{ marginTop: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Badge value={opApproval} tone={opApproval === 'fully_authorized' ? 'green' : opApproval === 'pilot_authorized' ? 'blue' : 'amber'} />
        </div>
      </div>
    </div>
  );
}

const NEXT_STEP_CONFIG = [
  {
    stage: 0,
    title: 'Application Submitted',
    desc: 'Your application is in the compliance queue.',
    platformAction: 'Verify Identity & Domain',
    platformGuide: 'Review the legal charter, confirm official domain DNS TXT record ownership, and validate the authorized signatory.',
    institutionAction: 'Await Review',
    institutionGuide: 'The platform compliance team will verify your charter and domain ownership. You will be notified once verification is complete.',
    tone: 'amber',
  },
  {
    stage: 1,
    title: 'Under Review — Verification In Progress',
    desc: 'Identity, charter, and domain are being verified.',
    platformAction: 'Complete Verification & Approve',
    platformGuide: 'Tick all verification checklist items (charter, domain DNS, signatory) then click "Confirm Verification" to advance to Approval.',
    institutionAction: 'Prepare Verification Evidence',
    institutionGuide: 'Ensure DNS TXT records for your domain are published. Have accreditation certificates and signatory authorization letters ready.',
    tone: 'blue',
  },
  {
    stage: 2,
    title: 'Verification Passed — Awaiting Platform Approval',
    desc: 'Identity verified. Platform admin sign-off required.',
    platformAction: 'Grant Formal Approval',
    platformGuide: 'Click "Approve Institution" on the institution detail page to advance to Tenant Provisioning.',
    institutionAction: 'Awaiting Approval',
    institutionGuide: 'Verification complete! Platform admin is reviewing your application for final approval. No action needed from you.',
    tone: 'blue',
  },
  {
    stage: 3,
    title: 'Approved — Ready for Tenant Provisioning',
    desc: 'Database schema, cryptographic keys, and license will be created.',
    platformAction: 'Execute Tenant Provisioning',
    platformGuide: 'Go to Tenant Provisioning and click "Execute Tenant Provisioning" to create the isolated database schema, cryptographic roots, and default license.',
    institutionAction: 'Provisioning In Progress',
    institutionGuide: 'Your institution has been approved! The platform is setting up your isolated database environment. This takes about 60 seconds.',
    tone: 'green',
  },
  {
    stage: 4,
    title: 'Provisioned — Administrator Setup Required',
    desc: 'Invite and enroll the primary institution administrator.',
    platformAction: 'Send Admin Invitation',
    platformGuide: 'Send an invitation link to the primary institution administrator. They must enroll with MFA (Google Authenticator / TOTP) before accessing the console.',
    institutionAction: 'Enroll Primary Administrator',
    institutionGuide: 'Check the representative email for an invitation link. Click to create your admin account and set up MFA using an authenticator app.',
    tone: 'amber',
  },
  {
    stage: 5,
    title: 'Admin Enrolled — Configure Organization Structure',
    desc: 'Set up campuses, departments, and examination centres.',
    platformAction: 'Monitor Organization Setup',
    platformGuide: 'The institution admin should now configure their campus hierarchy, departments, and exam centres.',
    institutionAction: 'Build Campus & Department Hierarchy',
    institutionGuide: 'Go to Organization Structure → add your campuses, academic departments, and assign examination centres with seat capacity.',
    tone: 'amber',
  },
  {
    stage: 6,
    title: 'Organization Configured — Assign Security Policy',
    desc: 'Assign an approved ExamOS OS release and security trust policy.',
    platformAction: 'Assign OS Release & Security Policy',
    platformGuide: 'Assign an approved ExamOS boot release (stable/pilot channel) and hardware security profile (TPM 2.0, Secure Boot) to this institution.',
    institutionAction: 'Review Security Settings',
    institutionGuide: 'Your IT admin should review the assigned ExamOS release and confirm hardware compatibility on a pilot workstation before the pilot phase.',
    tone: 'amber',
  },
  {
    stage: 7,
    title: 'Security Configured — Pilot Phase Active',
    desc: 'Run pilot examinations and validate device hardware attestation.',
    platformAction: 'Review Pilot Results & Grant Operational Approval',
    platformGuide: 'Once pilot exam results and TPM attestation are verified, grant full operational approval from the Readiness page.',
    institutionAction: 'Execute Pilot Testing',
    institutionGuide: 'Boot pilot devices using the ExamOS USB, run a test examination, and confirm all workstations pass TPM attestation checks.',
    tone: 'blue',
  },
  {
    stage: 8,
    title: 'Fully Operational — Certified for Live Examinations',
    desc: 'Institution is live and authorized for production examinations.',
    platformAction: 'Monitor Operations & Audit',
    platformGuide: 'Monitor active exam sessions, incidents, device telemetry, and audit trail from the Operations page.',
    institutionAction: 'Schedule & Conduct Examinations',
    institutionGuide: 'You are fully operational! Create exam schedules, assign candidates, and launch secure examinations. All sessions are cryptographically logged.',
    tone: 'green',
  },
];

export function NextActionCallout({ inst = {}, targetArea = 'platform' }) {
  const stage = getInstitutionStage(inst);
  const cfg = NEXT_STEP_CONFIG[Math.min(8, stage)];
  const next = ONBOARDING_STAGES[Math.min(8, stage + 1)];
  const isComplete = stage >= 8;

  const actionText = targetArea === 'institution' ? cfg?.institutionAction : cfg?.platformAction;
  const guideText = targetArea === 'institution' ? cfg?.institutionGuide : cfg?.platformGuide;
  const tone = cfg?.tone || 'amber';

  const toneColors = {
    green:  { bg: 'rgba(27, 122, 75, 0.07)',  border: 'rgba(27, 122, 75, 0.25)',  accent: '#1b7a4b', icon: '✓' },
    blue:   { bg: 'rgba(37, 99, 235, 0.07)',  border: 'rgba(37, 99, 235, 0.25)',  accent: '#2563eb', icon: '→' },
    amber:  { bg: 'rgba(181, 79, 52, 0.06)',  border: 'rgba(181, 79, 52, 0.22)',  accent: '#B54F34', icon: '⏳' },
    red:    { bg: 'rgba(192, 57, 43, 0.07)',   border: 'rgba(192, 57, 43, 0.25)',  accent: '#c0392b', icon: '✗' },
  };
  const tc = toneColors[tone] || toneColors.amber;

  return (
    <div style={{ padding: '16px 20px', background: tc.bg, border: `1px solid ${tc.border}`, borderRadius: '10px', marginBottom: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '16px' }}>{tc.icon}</span>
            <b style={{ color: 'var(--aubergine, #302337)', fontSize: '14px' }}>
              {isComplete ? '🎉 Fully Operational' : `Next: ${actionText}`}
            </b>
            <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', background: tc.border, color: tc.accent }}>
              Stage {stage + 1} / 9
            </span>
          </div>
          <p style={{ margin: '0 0 6px 24px', fontSize: '13px', color: 'var(--ink2, #48394F)', lineHeight: 1.55 }}>
            {guideText}
          </p>
          {!isComplete && next && (
            <p style={{ margin: '0 0 0 24px', fontSize: '11.5px', color: 'var(--mut, #756F79)' }}>
              Coming up: <b>{next.label}</b> — {next.desc}
            </p>
          )}
        </div>

        {targetArea === 'platform' && inst.id && (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
            {stage === 0 && <Link to={`/platform/institutions/${inst.id}/verification`} className="btn primary compact">Start Verification →</Link>}
            {stage === 1 && <Link to={`/platform/institutions/${inst.id}/verification`} className="btn primary compact">Complete Verification →</Link>}
            {stage === 2 && <Link to={`/platform/institutions/${inst.id}`} className="btn primary compact">Review &amp; Approve →</Link>}
            {stage === 3 && <Link to={`/platform/institutions/${inst.id}/provisioning`} className="btn primary compact">Provision Tenant →</Link>}
            {stage >= 4 && stage < 7 && <Link to={`/platform/institutions/${inst.id}`} className="btn compact">View Progress →</Link>}
            {stage === 7 && <Link to={`/platform/institutions/${inst.id}/readiness`} className="btn primary compact">Grant Pilot Approval →</Link>}
            {stage >= 8 && <Link to={`/platform/institutions/${inst.id}/operations`} className="btn compact">Operations &amp; Audit →</Link>}
          </div>
        )}

        {targetArea === 'institution' && inst.id && (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
            {stage === 5 && <Link to="/institution/organization" className="btn primary compact">Configure Organization →</Link>}
            {stage === 6 && <Link to="/institution/settings/security" className="btn primary compact">Security Settings →</Link>}
            {stage >= 8 && <Link to="/college/exams/new" className="btn primary compact">Create First Exam →</Link>}
          </div>
        )}
      </div>
    </div>
  );
}
