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

export function NextActionCallout({ inst = {}, targetArea = 'platform' }) {
  const stage = getInstitutionStage(inst);
  const next = ONBOARDING_STAGES[Math.min(8, stage + 1)];

  return (
    <div style={{ padding: '14px 18px', background: 'linear-gradient(135deg, rgba(181, 79, 52, 0.05), rgba(48, 35, 55, 0.05))', border: '1px solid rgba(181, 79, 52, 0.2)', borderRadius: '8px', marginBottom: '16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Icon name="arrow" size={14} />
          <b style={{ color: 'var(--aubergine, #302337)' }}>Next Permitted Onboarding Step:</b>
          <span style={{ fontWeight: 600, color: 'var(--terracotta, #B54F34)' }}>{next?.label} — {next?.desc}</span>
        </div>
        <p className="muted sm" style={{ margin: '4px 0 0 22px' }}>
          {stage < 3 && 'Awaiting Platform Admin verification and formal approval.'}
          {stage === 3 && 'Approved! Ready for Tenant Provisioning and database isolation setup.'}
          {stage === 4 && 'Provisioned. Primary administrator invitation and Google Authenticator setup pending.'}
          {stage === 5 && 'Organization structure (campuses, departments, programs) configuration in progress.'}
          {stage === 6 && 'Security policies, approved ExamOS release, and device trust bounds pending review.'}
          {stage === 7 && 'Pilot phase underway: workstation compatibility and preflight validation.'}
          {stage >= 8 && 'Full operational approval granted. The institution is certified for live examinations.'}
        </p>
      </div>

      {targetArea === 'platform' && inst.id && (
        <div style={{ display: 'flex', gap: '8px' }}>
          {stage === 1 && <Link to={`/platform/institutions/${inst.id}/verification`} className="btn primary compact">Perform Verification →</Link>}
          {stage === 2 && <Link to={`/platform/institutions/${inst.id}`} className="btn primary compact">Review &amp; Approve →</Link>}
          {stage === 3 && <Link to={`/platform/institutions/${inst.id}/provisioning`} className="btn primary compact">Provision Tenant →</Link>}
          {stage >= 6 && stage < 8 && <Link to={`/platform/institutions/${inst.id}/readiness`} className="btn primary compact">Pilot Approval →</Link>}
          {stage >= 8 && <Link to={`/platform/institutions/${inst.id}/operations`} className="btn compact">Operations &amp; Audit →</Link>}
        </div>
      )}
    </div>
  );
}
