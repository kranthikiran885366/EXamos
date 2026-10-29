import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from '../../core/ui/SppioLogo';
import { submitInstitutionApplication, fetchInstitutionApplications } from './service';
import { getInstitutionApplyStatus } from '../../core/api/services';
import { Icon } from '../../core/ui/kit';

export default function PublicInstitutionRegisterPage() {
  const [tab, setTab] = useState('register'); // 'register' | 'track'
  const [copiedRef, setCopiedRef] = useState(false);

  // Registration Form State
  const [f, setF] = useState({
    legalName: '',
    displayName: '',
    entityType: 'university',
    registrationNumber: '',
    country: 'India',
    state: '',
    region: 'India · Mumbai',
    timezone: 'Asia/Kolkata',
    address: '',
    domain: '',
    repName: '',
    repRole: '',
    repEmail: '',
    repPhone: '',
    coordName: '',
    coordEmail: '',
    campusCount: '2',
    studentCount: '1500',
    deviceCount: '200',
    targetExamUrl: '',
    deploymentModel: 'usb-boot',
    hardwareProfile: 'standard-uefi',
    plan: 'pilot',
    evidenceNotes: '',
    termsAgreed: false,
    privacyAgreed: false,
  });

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [receipt, setReceipt] = useState(null);

  // Tracking Form State
  const [trackRef, setTrackRef] = useState('');
  const [trackLoading, setTrackLoading] = useState(false);
  const [trackResult, setTrackResult] = useState(null);
  const [trackErr, setTrackErr] = useState('');

  const update = (key) => (e) => {
    const val = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setF((prev) => ({ ...prev, [key]: val }));
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setErr('');

    if (!f.legalName.trim()) return setErr('Official legal institution name is required.');
    if (!f.registrationNumber.trim()) return setErr('Accreditation board or university charter registration number is required.');
    if (!f.domain.trim()) return setErr('Official academic domain (e.g. university.edu.in) is required.');
    if (!f.repEmail.trim() || !f.repEmail.includes('@')) return setErr('A valid official representative email is required.');
    if (!f.repName.trim()) return setErr('Authorized representative name is required.');
    if (!f.address.trim()) return setErr('Physical campus / administrative address is required.');
    if (!f.termsAgreed) return setErr('You must agree to the ExamOS High-Assurance Enclave terms.');

    setBusy(true);
    try {
      const res = await submitInstitutionApplication(f);
      const appId = res?.application_id || res?.id || ('APP-' + Math.floor(100000 + Math.random() * 900000));
      setReceipt({
        id: appId,
        name: f.legalName,
        code: f.displayName || f.legalName.slice(0, 4).toUpperCase(),
        domain: f.domain,
        repName: f.repName,
        repEmail: f.repEmail,
        createdAt: new Date().toISOString(),
        status: 'SUBMITTED',
        plan: f.plan,
        deploymentModel: f.deploymentModel,
      });
    } catch (error) {
      setErr(error?.message || 'Failed to submit registration. Please verify connection to ExamOS core.');
    } finally {
      setBusy(false);
    }
  };

  const handleTrack = async (e) => {
    e.preventDefault();
    if (!trackRef.trim()) return setTrackErr('Please enter your Application Reference ID or Domain.');
    setTrackLoading(true);
    setTrackErr('');
    setTrackResult(null);

    try {
      const q = trackRef.trim();
      let found = null;

      // Try API status lookup first
      try {
        const res = await getInstitutionApplyStatus(q);
        if (res && res.status) found = res;
      } catch {}

      // Fallback: search local/cached applications
      if (!found) {
        const apps = await fetchInstitutionApplications();
        found = apps.find(
          (a) =>
            a.id?.toLowerCase() === q.toLowerCase() ||
            a.application_id?.toLowerCase() === q.toLowerCase() ||
            a.domain?.toLowerCase() === q.toLowerCase() ||
            a.repEmail?.toLowerCase() === q.toLowerCase() ||
            a.legalName?.toLowerCase().includes(q.toLowerCase())
        );
      }

      if (found) {
        const rawStatus = (found.status || 'SUBMITTED').toUpperCase();
        const stageDescriptions = {
          SUBMITTED: 'Enclave Enrollment Submitted â€” Awaiting Compliance Review',
          UNDER_REVIEW: 'Charter & Academic Domain DNS TXT Verification',
          VERIFICATION_PENDING: 'Signatory Authorization & Subnet Boundary Validation',
          MORE_INFORMATION_REQUIRED: 'Applicant Action Required â€” Additional Evidence Requested',
          APPROVED: 'Identity Certified â€” Ready for Dedicated Schema Provisioning',
          PROVISIONED: 'Tenant Provisioned â€” Isolated Enclave & Cryptographic Roots Active',
          REJECTED: 'Application Closed by Compliance Desk',
        };
        setTrackResult({
          id: found.id || found.application_id || q,
          legalName: found.legalName || found.displayName || found.institution_name || 'Academic Institution',
          status: rawStatus,
          step: stageDescriptions[rawStatus] || 'Compliance Validation in Progress',
          notes: found.reviewNotes || found.notes || 'Your application has been received and committed to the durable compliance registry. The platform review team will evaluate your charter credentials and domain ownership.',
          domain: found.domain || found.official_domain || '',
          plan: (found.plan || 'pilot').toUpperCase(),
          updatedAt: found.reviewedAt ? new Date(Number(found.reviewedAt)).toLocaleDateString() : (found.createdAt ? new Date(Number(found.createdAt)).toLocaleDateString() : new Date().toLocaleDateString()),
        });
      } else {
        setTrackResult(null);
        setTrackErr(`No active institution application was found for "${q}". Please verify your Reference ID (e.g. app_179... or APP-2026-...) or registered academic domain.`);
      }
    } catch (error) {
      setTrackErr(error?.message || 'Unable to retrieve status. Please contact platform support.');
    } finally {
      setTrackLoading(false);
    }
  };

  const copyRefId = (text) => {
    navigator.clipboard?.writeText(text);
    setCopiedRef(true);
    setTimeout(() => setCopiedRef(false), 2000);
  };

  return (
    <div
      className="institution-onboarding-split"
      style={{
        display: 'flex',
        minHeight: '100vh',
        background: 'var(--bg, #F6F2ED)',
        color: 'var(--ink, #302337)',
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      }}
    >
      {/* =========================================================================
          LEFT LAYOUT: Editorial Showcase & Enclave Architecture Value Prop
          ========================================================================= */}
      <div
        className="onboarding-showcase-column"
        style={{
          flex: '0 0 42%',
          background: 'linear-gradient(150deg, #1E1424 0%, #302337 55%, #3E2B47 100%)',
          color: '#F6F2ED',
          padding: '48px 56px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          height: '100vh',
          boxSizing: 'border-box',
          overflowY: 'auto',
          borderRight: '1px solid rgba(220, 213, 210, 0.15)',
        }}
      >
        <div>
          {/* Brand Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '36px' }}>
            <span style={{ background: 'linear-gradient(135deg, #B54F34, #973D25)', padding: '8px 10px', borderRadius: '10px', display: 'flex', alignItems: 'center', boxShadow: '0 4px 16px rgba(181, 79, 52, 0.35)' }}>
              <SppioSymbol size={26} accent="#FFFFFF" />
            </span>
            <div>
              <div style={{ fontWeight: 800, fontSize: '20px', letterSpacing: '-0.02em', color: '#FFFFFF' }}>
                ExamOS <span style={{ color: '#E57357' }}>SPPIO</span>
              </div>
              <div style={{ fontSize: '11px', color: '#CBC2BD', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                Institutional Accreditation Enclave
              </div>
            </div>
          </div>

          {/* Telemetry Badge */}
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'rgba(181, 79, 52, 0.18)', border: '1px solid rgba(181, 79, 52, 0.45)', padding: '5px 14px', borderRadius: '20px', fontSize: '11.5px', color: '#FFAE99', fontWeight: 700, marginBottom: '22px' }}>
            <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 8px #B54F34' }} />
            Zero-Trust Enclave · Multi-Tenant Campus Isolation
          </div>

          {/* Hero Headline */}
          <h1 style={{ fontSize: '30px', lineHeight: 1.25, fontWeight: 800, letterSpacing: '-0.025em', color: '#FFFFFF', margin: '0 0 16px' }}>
            Accredit Your Campus for <span style={{ background: 'linear-gradient(135deg, #DE7E64 0%, #F6F2ED 100%)', WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Tamper-Proof Examinations</span>
          </h1>

          <p style={{ fontSize: '14.5px', lineHeight: 1.6, color: '#CBC2BD', margin: '0 0 32px' }}>
            ExamOS provisions isolated database schemas, bare-metal hardware kiosks, and cryptographic audit ledger anchors for accredited colleges, universities, and examination directorates.
          </p>

          {/* Core Trust Pillars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginBottom: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Automated Charter &amp; Domain DNS Challenge</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Validates institutional credentials and academic domain ownership before provisioning enclave boundaries.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Bare-Metal Kiosk Isolation (USB / Lab)</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Boots directly from USB to lock host PC memory, mask shortcuts, block USB storage, and eliminate remote desktop exploits.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Target LMS / Assessment URL Containment</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Seamlessly packages your existing web exam portal in a secure sandbox with zero modification to your question authoring systems.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Immutable Ledger Proof of Examination</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Every test submission, seat verification, and invigilator action is chained into an HMAC-SHA256 audit ledger for recruitment audits.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Editorial Footer */}
        <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: '#8C8490' }}>
          <div>FIPS 140-3 Aligned • TPM 2.0 Silicon Root</div>
          <Link to="/landing" style={{ color: '#FFAE99', textDecoration: 'none', fontWeight: 600 }}>Architecture Spec →</Link>
        </div>
      </div>

      {/* =========================================================================
          RIGHT LAYOUT: Interactive Application & Tracking Workspace Pane
          ========================================================================= */}
      <div
        className="onboarding-form-column"
        style={{
          flex: '0 0 58%',
          padding: '40px 52px 64px',
          boxSizing: 'border-box',
          overflowY: 'auto',
          background: 'var(--bg, #F6F2ED)',
        }}
      >
        {/* Navigation Action Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '28px', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', gap: '8px', background: '#EAE4DC', padding: '4px', borderRadius: '10px' }}>
            <button
              type="button"
              onClick={() => setTab('register')}
              style={{
                background: tab === 'register' ? '#FFFFFF' : 'transparent',
                color: tab === 'register' ? 'var(--aubergine, #302337)' : 'var(--mut, #756F79)',
                border: 'none',
                borderRadius: '8px',
                padding: '8px 18px',
                fontSize: '13px',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: tab === 'register' ? '0 1px 4px rgba(48,35,55,0.08)' : 'none',
              }}
            >
              Apply for Onboarding
            </button>
            <button
              type="button"
              onClick={() => setTab('track')}
              style={{
                background: tab === 'track' ? '#FFFFFF' : 'transparent',
                color: tab === 'track' ? 'var(--aubergine, #302337)' : 'var(--mut, #756F79)',
                border: 'none',
                borderRadius: '8px',
                padding: '8px 18px',
                fontSize: '13px',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: tab === 'track' ? '0 1px 4px rgba(48,35,55,0.08)' : 'none',
              }}
            >
              Track Application Status
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--mut, #756F79)' }}>Already registered?</span>
            <Link
              to="/login"
              style={{
                background: '#FFFFFF',
                color: 'var(--aubergine, #302337)',
                border: '1px solid var(--line, #DCD5D2)',
                borderRadius: '8px',
                padding: '7px 16px',
                fontSize: '13px',
                fontWeight: 700,
                textDecoration: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                boxShadow: '0 1px 3px rgba(48,35,55,0.05)',
              }}
            >
              Console Sign In →
            </Link>
          </div>
        </div>

        {/* Dynamic Pane Content */}
        {tab === 'track' ? (
          /* Track Application View */
          <div
            style={{
              background: '#FFFFFF',
              borderRadius: '16px',
              border: '1px solid var(--line, #DCD5D2)',
              padding: '36px',
              boxShadow: 'var(--shadow2)',
            }}
          >
            <h2 style={{ fontSize: '22px', fontWeight: 800, margin: '0 0 8px', color: 'var(--aubergine, #302337)' }}>
              Track Accreditation &amp; Onboarding Progress
            </h2>
            <p style={{ fontSize: '14px', color: 'var(--mut, #756F79)', margin: '0 0 24px', lineHeight: 1.5 }}>
              Enter your Application Reference Number (e.g. <code>APP-849201</code>) or your official academic domain to check verification state.
            </p>

            <form onSubmit={handleTrack} style={{ display: 'flex', gap: '10px', marginBottom: '24px' }}>
              <input
                type="text"
                placeholder="e.g. APP-849201 or registrar@university.edu.in"
                value={trackRef}
                onChange={(e) => setTrackRef(e.target.value)}
                style={{
                  flex: 1,
                  background: '#FBF9F7',
                  border: '1px solid var(--line, #DCD5D2)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  color: 'var(--ink, #302337)',
                  fontSize: '14px',
                  fontWeight: 600,
                }}
              />
              <button
                type="submit"
                disabled={trackLoading}
                style={{
                  background: 'var(--copper, #B54F34)',
                  color: '#FFFFFF',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '12px 24px',
                  fontWeight: 700,
                  fontSize: '14px',
                  cursor: 'pointer',
                  boxShadow: '0 2px 8px rgba(181, 79, 52, 0.25)',
                }}
              >
                {trackLoading ? 'Searching…' : 'Query Status'}
              </button>
            </form>

            {trackErr && (
              <div style={{ background: 'var(--rbg, #fdf2f2)', border: '1px solid var(--rline, #f8c9c6)', padding: '12px 16px', borderRadius: '8px', color: 'var(--r, #c0392b)', fontSize: '13.5px', marginBottom: '20px', fontWeight: 600 }}>
                {trackErr}
              </div>
            )}

            {trackResult && (() => {
              const statusMeta = {
                SUBMITTED: {
                  icon: '📥', color: '#B54F34', bg: 'var(--abg, #fdf5f2)', border: 'var(--aline, #f4cfc5)',
                  title: 'Application Submitted — Awaiting Review',
                  nextAction: 'What to do next:',
                  nextItems: [
                    'Your application is in the compliance queue and will be reviewed by the ExamOS platform team.',
                    'Ensure your domain\'s DNS TXT records are accessible for verification.',
                    'Keep the authorized representative available for any clarification calls.',
                    'Expected review time: 2–5 business days.',
                  ],
                },
                UNDER_REVIEW: {
                  icon: '🔍', color: '#2563EB', bg: '#EEF4FF', border: '#BFDBFE',
                  title: 'Under Active Review',
                  nextAction: 'What to do next:',
                  nextItems: [
                    'A platform reviewer is actively verifying your charter, domain, and signatory credentials.',
                    'Publish the DNS TXT verification record on your domain if not already done.',
                    'Have accreditation certificates (NAAC/NBA/UGC/AICTE) ready if requested.',
                    'You will be notified of the decision via the email provided.',
                  ],
                },
                VERIFICATION_PENDING: {
                  icon: '⏳', color: '#D97706', bg: '#FFFBEB', border: '#FDE68A',
                  title: 'Verification in Progress',
                  nextAction: 'Action required from your institution:',
                  nextItems: [
                    'Add the DNS TXT record: _examosverify.[yourdomain] with the value provided by the reviewer.',
                    'Confirm the DNS change has propagated (use dig or nslookup to verify).',
                    'Ensure the authorized signatory has signed the provided authorization form.',
                    'Contact support@examos.in if you have not received specific instructions.',
                  ],
                },
                MORE_INFORMATION_REQUIRED: {
                  icon: '📋', color: '#2563EB', bg: '#EEF4FF', border: '#BFDBFE',
                  title: 'Additional Information Required',
                  nextAction: 'Action required — respond to reviewer:',
                  nextItems: [
                    'The reviewer has requested additional documents or corrections.',
                    'Review the notes below and prepare the requested information.',
                    'Resubmit your updated information via email to the reviewer or via the contact provided.',
                    'Your application will be re-evaluated once the information is received.',
                  ],
                },
                APPROVED: {
                  icon: '✅', color: 'var(--g, #1b7a4b)', bg: 'var(--gbg, #edf7f1)', border: 'var(--gline, #b9e3cc)',
                  title: 'Application Approved — Provisioning In Progress',
                  nextAction: 'What happens next:',
                  nextItems: [
                    'Your institution has been approved! The platform team is setting up your isolated tenant environment.',
                    'A dedicated database schema, cryptographic keys, and license entitlements are being created.',
                    'You will receive an invitation email to the representative address to set up the admin account.',
                    'Once you receive the invitation, create your account and set up MFA (Google Authenticator).',
                  ],
                },
                PROVISIONED: {
                  icon: '🚀', color: 'var(--g, #1b7a4b)', bg: 'var(--gbg, #edf7f1)', border: 'var(--gline, #b9e3cc)',
                  title: 'Fully Provisioned — Environment Ready',
                  nextAction: 'Your institution is live! Next steps:',
                  nextItems: [
                    'Your institution\'s secure testing environment is fully provisioned and active.',
                    'Check your representative email for the admin account invitation link.',
                    'Set up your ExamOS administrator account and configure MFA.',
                    'Once logged in, configure campuses, departments, and exam schedules.',
                  ],
                },
                REJECTED: {
                  icon: '✗', color: 'var(--r, #c0392b)', bg: 'var(--rbg, #fdf2f2)', border: 'var(--rline, #f8c9c6)',
                  title: 'Application Rejected',
                  nextAction: 'What you can do:',
                  nextItems: [
                    'Review the rejection reason in the compliance notes below.',
                    'You may reapply after addressing the issues indicated.',
                    'Common reasons: unverifiable registration number, invalid domain, or missing signatory authorization.',
                    'Contact support@examos.in if you believe this decision was made in error.',
                  ],
                },
              };
              const meta = statusMeta[trackResult.status] || statusMeta.SUBMITTED;
              return (
                <div>
                  {/* Status Header Card */}
                  <div style={{ background: meta.bg, border: `1px solid ${meta.border}`, borderRadius: '12px', padding: '20px 24px', marginBottom: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' }}>
                      <div>
                        <div style={{ fontSize: '24px', marginBottom: '4px' }}>{meta.icon}</div>
                        <div style={{ fontSize: '16px', fontWeight: 800, color: meta.color, marginBottom: '4px' }}>{meta.title}</div>
                        <div style={{ fontSize: '12px', color: 'var(--mut, #756F79)', fontWeight: 600 }}>
                          Ref: <code style={{ background: 'rgba(0,0,0,0.06)', padding: '1px 6px', borderRadius: '4px' }}>{trackResult.id || trackRef}</code>
                          {trackResult.domain && <> · {trackResult.domain}</>}
                        </div>
                      </div>
                      <span style={{ background: meta.color, color: '#FFFFFF', borderRadius: '6px', padding: '5px 14px', fontSize: '11.5px', fontWeight: 800, letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>
                        {trackResult.status?.replace(/_/g, ' ') || 'UNDER REVIEW'}
                      </span>
                    </div>
                  </div>

                  {/* Application Details */}
                  <div style={{ background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '18px', marginBottom: '14px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13.5px' }}>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Institution Legal Name</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>{trackResult.legalName || 'Academic Institution'}</div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Current Compliance Stage</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>{trackResult.step || 'Charter & DNS Verification'}</div>
                      </div>
                      {trackResult.plan && (
                        <div>
                          <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Subscription Plan</div>
                          <div style={{ fontWeight: 700, marginTop: '3px' }}>{trackResult.plan}</div>
                        </div>
                      )}
                      {trackResult.updatedAt && (
                        <div>
                          <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Last Updated</div>
                          <div style={{ fontWeight: 700, marginTop: '3px' }}>{trackResult.updatedAt}</div>
                        </div>
                      )}
                      {trackResult.notes && (
                        <div style={{ gridColumn: 'span 2' }}>
                          <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '4px' }}>Reviewer &amp; Compliance Notes</div>
                          <div style={{ color: 'var(--ink2, #48394F)', lineHeight: 1.55, background: '#FFFFFF', padding: '12px 14px', borderRadius: '8px', border: '1px solid var(--line, #DCD5D2)', fontSize: '13px' }}>
                            {trackResult.notes}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* What's Next Guidance */}
                  <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '18px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--aubergine, #302337)', marginBottom: '10px' }}>
                      {meta.nextAction}
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {meta.nextItems.map((item, i) => (
                        <li key={i} style={{ fontSize: '13px', color: 'var(--ink2, #48394F)', lineHeight: 1.55 }}>{item}</li>
                      ))}
                    </ul>
                    {trackResult.status === 'PROVISIONED' && (
                      <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--line, #DCD5D2)' }}>
                        <a href="/login" style={{ background: 'var(--copper, #B54F34)', color: '#FFFFFF', borderRadius: '8px', padding: '10px 24px', fontWeight: 700, fontSize: '14px', textDecoration: 'none', display: 'inline-block', boxShadow: '0 2px 8px rgba(181,79,52,0.25)' }}>
                          Sign In to ExamOS Console →
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        ) : receipt ? (
          /* Submission Receipt Card */
          <div
            style={{
              background: '#FFFFFF',
              borderRadius: '16px',
              border: '1px solid var(--gline, #b9e3cc)',
              padding: '44px 36px',
              textAlign: 'center',
              boxShadow: 'var(--shadow2)',
            }}
          >
            <div
              style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'var(--gbg, #edf7f1)',
                border: '1px solid var(--gline, #b9e3cc)',
                color: 'var(--g, #1b7a4b)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 18px',
                fontSize: '28px',
                fontWeight: 700,
              }}
            >
              ✓
            </div>
            <h2 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: '0 0 8px' }}>
              Application Successfully Registered
            </h2>
            <p style={{ color: 'var(--mut, #756F79)', fontSize: '14.5px', margin: '0 auto 28px', maxWidth: '540px', lineHeight: 1.6 }}>
              Your institutional accreditation application has been committed to the review ledger. Please save your application reference number to track progress.
            </p>

            <div
              style={{
                background: '#FBF9F7',
                borderRadius: '12px',
                border: '1px solid var(--line, #DCD5D2)',
                padding: '24px',
                maxWidth: '500px',
                margin: '0 auto 32px',
                textAlign: 'left',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ color: 'var(--mut, #756F79)', fontSize: '13px', fontWeight: 600 }}>Reference Identifier:</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <strong style={{ color: 'var(--copper, #B54F34)', fontFamily: 'var(--mono, monospace)', fontSize: '17px' }}>{receipt.id}</strong>
                  <button
                    type="button"
                    onClick={() => copyRefId(receipt.id)}
                    style={{
                      background: '#FFFFFF',
                      border: '1px solid var(--line, #DCD5D2)',
                      borderRadius: '6px',
                      padding: '3px 8px',
                      fontSize: '11px',
                      fontWeight: 700,
                      cursor: 'pointer',
                      color: 'var(--aubergine, #302337)',
                    }}
                  >
                    {copiedRef ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: 'var(--mut, #756F79)', fontSize: '13px', fontWeight: 600 }}>Institution Legal Name:</span>
                <span style={{ color: 'var(--aubergine, #302337)', fontSize: '13.5px', fontWeight: 700 }}>{receipt.name}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: 'var(--mut, #756F79)', fontSize: '13px', fontWeight: 600 }}>Official Domain:</span>
                <span style={{ color: 'var(--ink, #302337)', fontSize: '13px' }}>{receipt.domain}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: 'var(--mut, #756F79)', fontSize: '13px', fontWeight: 600 }}>Signatory Email:</span>
                <span style={{ color: 'var(--ink, #302337)', fontSize: '13px' }}>{receipt.repEmail}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--mut, #756F79)', fontSize: '13px', fontWeight: 600 }}>Current Status:</span>
                <span style={{ color: 'var(--copper, #B54F34)', fontSize: '11.5px', fontWeight: 800, background: 'var(--abg, #fdf5f2)', padding: '3px 10px', borderRadius: '4px' }}>
                  SUBMITTED — AWAITING REVIEW
                </span>
              </div>
            </div>

            {/* What's Next Timeline */}
            <div
              style={{
                background: '#F8F6FF',
                borderRadius: '12px',
                border: '1px solid #C4B5FD',
                padding: '20px 24px',
                maxWidth: '540px',
                margin: '0 auto 28px',
                textAlign: 'left',
              }}
            >
              <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--aubergine, #302337)', marginBottom: '14px' }}>
                📋 What happens next:
              </div>
              {[
                { step: '1', status: 'Now', label: 'Application Submitted', desc: 'Your application is in the compliance queue.', done: true },
                { step: '2', status: '2–5 days', label: 'Identity & Domain Verification', desc: 'Platform team verifies charter, DNS TXT record, and signatory.', done: false },
                { step: '3', status: 'After verify', label: 'Platform Approval', desc: 'Admin approves the application and provisions your tenant.', done: false },
                { step: '4', status: 'Upon approval', label: 'Admin Invitation Email', desc: `Invitation link sent to ${receipt?.repEmail || 'your representative email'}.`, done: false },
                { step: '5', status: 'After invite', label: 'Go Live!', desc: 'Configure campuses, schedule exams, and start secure examinations.', done: false },
              ].map((item) => (
                <div key={item.step} style={{ display: 'flex', gap: '12px', marginBottom: '10px', alignItems: 'flex-start' }}>
                  <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: item.done ? 'var(--copper, #B54F34)' : '#E5E0F0', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 800, color: item.done ? '#FFF' : '#8B7FA0', flexShrink: 0 }}>
                    {item.done ? '✓' : item.step}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '13px', fontWeight: 700, color: item.done ? 'var(--copper, #B54F34)' : 'var(--aubergine, #302337)' }}>{item.label}</span>
                      <span style={{ fontSize: '11px', color: 'var(--mut, #756F79)', fontWeight: 600 }}>{item.status}</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--mut, #756F79)', marginTop: '2px', lineHeight: 1.4 }}>{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '14px', justifyContent: 'center' }}>
              <button
                type="button"
                onClick={() => {
                  setTab('track');
                  setTrackRef(receipt.id);
                  setReceipt(null);
                }}
                style={{
                  background: '#FFFFFF',
                  border: '1px solid var(--line, #DCD5D2)',
                  color: 'var(--aubergine, #302337)',
                  borderRadius: '8px',
                  padding: '12px 24px',
                  fontWeight: 700,
                  fontSize: '14px',
                  cursor: 'pointer',
                }}
              >
                Track Live Progress
              </button>
              <Link
                to="/login"
                style={{
                  background: 'var(--copper, #B54F34)',
                  color: '#FFFFFF',
                  borderRadius: '8px',
                  padding: '12px 28px',
                  fontWeight: 700,
                  fontSize: '14px',
                  textDecoration: 'none',
                  display: 'inline-block',
                  boxShadow: '0 2px 8px rgba(181, 79, 52, 0.25)',
                }}
              >
                Go to Sign In
              </Link>
            </div>
          </div>
        ) : (
          /* Main Multi-Section Registration Form */
          <form
            onSubmit={handleRegister}
            style={{
              background: '#FFFFFF',
              borderRadius: '16px',
              border: '1px solid var(--line, #DCD5D2)',
              padding: '36px',
              boxShadow: 'var(--shadow2)',
              position: 'relative',
            }}
          >
            {/* Top Right Decorative 45° Corner Cut Accent */}
            <div
              style={{
                position: 'absolute',
                top: 0,
                right: 0,
                width: '32px',
                height: '32px',
                background: 'linear-gradient(225deg, var(--copper, #B54F34) 0%, var(--copper, #B54F34) 50%, transparent 50%)',
                borderTopRightRadius: '16px',
              }}
            />

            <div style={{ marginBottom: '28px' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--aubergine, #302337)', margin: '0 0 6px' }}>
                Institutional Accreditation Application
              </h2>
              <p style={{ fontSize: '14px', color: 'var(--mut, #756F79)', margin: 0, lineHeight: 1.5 }}>
                Submit official charter details, authorized contacts, and testing URL to configure your high-assurance enclave.
              </p>
            </div>

            {err && (
              <div style={{ background: 'var(--rbg, #fdf2f2)', border: '1px solid var(--rline, #f8c9c6)', padding: '14px 18px', borderRadius: '8px', color: 'var(--r, #c0392b)', fontSize: '13.5px', marginBottom: '24px', fontWeight: 600 }}>
                {err}
              </div>
            )}

            {/* Section 1: Institution & Accreditation Profile */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>1</span>
                <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>Institution &amp; Accreditation Profile</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Legal Entity Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Imperial Institute of Science & Technology"
                    value={f.legalName}
                    onChange={update('legalName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Entity Type *</label>
                  <select
                    value={f.entityType}
                    onChange={update('entityType')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px', fontWeight: 500 }}
                  >
                    <option value="university">Recognized University</option>
                    <option value="autonomous_college">Autonomous Engineering / Medical College</option>
                    <option value="examination_board">State / National Examination Board</option>
                    <option value="recruitment_agency">Enterprise Talent Recruitment Board</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Charter / Accreditation Number *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. UGC-2024-F409 / NAAC-A++ / ABET"
                    value={f.registrationNumber}
                    onChange={update('registrationNumber')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Institution Code / Acronym</label>
                  <input
                    type="text"
                    placeholder="e.g. IIST"
                    value={f.displayName}
                    onChange={update('displayName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Academic Domain(s) *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. iist.edu.in, exams.iist.edu.in"
                    value={f.domain}
                    onChange={update('domain')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Main Campus Headquarters Address *</label>
                  <textarea
                    rows={2}
                    required
                    placeholder="Physical administrative campus address"
                    value={f.address}
                    onChange={update('address')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>
              </div>
            </div>

            {/* Section 2: Authorized Signatory & Contact */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>2</span>
                <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>Authorized Signatory &amp; Administrator</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Signatory Full Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Dr. Rajesh Sharma"
                    value={f.repName}
                    onChange={update('repName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Designation / Title *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Controller of Examinations / Registrar"
                    value={f.repRole}
                    onChange={update('repRole')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Institutional Email *</label>
                  <input
                    type="email"
                    required
                    placeholder="e.g. registrar@iist.edu.in"
                    value={f.repEmail}
                    onChange={update('repEmail')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Contact Phone / Mobile</label>
                  <input
                    type="tel"
                    placeholder="e.g. +91 98765 43210"
                    value={f.repPhone}
                    onChange={update('repPhone')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>
              </div>
            </div>

            {/* Section 3: Testing Infrastructure & Scope */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>3</span>
                <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>Testing Infrastructure &amp; Exam URL Target</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Target Examination Portal URL (Assessment LMS)</label>
                  <input
                    type="url"
                    placeholder="https://assessment.university.edu.in/portal"
                    value={f.targetExamUrl}
                    onChange={update('targetExamUrl')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  <small style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', marginTop: '4px', display: 'block' }}>The secure URL that candidates access inside the isolated ExamOS kiosk.</small>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Annual Candidate Volume</label>
                  <select
                    value={f.studentCount}
                    onChange={update('studentCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px', fontWeight: 500 }}
                  >
                    <option value="500">Up to 500 Candidates</option>
                    <option value="2500">2,500 Candidates</option>
                    <option value="10000">10,000 Candidates</option>
                    <option value="50000">50,000+ Candidates (Enterprise Tier)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Deployment Model</label>
                  <select
                    value={f.deploymentModel}
                    onChange={update('deploymentModel')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px', fontWeight: 500 }}
                  >
                    <option value="usb-boot">Bootable USB Kiosk (Zero Host Footprint)</option>
                    <option value="managed-lab">Managed Lab Appliance (Bare-metal Disk Flash)</option>
                    <option value="hybrid">Hybrid USB + Managed Lab Cluster</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Number of Campuses / Testing Centers</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={f.campusCount}
                    onChange={update('campusCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Workstation Fleet Size</label>
                  <input
                    type="number"
                    min="10"
                    max="10000"
                    value={f.deviceCount}
                    onChange={update('deviceCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>
              </div>
            </div>

            {/* Section 4: Terms & Declarations */}
            <div style={{ marginBottom: '28px', background: '#FBF9F7', padding: '20px', borderRadius: '10px', border: '1px solid var(--line, #DCD5D2)' }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: 'var(--ink2, #48394F)', cursor: 'pointer', marginBottom: '12px' }}>
                <input
                  type="checkbox"
                  required
                  checked={f.termsAgreed}
                  onChange={update('termsAgreed')}
                  style={{ marginTop: '2px', accentColor: 'var(--copper, #B54F34)' }}
                />
                <span>I confirm that I am an authorized institutional representative empowered to initiate ExamOS deployment and agree to standard enclave verification protocols.</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: 'var(--ink2, #48394F)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={f.privacyAgreed}
                  onChange={update('privacyAgreed')}
                  style={{ marginTop: '2px', accentColor: 'var(--copper, #B54F34)' }}
                />
                <span>I consent to cryptographic audit ledger recording for all provisioning and administrative activities.</span>
              </label>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '14px', alignItems: 'center' }}>
              <Link to="/login" style={{ color: 'var(--mut, #756F79)', textDecoration: 'none', fontSize: '13.5px', fontWeight: 600 }}>Cancel</Link>
              <button
                type="submit"
                disabled={busy}
                style={{
                  background: 'var(--copper, #B54F34)',
                  color: '#FFFFFF',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '12px 32px',
                  fontSize: '14px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 4px 14px rgba(181, 79, 52, 0.35)',
                }}
              >
                {busy ? 'Submitting Application…' : 'Submit Accreditation Application →'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
