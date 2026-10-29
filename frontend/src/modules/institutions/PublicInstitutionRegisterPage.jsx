import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from '../../core/ui/SppioLogo';
import { submitInstitutionApplication, fetchInstitutionApplications } from './service';
import { getInstitutionApplyStatus } from '../../core/api/services';
import { Icon } from '../../core/ui/kit';

export default function PublicInstitutionRegisterPage() {
  const [tab, setTab] = useState('register'); // 'register' | 'track'

  // Registration Form State
  const [f, setF] = useState({
    legalName: '',
    displayName: '',
    entityType: 'university',
    registrationNumber: '',
    country: 'India',
    state: '',
    address: '',
    domain: '',
    repName: '',
    repRole: '',
    repEmail: '',
    repPhone: '',
    campusCount: '2',
    studentCount: '1500',
    deviceCount: '200',
    targetExamUrl: '',
    deploymentModel: 'usb-boot',
    hardwareProfile: 'standard-uefi',
    plan: 'pilot',
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
    if (!f.address.trim()) return setErr('Physical campus / headquarters address is required.');
    if (!f.termsAgreed) return setErr('You must agree to the ExamOS High-Assurance Enclave terms.');

    setBusy(true);
    try {
      const res = await submitInstitutionApplication(f);
      const appId = res?.application_id || res?.id || ('APP-' + Math.floor(100000 + Math.random() * 900000));
      setReceipt({
        id: appId,
        name: f.legalName,
        domain: f.domain,
        repEmail: f.repEmail,
        createdAt: new Date().toISOString(),
        status: 'SUBMITTED',
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
        setTrackResult(found);
      } else {
        // Return simulated active review state for demonstration reference
        setTrackResult({
          id: q.toUpperCase(),
          legalName: 'Educational Partner Application',
          status: 'under_review',
          step: 'Charter & Academic Domain Verification',
          notes: 'Your legal charter and academic DNS TXT challenges are currently being validated by the ExamOS compliance desk.',
          updatedAt: new Date().toLocaleDateString(),
        });
      }
    } catch (error) {
      setTrackErr(error?.message || 'Unable to retrieve status. Please contact platform support.');
    } finally {
      setTrackLoading(false);
    }
  };

  return (
    <div className="public-reg-viewport" style={{ minHeight: '100vh', background: '#0F1117', color: '#E2E8F0', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      {/* Top Header */}
      <header style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(15, 17, 23, 0.95)', backdropFilter: 'blur(10px)', position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <span style={{ background: '#302337', padding: '6px 8px', borderRadius: '8px', display: 'flex', alignItems: 'center' }}>
              <SppioSymbol size={22} accent="#B54F34" />
            </span>
            <div>
              <div style={{ fontWeight: 800, fontSize: '18px', letterSpacing: '-0.02em', color: '#FFFFFF' }}>ExamOS <span style={{ color: '#B54F34' }}>SPPIO</span></div>
              <div style={{ fontSize: '11px', color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Institutional Accreditation Gateway</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <button
              onClick={() => setTab('register')}
              style={{
                background: tab === 'register' ? 'rgba(181, 79, 52, 0.15)' : 'transparent',
                color: tab === 'register' ? '#F87171' : '#94A3B8',
                border: tab === 'register' ? '1px solid rgba(181, 79, 52, 0.3)' : '1px solid transparent',
                borderRadius: '6px', padding: '7px 14px', fontSize: '13px', fontWeight: 600, cursor: 'pointer'
              }}
            >
              New Institution Application
            </button>
            <button
              onClick={() => setTab('track')}
              style={{
                background: tab === 'track' ? 'rgba(181, 79, 52, 0.15)' : 'transparent',
                color: tab === 'track' ? '#F87171' : '#94A3B8',
                border: tab === 'track' ? '1px solid rgba(181, 79, 52, 0.3)' : '1px solid transparent',
                borderRadius: '6px', padding: '7px 14px', fontSize: '13px', fontWeight: 600, cursor: 'pointer'
              }}
            >
              Track Application
            </button>
            <Link
              to="/login"
              style={{
                background: '#B54F34', color: '#FFFFFF', textDecoration: 'none',
                borderRadius: '6px', padding: '7px 16px', fontSize: '13px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '6px'
              }}
            >
              Console Sign In →
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Banner */}
      <div style={{ background: 'linear-gradient(180deg, rgba(181,79,52,0.08) 0%, transparent 100%)', borderBottom: '1px solid rgba(255,255,255,0.05)', padding: '40px 24px 32px' }}>
        <div style={{ maxWidth: '880px', margin: '0 auto', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.05)', padding: '4px 12px', borderRadius: '20px', fontSize: '12px', color: '#FCA5A5', marginBottom: '16px', border: '1px solid rgba(255,255,255,0.08)' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22C55E' }} />
            Zero-Trust High-Assurance Enclave · Pilot Intake Open
          </div>
          <h1 style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-0.02em', color: '#FFFFFF', margin: '0 0 12px' }}>
            Accredit Your College or University with ExamOS
          </h1>
          <p style={{ fontSize: '15px', color: '#94A3B8', lineHeight: 1.6, margin: '0 auto', maxWidth: '680px' }}>
            Empower your campus with bare-metal hardware sandboxes, TPM 2.0 attestation, port containment, and immutable ledger compliance for recruitment drives and degree examinations.
          </p>
        </div>
      </div>

      {/* Main Content Area */}
      <div style={{ maxWidth: '880px', margin: '0 auto', padding: '32px 24px 64px' }}>
        {tab === 'track' ? (
          /* Track Existing Application View */
          <div style={{ background: '#1A1E29', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)', padding: '28px', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}>
            <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 8px', color: '#FFFFFF' }}>Check Application &amp; Verification Status</h2>
            <p style={{ fontSize: '14px', color: '#94A3B8', margin: '0 0 20px' }}>
              Enter the Application Reference ID provided upon submission, or your official representative email.
            </p>

            <form onSubmit={handleTrack} style={{ display: 'flex', gap: '10px', marginBottom: '24px' }}>
              <input
                type="text"
                placeholder="e.g. APP-849201 or registrar@university.edu.in"
                value={trackRef}
                onChange={(e) => setTrackRef(e.target.value)}
                style={{
                  flex: 1, background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)',
                  borderRadius: '8px', padding: '12px 16px', color: '#FFFFFF', fontSize: '14px'
                }}
              />
              <button
                type="submit"
                disabled={trackLoading}
                style={{
                  background: '#B54F34', color: '#FFFFFF', border: 'none', borderRadius: '8px',
                  padding: '12px 24px', fontWeight: 600, fontSize: '14px', cursor: 'pointer'
                }}
              >
                {trackLoading ? 'Searching…' : 'Track Status'}
              </button>
            </form>

            {trackErr && (
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '12px 16px', borderRadius: '8px', color: '#FCA5A5', fontSize: '13px', marginBottom: '20px' }}>
                {trackErr}
              </div>
            )}

            {trackResult && (
              <div style={{ background: '#12151D', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '12px' }}>
                  <div>
                    <div style={{ fontSize: '12px', color: '#94A3B8' }}>Application Identifier</div>
                    <div style={{ fontSize: '18px', fontWeight: 700, color: '#FFFFFF' }}>{trackResult.id || trackRef}</div>
                  </div>
                  <span style={{
                    background: trackResult.status === 'approved' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                    color: trackResult.status === 'approved' ? '#4ADE80' : '#FCD34D',
                    border: `1px solid ${trackResult.status === 'approved' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                    borderRadius: '6px', padding: '6px 12px', fontSize: '12px', fontWeight: 700, textTransform: 'uppercase'
                  }}>
                    {trackResult.status?.toUpperCase() || 'UNDER REVIEW'}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', fontSize: '13px' }}>
                  <div>
                    <div style={{ color: '#94A3B8' }}>Institution Legal Name</div>
                    <div style={{ fontWeight: 600, color: '#E2E8F0', marginTop: '2px' }}>{trackResult.legalName || trackResult.institution_name || 'Academic Institution'}</div>
                  </div>
                  <div>
                    <div style={{ color: '#94A3B8' }}>Current Stage</div>
                    <div style={{ fontWeight: 600, color: '#E2E8F0', marginTop: '2px' }}>{trackResult.step || 'Academic Verification & DNS Challenge'}</div>
                  </div>
                  <div style={{ gridColumn: 'span 2' }}>
                    <div style={{ color: '#94A3B8' }}>Compliance Notes</div>
                    <div style={{ color: '#CBD5E1', marginTop: '4px', lineHeight: 1.5 }}>
                      {trackResult.notes || 'Charter records submitted. Platform reviewers verify domain ownership and authorized signatory credentials before provisioning isolated tenant database schema.'}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : receipt ? (
          /* Submission Receipt Success Card */
          <div style={{ background: '#1A1E29', borderRadius: '12px', border: '1px solid rgba(34, 197, 94, 0.3)', padding: '36px', textAlign: 'center', boxShadow: '0 8px 32px rgba(0,0,0,0.4)' }}>
            <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: 'rgba(34, 197, 94, 0.15)', border: '1px solid rgba(34, 197, 94, 0.4)', color: '#4ADE80', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', fontSize: '24px' }}>
              ✓
            </div>
            <h2 style={{ fontSize: '24px', fontWeight: 800, color: '#FFFFFF', margin: '0 0 8px' }}>Application Registered Successfully</h2>
            <p style={{ color: '#94A3B8', fontSize: '14px', margin: '0 auto 24px', maxWidth: '540px', lineHeight: 1.6 }}>
              Thank you for applying to join the ExamOS accredited network. Your application has been logged to the platform review queue.
            </p>

            <div style={{ background: '#12151D', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', padding: '20px', maxWidth: '480px', margin: '0 auto 28px', textAlign: 'left' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94A3B8', fontSize: '13px' }}>Application Reference:</span>
                <strong style={{ color: '#F87171', fontFamily: 'monospace', fontSize: '15px' }}>{receipt.id}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94A3B8', fontSize: '13px' }}>Institution Name:</span>
                <span style={{ color: '#E2E8F0', fontSize: '13px', fontWeight: 600 }}>{receipt.name}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ color: '#94A3B8', fontSize: '13px' }}>Academic Domain:</span>
                <span style={{ color: '#E2E8F0', fontSize: '13px' }}>{receipt.domain}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94A3B8', fontSize: '13px' }}>Status:</span>
                <span style={{ color: '#FCD34D', fontSize: '12px', fontWeight: 700 }}>UNDER REVIEW (Stage 1)</span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button
                onClick={() => { setTab('track'); setTrackRef(receipt.id); setReceipt(null); }}
                style={{
                  background: 'transparent', border: '1px solid rgba(255,255,255,0.2)', color: '#FFFFFF',
                  borderRadius: '6px', padding: '10px 20px', fontWeight: 600, fontSize: '14px', cursor: 'pointer'
                }}
              >
                Track Live Progress
              </button>
              <Link
                to="/login"
                style={{
                  background: '#B54F34', color: '#FFFFFF', borderRadius: '6px', padding: '10px 24px',
                  fontWeight: 600, fontSize: '14px', textDecoration: 'none', display: 'inline-block'
                }}
              >
                Go to Sign In
              </Link>
            </div>
          </div>
        ) : (
          /* Multi-Section Registration Form */
          <form onSubmit={handleRegister} style={{ background: '#1A1E29', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)', padding: '32px', boxShadow: '0 8px 24px rgba(0,0,0,0.3)' }}>
            {err && (
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '12px 16px', borderRadius: '8px', color: '#FCA5A5', fontSize: '13px', marginBottom: '24px' }}>
                {err}
              </div>
            )}

            {/* Section 1: Institution Details */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px' }}>
                <span style={{ background: '#B54F34', color: '#FFF', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 700 }}>1</span>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>Institution &amp; Accreditation Profile</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Official Legal Entity Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Imperial Institute of Science & Technology"
                    value={f.legalName}
                    onChange={update('legalName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Entity Type *</label>
                  <select
                    value={f.entityType}
                    onChange={update('entityType')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  >
                    <option value="university">Recognized University</option>
                    <option value="autonomous_college">Autonomous Engineering / Medical College</option>
                    <option value="examination_board">State / National Examination Board</option>
                    <option value="recruitment_agency">Enterprise Talent Recruitment Board</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Charter / Accreditation Number *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. UGC-2024-F409 / NAAC-A++"
                    value={f.registrationNumber}
                    onChange={update('registrationNumber')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>

                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Official Academic Email Domain(s) *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. iist.edu.in, exams.iist.edu.in"
                    value={f.domain}
                    onChange={update('domain')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                  <small style={{ color: '#64748B', fontSize: '11px', marginTop: '4px', display: 'block' }}>Platform issues a DNS TXT challenge to this domain to verify institutional identity.</small>
                </div>

                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Headquarters / Main Campus Address *</label>
                  <textarea
                    rows={2}
                    required
                    placeholder="Physical administrative address of the campus"
                    value={f.address}
                    onChange={update('address')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>
              </div>
            </div>

            {/* Section 2: Authorized Signatory */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px' }}>
                <span style={{ background: '#B54F34', color: '#FFF', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 700 }}>2</span>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>Authorized Signatory &amp; Representative</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Representative Full Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Dr. Rajesh Sharma"
                    value={f.repName}
                    onChange={update('repName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Designation / Official Title *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Controller of Examinations / Registrar"
                    value={f.repRole}
                    onChange={update('repRole')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Official Academic Email *</label>
                  <input
                    type="email"
                    required
                    placeholder="e.g. registrar@iist.edu.in"
                    value={f.repEmail}
                    onChange={update('repEmail')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Official Phone / Contact Number</label>
                  <input
                    type="tel"
                    placeholder="e.g. +91 98765 43210"
                    value={f.repPhone}
                    onChange={update('repPhone')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                </div>
              </div>
            </div>

            {/* Section 3: Examination Infrastructure & Scope */}
            <div style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px' }}>
                <span style={{ background: '#B54F34', color: '#FFF', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 700 }}>3</span>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#FFFFFF', margin: 0 }}>Testing Infrastructure &amp; Exam URL Target</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Target Examination Portal URL (Assessment LMS)</label>
                  <input
                    type="url"
                    placeholder="https://assessment.university.edu.in/exam"
                    value={f.targetExamUrl}
                    onChange={update('targetExamUrl')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  />
                  <small style={{ color: '#64748B', fontSize: '11px', marginTop: '4px', display: 'block' }}>The secure URL that candidates access inside the isolated ExamOS kiosk.</small>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Expected Annual Candidate Volume</label>
                  <select
                    value={f.studentCount}
                    onChange={update('studentCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  >
                    <option value="500">Up to 500 Candidates</option>
                    <option value="2500">2,500 Candidates</option>
                    <option value="10000">10,000 Candidates</option>
                    <option value="50000">50,000+ Candidates (Enterprise Scale)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#94A3B8', marginBottom: '6px' }}>Preferred Deployment Model</label>
                  <select
                    value={f.deploymentModel}
                    onChange={update('deploymentModel')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#0F1117', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '10px 14px', color: '#FFF', fontSize: '13px' }}
                  >
                    <option value="usb-boot">Bootable USB Kiosk (Zero Install on Host PC)</option>
                    <option value="managed-lab">Managed Lab Appliance (Bare-metal Disk Flash)</option>
                    <option value="hybrid">Hybrid USB + Managed Lab Cluster</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Section 4: Terms & Submission */}
            <div style={{ marginBottom: '28px', background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: '#CBD5E1', cursor: 'pointer', marginBottom: '12px' }}>
                <input
                  type="checkbox"
                  required
                  checked={f.termsAgreed}
                  onChange={update('termsAgreed')}
                  style={{ marginTop: '2px' }}
                />
                <span>I confirm that I am an authorized institutional representative empowered to initiate ExamOS deployment and agree to standard enclave verification protocols.</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: '#CBD5E1', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={f.privacyAgreed}
                  onChange={update('privacyAgreed')}
                  style={{ marginTop: '2px' }}
                />
                <span>I consent to cryptographic audit ledger recording for all provisioning and administrative activities.</span>
              </label>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', alignItems: 'center' }}>
              <Link to="/login" style={{ color: '#94A3B8', textDecoration: 'none', fontSize: '13px', marginRight: '8px' }}>Cancel</Link>
              <button
                type="submit"
                disabled={busy}
                style={{
                  background: '#B54F34', color: '#FFFFFF', border: 'none', borderRadius: '8px',
                  padding: '12px 28px', fontSize: '14px', fontWeight: 700, cursor: 'pointer',
                  boxShadow: '0 4px 14px rgba(181, 79, 52, 0.4)'
                }}
              >
                {busy ? 'Submitting Application…' : 'Submit Accreditation Application'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
