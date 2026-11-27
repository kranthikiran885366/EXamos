import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import SppioLogo from '../../core/ui/SppioLogo';
import { submitInstitutionApplication, ENTITY_TYPES, getOrgTerms, isCorporateEntity } from './service';
import { getInstitutionApplyStatus } from '../../core/api/services';
import { Icon } from '../../core/ui/kit';
import { getApplicationLifecycle } from './applicationLifecycle';
import usePageMeta from '../../core/ui/usePageMeta';

function formatApplicationTimestamp(value) {
  if (value === null || value === undefined || value === '') return '';
  const raw = String(value);
  const date = /^\d{10,13}$/.test(raw)
    ? new Date(Number(raw) * (raw.length === 10 ? 1000 : 1))
    : new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
}

export default function PublicInstitutionRegisterPage() {
  usePageMeta({
    title: 'Institution onboarding | SPPIO',
    description:
      'Apply for SPPIO institution onboarding or track an existing institutional assessment application.',
    path: '/register-institution',
  });

  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState(searchParams.get('tab') === 'track' ? 'track' : 'register');
  const [copiedRef, setCopiedRef] = useState(false);
  const [copyError, setCopyError] = useState('');
  const [formStep, setFormStep] = useState(0);
  const [fieldErrors, setFieldErrors] = useState({});
  const stepTitles = ['Institution', 'Representative', 'Deployment', 'Review and submit'];
  const selectTab = (nextTab) => {
    setTab(nextTab);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (nextTab === 'track') next.set('tab', 'track');
      else next.delete('tab');
      return next;
    }, { replace: true });
  };

  // Registration Form State
  const [f, setF] = useState({
    legalName: '',
    displayName: '',
    entityType: 'university',
    registrationNumber: '',
    country: '',
    state: '',
    region: '',
    timezone: '',
    address: '',
    domain: '',
    repName: '',
    repRole: '',
    repEmail: '',
    repPhone: '',
    coordName: '',
    coordEmail: '',
    campusCount: '',
    studentCount: '',
    deviceCount: '',
    targetExamUrl: '',
    deploymentModel: 'usb-boot',
    hardwareProfile: '',
    plan: '',
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
  const [trackErrorType, setTrackErrorType] = useState('');

  const update = (key) => (e) => {
    const val = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setF((prev) => ({ ...prev, [key]: val }));
    setFieldErrors((previous) => {
      if (!previous[key]) return previous;
      const next = { ...previous };
      delete next[key];
      return next;
    });
  };

  const getStepErrors = (step) => {
    const requiredByStep = [
      [
        ['legalName', 'Official legal entity name'],
        ['registrationNumber', 'Charter / accreditation number'],
        ['domain', 'Official academic domain'],
        ['address', 'Administrative address'],
      ],
      [
        ['repName', 'Authorized representative name'],
        ['repRole', 'Representative designation'],
        ['repEmail', 'Institutional email'],
      ],
      [
        ['campusCount', 'Number of campuses or testing centers'],
        ['studentCount', 'Annual candidate volume'],
        ['deviceCount', 'Workstation fleet size'],
      ],
      [],
    ];
    const errors = {};
    for (const [key, label] of requiredByStep[step]) {
      if (!String(f[key] || '').trim()) errors[key] = `${label} is required.`;
    }
    if (step === 1 && f.repEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.repEmail)) {
      errors.repEmail = 'Enter a valid institutional email address.';
    }
    if (step === 2) {
      if (f.targetExamUrl) {
        try {
          const targetUrl = new URL(f.targetExamUrl.trim());
          if (!['http:', 'https:'].includes(targetUrl.protocol)) errors.targetExamUrl = 'Use an http or https assessment URL.';
        } catch {
          errors.targetExamUrl = 'Enter a valid assessment URL.';
        }
      }
      if (Number(f.campusCount) < 1 || Number(f.campusCount) > 100) errors.campusCount = 'Enter a campus count from 1 to 100.';
      if (Number(f.studentCount) < 1) errors.studentCount = 'Enter an annual candidate volume greater than 0.';
      if (Number(f.deviceCount) < 10 || Number(f.deviceCount) > 10000) errors.deviceCount = 'Enter a workstation fleet size from 10 to 10,000.';
    }
    if (step === 3) {
      if (!f.termsAgreed) errors.termsAgreed = 'Confirm you are authorized to submit this application.';
      if (!f.privacyAgreed) errors.privacyAgreed = 'Accept the privacy declaration to submit.';
    }
    return errors;
  };

  const validateStep = (step) => {
    const errors = getStepErrors(step);
    setFieldErrors(errors);
    if (Object.keys(errors).length) {
      const firstError = Object.keys(errors)[0];
      setErr('Review the highlighted fields before continuing.');
      setTimeout(() => document.getElementById(`application-${firstError}`)?.focus(), 0);
      return false;
    }
    setErr('');
    return true;
  };

  const moveToStep = (nextStep) => {
    if (nextStep <= formStep || (nextStep === formStep + 1 && validateStep(formStep))) {
      setFormStep(nextStep);
      setErr('');
      setTimeout(() => document.getElementById(`application-step-${nextStep}`)?.focus(), 0);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setErr('');
    if (busy) return;

    const allErrors = Object.assign({}, ...[0, 1, 2, 3].map(getStepErrors));
    setFieldErrors(allErrors);
    if (Object.keys(allErrors).length) {
      const field = Object.keys(allErrors)[0];
      setErr('Some required information is missing or invalid. Review the fields listed below.');
      const stepForField = ['legalName', 'registrationNumber', 'domain', 'address'].includes(field) ? 0
        : ['repName', 'repRole', 'repEmail'].includes(field) ? 1
          : ['campusCount', 'studentCount', 'deviceCount', 'targetExamUrl'].includes(field) ? 2 : 3;
      setFormStep(stepForField);
      setTimeout(() => document.getElementById(`application-${field}`)?.focus(), 0);
      return;
    }

    setBusy(true);
    try {
      const res = await submitInstitutionApplication(f);
      const appId = res?.application_id || res?.id;
      if (!appId) {
        throw new Error('Registration failed: the server did not return a valid application reference ID.');
      }
      setReceipt({
        id: appId,
        name: f.legalName,
        domain: f.domain,
        repName: f.repName,
        repEmail: f.repEmail,
      });
    } catch (error) {
      setErr(error?.message || 'Failed to submit registration. Please verify connection to SPPIO core.');
    } finally {
      setBusy(false);
    }
  };

  const handleTrack = async (e) => {
    e.preventDefault();
    const reference = trackRef.trim();
    if (!/^app_\d+_[A-Fa-f0-9]{32}$/.test(reference)) {
      setTrackErrorType('invalid');
      setTrackErr('Enter the application reference shown on your submission receipt (it starts with “app_”).');
      return;
    }
    setTrackLoading(true);
    setTrackErr('');
    setTrackErrorType('');
    setTrackResult(null);

    try {
      const res = await getInstitutionApplyStatus(reference);
      if (!res || !res.status) {
        throw new Error('The server returned no application status for that reference.');
      }
      const found = res;
      const rawStatus = found.status.toUpperCase();
      const lifecycle = getApplicationLifecycle(rawStatus, found.institutionStatus, found.adminSetupComplete);
      setTrackResult({
        id: found.id || reference,
        legalName: found.legalName || found.displayName || found.institution_name || '',
        status: rawStatus,
        institutionStatus: found.institutionStatus || '',
        adminSetupComplete: typeof found.adminSetupComplete === 'boolean' ? found.adminSetupComplete : null,
        step: lifecycle.stage,
        nextAction: lifecycle.nextAction,
        owner: lifecycle.owner,
        reviewNotes: found.reviewNotes || '',
        domain: found.domain || found.official_domain || '',
        plan: (found.plan || '').toUpperCase(),
        updatedAt: formatApplicationTimestamp(found.updatedAt),
      });
    } catch (error) {
      setTrackResult(null);
      if (error?.status === 404) {
        setTrackErrorType('unmatched');
        setTrackErr('No application matches that reference. Check the receipt and try again.');
      } else {
        setTrackErrorType('temporary');
        setTrackErr('Application status is temporarily unavailable. Your reference is unchanged; retry shortly or contact platform support.');
      }
    } finally {
      setTrackLoading(false);
    }
  };

  const copyRefId = (text) => {
    setCopyError('');
    if (!navigator.clipboard?.writeText) {
      setCopyError('Clipboard access is unavailable. Select and copy the reference manually.');
      return;
    }
    navigator.clipboard.writeText(text).then(() => {
      setCopiedRef(true);
      setTimeout(() => setCopiedRef(false), 2000);
    }).catch(() => {
      setCopyError('Could not copy the reference. Select and copy it manually.');
    });
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '36px' }}>
            <Link to="/" aria-label="SPPIO home" style={{ display: 'inline-flex', alignItems: 'center' }}>
              <SppioLogo width={164} accent="#B54F34" ink="#FFFFFF" />
            </Link>
            <div style={{ fontSize: '11px', color: '#CBC2BD', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
              Institutional Accreditation Enclave
            </div>
          </div>

          {/* Telemetry Badge */}
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'rgba(181, 79, 52, 0.18)', border: '1px solid rgba(181, 79, 52, 0.45)', padding: '5px 14px', borderRadius: '20px', fontSize: '11.5px', color: '#FFAE99', fontWeight: 700, marginBottom: '22px' }}>
            <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 8px #B54F34' }} />
            Institutional onboarding application
          </div>

          {/* Hero Headline */}
          <h1 style={{ fontSize: '30px', lineHeight: 1.25, fontWeight: 800, letterSpacing: '-0.025em', color: '#FFFFFF', margin: '0 0 16px' }}>
            Apply to plan <span style={{ background: 'linear-gradient(135deg, #DE7E64 0%, #F6F2ED 100%)', WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>institutional assessment</span>
          </h1>

          <p style={{ fontSize: '14.5px', lineHeight: 1.6, color: '#CBC2BD', margin: '0 0 32px' }}>
            Submit institution and representative details for review. Approval, tenant provisioning, workstation deployment, and authorization for live operations are separate lifecycle steps.
          </p>

          {/* Core Trust Pillars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginBottom: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Institution review</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>The platform review team evaluates submitted institution and representative information.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Deployment planning</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Hardware support and station controls must be validated for your intended deployment.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Assessment integration</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Provide the assessment URL and discuss compatibility during onboarding review.</p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#B54F34', boxShadow: '0 0 10px rgba(181, 79, 52, 0.6)', marginTop: '6px', flexShrink: 0 }} />
              <div>
                <strong style={{ display: 'block', fontSize: '14px', color: '#FFFFFF', marginBottom: '2px' }}>Audit requirements</strong>
                <p style={{ margin: 0, fontSize: '12.5px', lineHeight: 1.5, color: '#A89FA9' }}>Confirm event coverage, retention, verification, and audit evidence for the selected release.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Editorial Footer */}
        <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: '#8C8490' }}>
          <div>Illustrative architecture overview • deployment-dependent controls</div>
          <Link to="/architecture" style={{ color: '#FFAE99', textDecoration: 'none', fontWeight: 600 }}>Architecture Spec →</Link>
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
              aria-pressed={tab === 'register'}
              onClick={() => selectTab('register')}
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
              aria-pressed={tab === 'track'}
              onClick={() => selectTab('track')}
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
              Enter the Application Reference Number returned after submitting your application.
            </p>

            <form onSubmit={handleTrack} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: '10px', marginBottom: '24px', alignItems: 'end' }}>
              <label htmlFor="application-reference" style={{ gridColumn: '1 / -1', fontSize: '12.5px', fontWeight: 700 }}>
                Application Reference Number
              </label>
              <input
                type="text"
                required
                aria-required="true"
                id="application-reference"
                aria-describedby={trackErr ? 'track-error' : 'track-reference-help'}
                aria-invalid={Boolean(trackErr)}
                placeholder="app_… reference from your receipt"
                value={trackRef}
                onChange={(e) => setTrackRef(e.target.value)}
                style={{
                  width: '100%',
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
              <small id="track-reference-help" style={{ gridColumn: '1 / -1', color: 'var(--mut, #756F79)' }}>Use the receipt reference in the format app_&lt;unix-time&gt;_&lt;32 hexadecimal characters&gt;.</small>
            </form>

            {trackErr && (
              <div id="track-error" role="alert" style={{ background: 'var(--rbg, #fdf2f2)', border: '1px solid var(--rline, #f8c9c6)', padding: '12px 16px', borderRadius: '8px', color: 'var(--r, #c0392b)', fontSize: '13.5px', marginBottom: '20px', fontWeight: 600 }}>
                {trackErrorType === 'invalid' ? 'Invalid reference · ' : trackErrorType === 'unmatched' ? 'Reference not found · ' : 'Temporary lookup failure · '}
                {trackErr}
              </div>
            )}

            {trackResult && (() => {
              const isRejected = trackResult.status === 'REJECTED';
              const meta = {
                icon: isRejected ? '✗' : '•',
                color: isRejected ? 'var(--r, #c0392b)' : 'var(--copper, #B54F34)',
                bg: isRejected ? 'var(--rbg, #fdf2f2)' : 'var(--abg, #fdf5f2)',
                border: isRejected ? 'var(--rline, #f8c9c6)' : 'var(--aline, #f4cfc5)',
                title: trackResult.step,
              };
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
                        {trackResult.status?.replace(/_/g, ' ') || 'UNKNOWN'}
                      </span>
                    </div>
                  </div>

                  {/* Application Details */}
                  <div style={{ background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '18px', marginBottom: '14px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13.5px' }}>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Institution Legal Name</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>{trackResult.legalName || '—'}</div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Current application stage</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>{trackResult.step || '—'}</div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Live Operations Authorization</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>
                          {trackResult.status === 'PROVISIONED'
                            && trackResult.institutionStatus?.toLowerCase() === 'active'
                            && trackResult.adminSetupComplete === true
                            ? 'Authorized for live operations'
                            : `Not authorized for live operations${trackResult.adminSetupComplete === false ? ' (primary administrator MFA setup is incomplete)' : trackResult.institutionStatus ? ` (institution status: ${trackResult.institutionStatus})` : ''}`}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Next Action Owner</div>
                        <div style={{ fontWeight: 700, color: 'var(--aubergine, #302337)', marginTop: '3px' }}>{trackResult.owner}</div>
                      </div>
                      {trackResult.plan && (
                        <div>
                          <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Subscription Plan</div>
                          <div style={{ fontWeight: 700, marginTop: '3px' }}>{trackResult.plan}</div>
                        </div>
                      )}
                      <div>
                        <div style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Last Updated</div>
                        <div style={{ fontWeight: 700, marginTop: '3px' }}>{trackResult.updatedAt || 'Not reported by the server'}</div>
                      </div>
                    </div>
                  </div>

                  {/* What's Next Guidance */}
                  <div style={{ background: '#FFFFFF', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '18px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--aubergine, #302337)', marginBottom: '10px' }}>
                      Next action
                    </div>
                    <p style={{ fontSize: '13px', lineHeight: 1.55, color: 'var(--ink2, #48394F)' }}>{trackResult.nextAction}</p>
                    {trackResult.reviewNotes && ['MORE_INFORMATION_REQUIRED', 'REJECTED'].includes(trackResult.status) && (
                      <div style={{ marginTop: '12px', padding: '12px 14px', background: trackResult.status === 'REJECTED' ? 'var(--rbg, #fdf2f2)' : '#EEF4FF', border: `1px solid ${trackResult.status === 'REJECTED' ? 'var(--rline, #f8c9c6)' : '#BFDBFE'}`, borderRadius: '8px' }}>
                        <b style={{ display: 'block', marginBottom: '6px' }}>{trackResult.status === 'REJECTED' ? 'Reviewer rationale' : 'Requested corrections'}</b>
                        <div style={{ whiteSpace: 'pre-wrap', fontSize: '13px', lineHeight: 1.55 }}>{trackResult.reviewNotes}</div>
                      </div>
                    )}
                    {trackResult.status === 'PROVISIONED'
                      && trackResult.institutionStatus?.toLowerCase() === 'active'
                      && trackResult.adminSetupComplete === true && (
                      <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--line, #DCD5D2)' }}>
                        <a href="/login" style={{ background: 'var(--copper, #B54F34)', color: '#FFFFFF', borderRadius: '8px', padding: '10px 24px', fontWeight: 700, fontSize: '14px', textDecoration: 'none', display: 'inline-block', boxShadow: '0 2px 8px rgba(181,79,52,0.25)' }}>
                          Sign In to SPPIO Console →
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
              Application Submitted
            </h2>
            <p style={{ color: 'var(--mut, #756F79)', fontSize: '14.5px', margin: '0 auto 28px', maxWidth: '540px', lineHeight: 1.6 }}>
              Your application was submitted. Save the reference number to check the status later.
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
              {copyError && <p role="status" style={{ color: 'var(--r, #c0392b)', fontSize: '12px', margin: '0 0 10px' }}>{copyError}</p>}
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
                { step: '2', status: 'Pending', label: 'Application Review', desc: 'The application status will update when the platform team records a decision.', done: false },
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
                  selectTab('track');
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
                Track Application
              </button>
            </div>
          </div>
        ) : (
          /* Main Multi-Section Registration Form */
          <form
            onSubmit={handleRegister}
            noValidate
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
                Provide institution, representative, and deployment information for platform review.
              </p>
            </div>

            <section aria-label="Information you will need" style={{ background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', marginBottom: '20px' }}>
              <h3 style={{ margin: '0 0 8px', fontSize: '15px' }}>Information you’ll need</h3>
              <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.6 }}>
                Institution charter or accreditation number, official domain, administrative address, authorized representative details, deployment model, campus count, annual candidate volume, and workstation estimate. Before submission, the representative must confirm they are authorized to apply and review the privacy declaration.
              </p>
            </section>

            <nav aria-label="Application steps" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '6px', marginBottom: '24px' }}>
              {stepTitles.map((title, index) => (
                <button
                  key={title}
                  type="button"
                  disabled={index > formStep + 1}
                  aria-current={formStep === index ? 'step' : undefined}
                  onClick={() => moveToStep(index)}
                  style={{ border: `1px solid ${formStep === index ? 'var(--copper, #B54F34)' : 'var(--line, #DCD5D2)'}`, borderRadius: '7px', padding: '8px 6px', background: formStep === index ? '#FDF5F2' : '#FFFFFF', color: 'var(--aubergine, #302337)', fontSize: '11px', fontWeight: 700, cursor: index > formStep + 1 ? 'not-allowed' : 'pointer', opacity: index > formStep + 1 ? 0.55 : 1 }}
                >
                  {index + 1}. {title}
                </button>
              ))}
            </nav>

            {err && (
              <div role="alert" style={{ background: 'var(--rbg, #fdf2f2)', border: '1px solid var(--rline, #f8c9c6)', padding: '14px 18px', borderRadius: '8px', color: 'var(--r, #c0392b)', fontSize: '13.5px', marginBottom: '24px', fontWeight: 600 }}>
                <p style={{ margin: '0 0 8px' }}>{err}</p>
                {Object.entries(fieldErrors).length > 0 && (
                  <ul style={{ margin: 0, paddingLeft: '20px' }}>
                    {Object.entries(fieldErrors).map(([field, message]) => (
                      <li key={field}><a href={`#application-${field}`} onClick={(event) => { event.preventDefault(); document.getElementById(`application-${field}`)?.focus(); }} style={{ color: 'inherit' }}>{message}</a></li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* Section 1: Institution & Accreditation Profile */}
            <div hidden={formStep !== 0} aria-labelledby="application-step-0" style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>1</span>
                <h3 id="application-step-0" tabIndex="-1" style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>Institution &amp; Accreditation Profile</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label htmlFor="application-legalName" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Legal Entity Name *</label>
                  <input
                    id="application-legalName"
                    type="text"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.legalName)}
                    aria-describedby={fieldErrors.legalName ? 'application-legalName-error' : undefined}
                    placeholder="e.g. Imperial Institute of Science & Technology"
                    value={f.legalName}
                    onChange={update('legalName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.legalName && <small id="application-legalName-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.legalName}</small>}
                </div>

                <div>
                  <label htmlFor="application-entityType" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Entity Type *</label>
                  <select
                    id="application-entityType"
                    required
                    aria-required="true"
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
                  <label htmlFor="application-registrationNumber" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Charter / Accreditation Number *</label>
                  <input
                    id="application-registrationNumber"
                    type="text"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.registrationNumber)}
                    aria-describedby={fieldErrors.registrationNumber ? 'application-registrationNumber-error' : undefined}
                    placeholder="e.g. UGC-2024-F409 / NAAC-A++ / ABET"
                    value={f.registrationNumber}
                    onChange={update('registrationNumber')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.registrationNumber && <small id="application-registrationNumber-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.registrationNumber}</small>}
                </div>

                <div>
                  <label htmlFor="application-displayName" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Institution Code / Acronym</label>
                  <input
                    id="application-displayName"
                    type="text"
                    placeholder="e.g. IIST"
                    value={f.displayName}
                    onChange={update('displayName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                </div>

                <div>
                  <label htmlFor="application-domain" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Academic Domain(s) *</label>
                  <input
                    id="application-domain"
                    type="text"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.domain)}
                    aria-describedby={fieldErrors.domain ? 'application-domain-error' : undefined}
                    placeholder="e.g. iist.edu.in, exams.iist.edu.in"
                    value={f.domain}
                    onChange={update('domain')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.domain && <small id="application-domain-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.domain}</small>}
                </div>

                <div style={{ gridColumn: 'span 2' }}>
                  <label htmlFor="application-address" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Main Campus Headquarters Address *</label>
                  <textarea
                    id="application-address"
                    rows={2}
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.address)}
                    aria-describedby={fieldErrors.address ? 'application-address-error' : undefined}
                    placeholder="Physical administrative campus address"
                    value={f.address}
                    onChange={update('address')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.address && <small id="application-address-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.address}</small>}
                </div>
              </div>
            </div>

            {/* Section 2: Authorized Signatory & Contact */}
            <div hidden={formStep !== 1} aria-labelledby="application-step-1" style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>2</span>
                <h3 id="application-step-1" tabIndex="-1" style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>Authorized Signatory &amp; Administrator</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <label htmlFor="application-repName" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Signatory Full Name *</label>
                  <input
                    id="application-repName"
                    type="text"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.repName)}
                    aria-describedby={fieldErrors.repName ? 'application-repName-error' : undefined}
                    placeholder="e.g. Dr. Rajesh Sharma"
                    value={f.repName}
                    onChange={update('repName')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.repName && <small id="application-repName-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.repName}</small>}
                </div>

                <div>
                  <label htmlFor="application-repRole" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Designation / Title *</label>
                  <input
                    id="application-repRole"
                    type="text"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.repRole)}
                    aria-describedby={fieldErrors.repRole ? 'application-repRole-error' : undefined}
                    placeholder="e.g. Controller of Examinations / Registrar"
                    value={f.repRole}
                    onChange={update('repRole')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.repRole && <small id="application-repRole-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.repRole}</small>}
                </div>

                <div>
                  <label htmlFor="application-repEmail" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Official Institutional Email *</label>
                  <input
                    id="application-repEmail"
                    type="email"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.repEmail)}
                    aria-describedby={fieldErrors.repEmail ? 'application-repEmail-error' : undefined}
                    placeholder="e.g. registrar@iist.edu.in"
                    value={f.repEmail}
                    onChange={update('repEmail')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.repEmail && <small id="application-repEmail-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.repEmail}</small>}
                </div>

                <div>
                  <label htmlFor="application-repPhone" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Contact Phone / Mobile</label>
                  <input
                    id="application-repPhone"
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
            <div hidden={formStep !== 2} aria-labelledby="application-step-2" style={{ marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px', borderBottom: '1px solid var(--line, #DCD5D2)', paddingBottom: '10px' }}>
                <span style={{ background: 'var(--copper, #B54F34)', color: '#FFF', width: '24px', height: '24px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 800 }}>3</span>
                <h3 id="application-step-2" tabIndex="-1" style={{ fontSize: '16px', fontWeight: 800, color: 'var(--aubergine, #302337)', margin: 0 }}>{isCorporateEntity(f.entityType) ? 'Testing Infrastructure & Assessment Delivery' : 'Testing Infrastructure & Exam URL Target'}</h3>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div style={{ gridColumn: 'span 2' }}>
                  <label htmlFor="application-targetExamUrl" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>{isCorporateEntity(f.entityType) ? 'Assessment Platform URL (ATS / LMS)' : 'Target Examination Portal URL (Assessment LMS)'}</label>
                  <input
                    id="application-targetExamUrl"
                    type="url"
                    maxLength={2048}
                    aria-invalid={Boolean(fieldErrors.targetExamUrl)}
                    aria-describedby={fieldErrors.targetExamUrl ? 'application-targetExamUrl-error' : undefined}
                    placeholder={isCorporateEntity(f.entityType) ? "https://assessment.yourcompany.com/exams" : "https://assessment.university.edu.in/portal"}
                    value={f.targetExamUrl}
                    onChange={update('targetExamUrl')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.targetExamUrl && <small id="application-targetExamUrl-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.targetExamUrl}</small>}
                  <small style={{ color: 'var(--mut, #756F79)', fontSize: '11.5px', marginTop: '4px', display: 'block' }}>Provide the assessment URL for compatibility review.</small>
                </div>

                <div>
                  <label htmlFor="application-studentCount" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>{`Annual ${getOrgTerms(f.entityType).candidateLabel} Volume`}</label>
                  <select
                    id="application-studentCount"
                    required
                    aria-required="true"
                    aria-invalid={Boolean(fieldErrors.studentCount)}
                    aria-describedby={fieldErrors.studentCount ? 'application-studentCount-error' : undefined}
                    value={f.studentCount}
                    onChange={update('studentCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px', fontWeight: 500 }}
                  >
                    <option value="" disabled>Select annual volume</option>
                    <option value="500">Up to 500 {getOrgTerms(f.entityType).candidateLabel}</option>
                    <option value="2500">2,500 {getOrgTerms(f.entityType).candidateLabel}</option>
                    <option value="10000">10,000 {getOrgTerms(f.entityType).candidateLabel}</option>
                    <option value="50000">50,000+ {getOrgTerms(f.entityType).candidateLabel} (Enterprise Tier)</option>
                  </select>
                  {fieldErrors.studentCount && <small id="application-studentCount-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.studentCount}</small>}
                </div>

                <div>
                  <label htmlFor="application-deploymentModel" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Deployment Model</label>
                  <select
                    id="application-deploymentModel"
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
                  <label htmlFor="application-campusCount" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>{`Number of ${getOrgTerms(f.entityType).campusLabel}`}</label>
                  <input
                    id="application-campusCount"
                    type="number"
                    required
                    aria-required="true"
                    min="1"
                    max="100"
                    aria-invalid={Boolean(fieldErrors.campusCount)}
                    aria-describedby={fieldErrors.campusCount ? 'application-campusCount-error' : undefined}
                    value={f.campusCount}
                    onChange={update('campusCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.campusCount && <small id="application-campusCount-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.campusCount}</small>}
                </div>

                <div>
                  <label htmlFor="application-deviceCount" style={{ display: 'block', fontSize: '12.5px', fontWeight: 700, color: 'var(--ink2, #48394F)', marginBottom: '6px' }}>Workstation Fleet Size</label>
                  <input
                    id="application-deviceCount"
                    type="number"
                    required
                    aria-required="true"
                    min="10"
                    max="10000"
                    aria-invalid={Boolean(fieldErrors.deviceCount)}
                    aria-describedby={fieldErrors.deviceCount ? 'application-deviceCount-error' : undefined}
                    value={f.deviceCount}
                    onChange={update('deviceCount')}
                    style={{ width: '100%', boxSizing: 'border-box', background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '8px', padding: '10px 14px', color: 'var(--ink, #302337)', fontSize: '13.5px' }}
                  />
                  {fieldErrors.deviceCount && <small id="application-deviceCount-error" role="status" style={{ display: 'block', color: '#A93226', marginTop: '4px' }}>{fieldErrors.deviceCount}</small>}
                </div>
              </div>
            </div>

            {/* Section 4: Terms & Declarations */}
            <section hidden={formStep !== 3} aria-labelledby="application-step-3" style={{ marginBottom: '28px' }}>
              <h3 id="application-step-3" tabIndex="-1" style={{ fontSize: '16px', margin: '0 0 14px' }}>Review and submit</h3>
              <p style={{ fontSize: '13px', lineHeight: 1.55, color: 'var(--ink2, #48394F)' }}>
                <strong>Privacy declaration:</strong> The institution, representative, deployment estimates, and assessment URL entered here are sent to the onboarding service for application review. This form does not request student records. Retention and deletion terms are not published in this flow; do not include sensitive information beyond the fields requested.
              </p>
              <div style={{ background: '#FBF9F7', border: '1px solid var(--line, #DCD5D2)', borderRadius: '10px', padding: '16px', marginBottom: '16px' }}>
                <dl style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 1fr) 2fr', gap: '8px', margin: 0, fontSize: '13px' }}>
                  {[
                    ['Institution', f.legalName],
                    ['Entity type', f.entityType],
                    ['Registration', f.registrationNumber],
                    ['Domain', f.domain],
                    ['Assessment URL', f.targetExamUrl],
                    ['Representative', f.repName],
                    ['Representative email', f.repEmail],
                    ['Deployment model', f.deploymentModel],
                    ['Campuses / centers', f.campusCount],
                    ['Annual candidates', f.studentCount],
                    ['Workstations', f.deviceCount],
                  ].map(([label, value]) => <React.Fragment key={label}><dt>{label}</dt><dd style={{ margin: 0, fontWeight: 650 }}>{value || 'Not provided'}</dd></React.Fragment>)}
                </dl>
              </div>
            <div style={{ background: '#FBF9F7', padding: '20px', borderRadius: '10px', border: '1px solid var(--line, #DCD5D2)' }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: 'var(--ink2, #48394F)', cursor: 'pointer', marginBottom: '12px' }}>
                <input
                  type="checkbox"
                  id="application-termsAgreed"
                  required
                  aria-required="true"
                  aria-invalid={Boolean(fieldErrors.termsAgreed)}
                  aria-describedby={fieldErrors.termsAgreed ? 'application-termsAgreed-error' : undefined}
                  checked={f.termsAgreed}
                  onChange={update('termsAgreed')}
                  style={{ marginTop: '2px', accentColor: 'var(--copper, #B54F34)' }}
                />
                <span>I confirm that I am an authorized institutional representative empowered to submit this application and participate in the verification process.</span>
              </label>
              {fieldErrors.termsAgreed && <small id="application-termsAgreed-error" role="status" style={{ display: 'block', color: '#A93226', margin: '-8px 0 12px 28px' }}>{fieldErrors.termsAgreed}</small>}

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', color: 'var(--ink2, #48394F)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  id="application-privacyAgreed"
                  required
                  aria-required="true"
                  aria-invalid={Boolean(fieldErrors.privacyAgreed)}
                  aria-describedby={fieldErrors.privacyAgreed ? 'application-privacyAgreed-error' : undefined}
                  checked={f.privacyAgreed}
                  onChange={update('privacyAgreed')}
                  style={{ marginTop: '2px', accentColor: 'var(--copper, #B54F34)' }}
                />
                <span>I acknowledge the privacy declaration above and consent to sending these application details for onboarding review.</span>
              </label>
              {fieldErrors.privacyAgreed && <small id="application-privacyAgreed-error" role="status" style={{ display: 'block', color: '#A93226', margin: '-4px 0 0 28px' }}>{fieldErrors.privacyAgreed}</small>}
            </div>
            </section>

            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '14px', alignItems: 'center' }}>
              <Link to="/login" style={{ color: 'var(--mut, #756F79)', textDecoration: 'none', fontSize: '13.5px', fontWeight: 600 }}>Cancel</Link>
              <div style={{ display: 'flex', gap: '8px' }}>
              {formStep > 0 && <button type="button" className="btn" onClick={() => moveToStep(formStep - 1)} disabled={busy}>Back</button>}
              {formStep < 3 ? <button
                type="button"
                onClick={() => moveToStep(formStep + 1)}
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
                Continue to {stepTitles[formStep + 1]} →
              </button> : <button
                type="submit"
                disabled={busy}
                style={{ background: 'var(--copper, #B54F34)', color: '#FFFFFF', border: 'none', borderRadius: '8px', padding: '12px 32px', fontSize: '14px', fontWeight: 700, cursor: busy ? 'wait' : 'pointer' }}
              >
                {busy ? 'Submitting Application…' : 'Submit Application'}
              </button>}
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
