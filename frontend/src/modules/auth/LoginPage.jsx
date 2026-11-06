import { useEffect, useState, useRef } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { safeRedirect } from '../../core/security/sanitize';
import QrCodeSvg from '../../core/ui/QrCodeSvg';
import SppioLogo, { SppioSymbol } from '../../core/ui/SppioLogo';

function LoginShowcase({ candidateOnly = false }) {
  return (
    <div className="login-editorial-showcase">
      <div className="editorial-content">
        <div className="editorial-brand">
          <SppioLogo width={164} accent="#B54F34" ink="#FFFFFF" />
          <span className="editorial-badge">{candidateOnly ? 'ExamOS Candidate Station' : 'SPPIO-Command™ Console'}</span>
        </div>

        <div className="editorial-hero">
          <div className="editorial-telemetry-badge">
            <span className="editorial-ping" />
            <span>{candidateOnly ? 'Candidate examination sign-in' : 'Management console sign-in'}</span>
          </div>

          {candidateOnly ? (
            <>
              <h1 className="editorial-headline">Your examination <span>workspace</span></h1>
              <p className="editorial-sub">Sign in with the candidate ID and examination PIN provided by your institution.</p>
              <div className="editorial-points">
                <div className="editorial-point">
                  <div className="editorial-point-marker" />
                  <div>
                    <strong>Secure candidate access</strong>
                    <p>Your assignments and exam readiness steps are shown after authentication.</p>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <>
              <h1 className="editorial-headline">
                High-Assurance Infrastructure for <span>Enterprise Recruitment &amp; Exams</span>
              </h1>
              <p className="editorial-sub">
                Sign in to manage institution, examination, and assessment workflows.
              </p>

              <div className="editorial-points">
                <div className="editorial-point">
                  <div className="editorial-point-marker" />
                  <div>
                    <strong>SPPIO-Isolation™ &amp; Kiosk™ Sandbox</strong>
                    <p>Assessment station controls depend on supported hardware and the profile configured for your institution.</p>
                  </div>
                </div>
                <div className="editorial-point">
                  <div className="editorial-point-marker" />
                  <div>
                    <strong>SPPIO-Proctor™ &amp; Forensics™</strong>
                    <p>Optional monitoring and event-review features depend on enabled modules, consent, and retention policy.</p>
                  </div>
                </div>
                <div className="editorial-point">
                  <div className="editorial-point-marker" />
                  <div>
                    <strong>SPPIO-Ledger™ &amp; Core™ Storage</strong>
                    <p>Hash-linked audit events may make selected changes detectable; they do not by themselves guarantee non-repudiation or compliance.</p>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>

        <div className="editorial-footer">
          {!candidateOnly && (
            <div className="editorial-standards">
              <span>SPPIO-TrustEngine™</span>
              <span className="sep">•</span>
              <span>SPPIO-PhysicalGuard™</span>
              <span className="sep">•</span>
              <span>SPPIO-Forensics™</span>
              <span className="sep">•</span>
              <span>Deployment-specific controls</span>
            </div>
          )}
          <div className="editorial-copy">{candidateOnly ? 'ExamOS Candidate Examination Portal' : '© 2026 SPPIO Systems Enclave. All rights reserved.'}</div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage({ candidateOnly = false }) {
  const {
    user,
    pending,
    backendLogin,
    backendCandidateLogin,
    verifyMfa,
    cancelPending,
    backendReady,
    mfaSetup,
    mfaConfirm,
  } = useAuth();

  const loc = useLocation();
  const navigate = useNavigate();

  const [realm, setRealm] = useState(() => candidateOnly || new URLSearchParams(window.location.search).get('realm') === 'candidate' ? 'candidate' : 'admin');
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [candId, setCandId] = useState('');
  const [candPin, setCandPin] = useState('');
  const [candExamToken, setCandExamToken] = useState('');
  const [code, setCode] = useState('');
  const [isRecoveryCode, setIsRecoveryCode] = useState(false);
  const [err, setErr] = useState('');
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);
  const [showPw, setShowPw] = useState(false);

  // Authenticator QR Setup Modal state
  const [showQrModal, setShowQrModal] = useState(false);
  const [qrLoading, setQrLoading] = useState(false);
  const [qrData, setQrData] = useState(null);
  const [setupUsername, setSetupUsername] = useState('');
  const [confirmCode, setConfirmCode] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const mfaInputRef = useRef(null);

  if (user) {
    if (user.role === 'student' || user.candidateId) {
      return <Navigate to="/student/home" replace />;
    }
    return <Navigate to={safeRedirect(loc.state?.from)} replace />;
  }

  useEffect(() => {
    if (pending && mfaInputRef.current) {
      mfaInputRef.current.focus();
    }
  }, [pending]);

  const isInsideExamOS = typeof navigator !== 'undefined' &&
    (navigator.userAgent.includes('ExamOS-Kiosk') ||
     (typeof window !== 'undefined' && (
       window.location.search.includes('kiosk=1') ||
       window.location.search.includes('dev_kiosk=1')
     )));

  const handleAdminSubmit = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    const username = u.trim();
    if (busy || !username || !p) return;
    setBusy(true);
    setErr('');
    setInfo('');
    try {
      const res = await backendLogin({ username, password: p });
      if (res?.mfaSetupRequired) {
        setInfo('First-time login: Please set up Google Authenticator to secure your management account.');
        openQrSetup();
      } else if (res?.mfa) {
        setInfo('Enter the 6-digit code from your Google Authenticator app.');
      } else if (res?.error) {
        setErr(res.error);
      }
    } catch (x) {
      setErr(x.message || 'Authentication failed. Please verify credentials.');
    }
    setBusy(false);
  };

  const handleCandidateSubmit = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!isInsideExamOS) {
      setErr('ACCESS_DENIED: Candidate examinations require the secure ExamOS bootable kiosk operating system.');
      return;
    }
    const candidateId = candId.trim();
    const pin = candPin.trim();
    const examToken = candExamToken.trim();
    if (busy || !candidateId || (!pin && !examToken)) return;
    setBusy(true);
    setErr('');
    try {
      const res = await backendCandidateLogin({
        candidateId,
        pin,
        examToken,
        onPending: () => setInfo('Identity submitted. Waiting for an invigilator to verify you at the desk…'),
      });
      if (res?.ok) {
        const examId = res.profile?.examId;
        navigate(examId ? `/student/exams/${encodeURIComponent(examId)}` : '/student/home', { replace: true });
      } else if (res?.error) {
        setErr(res.error);
      }
    } catch (x) {
      setErr(x.message || 'Candidate authentication failed.');
    }
    setBusy(false);
  };

  const handleMfaSubmit = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (busy || !code) return;
    setBusy(true);
    setErr('');
    try {
      const res = await verifyMfa(code);
      if (res?.ok) {
        navigate(safeRedirect(loc.state?.from));
      } else if (res?.error) {
        setErr(res.error);
      }
    } catch (x) {
      setErr(x.message || 'MFA code verification failed.');
    }
    setBusy(false);
  };


  const openQrSetup = async () => {
    setSetupUsername(pending || u || '');
    setQrLoading(true);
    setErr('');
    setConfirmCode('');
    setShowQrModal(true);
    try {
      const data = await mfaSetup();
      if (data?.error) {
        setErr(data.error);
        setShowQrModal(false);
      } else {
        setQrData(data);
      }
    } catch (e) {
      setErr(e.message || 'Failed to initialize Google Authenticator');
      setShowQrModal(false);
    }
    setQrLoading(false);
  };

  const handleConfirmMfa = async () => {

    if (!qrData || confirmCode.length < 6) return;

    setBusy(true);

    setErr('');

    try {

      const res = await mfaConfirm({

        code: confirmCode,

      });

      if (res?.status === 'SUCCESS' || res?.ok) {

        setInfo(`Google Authenticator configured for ${qrData.username}! Logging in…`);

        setShowQrModal(false);

        const loginUser = qrData.username || u;

        if (p) {

          try {

            const authRes = await backendLogin({ username: loginUser, password: p, mfaCode: confirmCode });

            if (authRes?.ok) {

              navigate(safeRedirect(loc.state?.from));

              return;

            } else if (authRes?.error) {

              setErr(authRes.error);

            }

          } catch (loginErr) {

            setErr(loginErr.message || 'Failed to complete login. Please sign in with your authenticator code.');

          }

        }

        if (pending) {

          setCode(confirmCode);

        }

      } else {

        setErr(res?.error || 'Invalid authenticator code. Check your device clock.');

      }

    } catch (e) {

      setErr(e.message || 'Failed to activate Google Authenticator');

    } finally {

      setBusy(false);

    }

  };


  const copyToClipboard = (text, setCopied) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const downloadRecoveryCodes = () => {
    if (!qrData?.recovery_codes) return;
    const content =
      `====================================================\n` +
      `SPPIO Enterprise — Emergency Single-Use Recovery Codes\n` +
      `====================================================\n` +
      `Account:   ${qrData.username}\n` +
      `Generated: ${new Date().toISOString()}\n\n` +
      `Keep these codes in a secure, confidential offline location.\n` +
      `Each code can be used exactly once if your phone is lost:\n\n` +
      qrData.recovery_codes.map((c, i) => `[Code ${i + 1}]  ${c}`).join('\n') +
      `\n\nSPPIO Hardware-Rooted Security (RFC 6238 TOTP)`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sppio-recovery-codes-${qrData.username}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`login-flow-container${candidateOnly ? ' candidate-login-only' : ''}`}>
      {/* Left Column: Refined Editorial Showcase (No Cards / No Grids) */}
      <LoginShowcase candidateOnly={candidateOnly} />

      {/* Right Column: Polished Authentication Form */}
      <div className="login-form-container">
        <div className="login-form-inner">
          {/* Prominent SPPIO Logo Header */}
          <div className="login-form-brand">
            <SppioLogo width={152} accent="#B54F34" ink="#302337" />
          </div>

          {!pending ? (
            <>
              {/* Header with Connectivity Status */}
              <div className="login-auth-header">
                <div>
                  <h2 className="login-auth-title">{candidateOnly ? 'Candidate Sign In' : 'SPPIO Console Access'}</h2>
                  <p className="login-auth-subtitle">{candidateOnly ? 'Enter your institution-issued examination credentials.' : 'Choose the sign-in path for your role.'}</p>
                </div>
                <div className={`status-pill ${backendReady ? 'status-online' : 'status-offline'}`}>
                  <span className="status-ping" />
                  <span>{backendReady ? 'Backend Online' : 'Backend Offline'}</span>
                </div>
              </div>

              {/* Segmented Realm Switcher */}
              {!candidateOnly && <div className="segmented-realm-control">
                <button
                  type="button"
                  className={`realm-btn ${realm === 'admin' ? 'active' : ''}`}
                  aria-pressed={realm === 'admin'}
                  onClick={() => { setRealm('admin'); setErr(''); }}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  Admin Console
                </button>
                <button
                  type="button"
                  className={`realm-btn ${realm === 'candidate' ? 'active' : ''}`}
                  aria-pressed={realm === 'candidate'}
                  onClick={() => { setRealm('candidate'); setErr(''); }}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 10v6M2 10l10-5 10 5-10 5z"/>
                    <path d="M6 12v5c3 3 9 3 12 0v-5"/>
                  </svg>
                  Candidate Station
                </button>
              </div>}

              {!candidateOnly && realm === 'admin' ? (
                <form onSubmit={handleAdminSubmit} className="login-flow-form">
                  <div className="input-group">
                    <label htmlFor="login-username">Username</label>
                    <div className="input-wrapper">
                      <span className="input-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                          <circle cx="12" cy="7" r="4" />
                        </svg>
                      </span>
                      <input
                        id="login-username"
                        className="polished-input with-icon"
                        value={u}
                        onChange={(e) => setU(e.target.value)}
                        onBlur={() => setU((value) => value.trim())}
                        autoComplete="username"
                        maxLength={64}
                        placeholder="admin or root"
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="input-group">
                    <div className="label-row">
                      <label htmlFor="login-password">Password</label>
                      <button
                        type="button"
                        className="text-action-link"
                        onClick={() => setShowPw(!showPw)}
                      >
                        {showPw ? 'Hide password' : 'Show password'}
                      </button>
                    </div>
                    <div className="input-wrapper">
                      <span className="input-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                      </span>
                      <input
                        id="login-password"
                        className="polished-input with-icon"
                        type={showPw ? 'text' : 'password'}
                        value={p}
                        onChange={(e) => setP(e.target.value)}
                        autoComplete="current-password"
                        maxLength={128}
                        placeholder="••••••••••••"
                      />
                    </div>
                  </div>

                  {/*
                    Credential quick-fill chips were removed deliberately.
                    Shipping admin passwords in the bundle lets anyone with the
                    login page obtain management credentials; operators must
                    receive their first password out of band.
                  */}

                  {err && (
                    <div className="polished-error-banner" role="alert">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="8" x2="12" y2="12" />
                        <line x1="12" y1="16" x2="12.01" y2="16" />
                      </svg>
                      <span>{err}</span>
                    </div>
                  )}

                  {info && (
                    <div className="polished-success-banner">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      <span>{info}</span>
                    </div>
                  )}

                  <button
                    className="polished-submit-btn"
                    disabled={busy || !u.trim() || !p}
                  >
                    {busy ? (
                      <span className="btn-loading">
                        <span className="spinner-dots" />
                        Authenticating…
                      </span>
                    ) : (
                      'Sign In to Console'
                    )}
                  </button>

                  <div className="form-secondary-links">
                    <Link to="/recovery" className="secondary-link">Lost Phone / Recovery Code</Link>
                    {/*
                      Authenticator enrollment is bound to a single-use token issued
                      by a successful password check (first-time login) or to an
                      authenticated management session. A standalone button here
                      could never satisfy either requirement, so it is not offered.
                    */}
                    <Link to="/landing" className="secondary-link">Platform Overview →</Link>
                  </div>
                  <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid rgba(0,0,0,0.08)', textAlign: 'center' }}>
                    <span style={{ fontSize: '12.5px', color: '#6b7280' }}>Accredited University / College? </span>
                    <Link to="/register-institution" style={{ fontSize: '12.5px', fontWeight: 700, color: '#B54F34', textDecoration: 'none' }}>
                      Apply for Onboarding →
                    </Link>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleCandidateSubmit} className="login-flow-form">
                  {!isInsideExamOS && (
                    <div className="kiosk-notice-banner">
                      <div className="notice-title">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                          <line x1="12" y1="9" x2="12" y2="13"/>
                          <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        ExamOS Hardware Kiosk Required
                      </div>
                      <p>
                        Candidate exams require an institution-configured ExamOS kiosk workstation. This browser cannot start an exam. Contact your institution’s exam office or help desk for kiosk access and assistance.
                      </p>
                    </div>
                  )}

                  <div className="input-group">
                    <label htmlFor="cand-id">Candidate Registration ID</label>
                    <input
                      id="cand-id"
                      className="polished-input"
                      value={candId}
                      onChange={(e) => setCandId(e.target.value)}
                      onBlur={() => setCandId((value) => value.trim())}
                      maxLength={64}
                      placeholder="e.g. CAND-001 or roll number"
                      autoFocus
                    />
                  </div>

                  <div className="input-group">
                    <label htmlFor="cand-pin">Candidate PIN (account/proctor-verified exams)</label>
                    <input
                      id="cand-pin"
                      className="polished-input"
                      type="password"
                      value={candPin}
                      onChange={(e) => setCandPin(e.target.value)}
                      onBlur={() => setCandPin((value) => value.trim())}
                      maxLength={32}
                      placeholder="Enter your candidate PIN"
                    />
                  </div>

                  <div className="input-group">
                    <label htmlFor="cand-exam-token">Single-use desk token (token-authenticated exams)</label>
                    <input
                      id="cand-exam-token"
                      className="polished-input"
                      type="password"
                      value={candExamToken}
                      onChange={(e) => setCandExamToken(e.target.value)}
                      onBlur={() => setCandExamToken((value) => value.trim())}
                      maxLength={128}
                      autoComplete="off"
                      placeholder="Enter token issued by the invigilator"
                    />
                    <p className="login-auth-subtitle">Use your PIN or the one-time token provided for this exam. The exam setting decides which credential is accepted.</p>
                  </div>

                  {info && <div className="polished-success-banner" role="status">{info}</div>}

                  {err && (
                    <div className="polished-error-banner" role="alert">
                      <span>{err}</span>
                    </div>
                  )}

                  <button
                    className="polished-submit-btn"
                    disabled={busy || !candId.trim() || (!candPin.trim() && !candExamToken.trim()) || !isInsideExamOS}
                  >
                    {!isInsideExamOS
                      ? 'ExamOS Kiosk Runtime Required'
                      : busy
                      ? (info ? 'Waiting for Invigilator…' : 'Authenticating Station…')
                      : 'Enter Examination Workspace'}
                  </button>
                </form>
              )}
            </>
          ) : (
            /* Two-Factor Authentication View */
            <div className="mfa-flow-view">
              <div className="mfa-icon-badge">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
              </div>
              <h2 className="login-auth-title" style={{ marginTop: '12px' }}>Two-Factor Authentication</h2>
              <p className="login-auth-subtitle">
                Enter code for <strong>{pending}</strong> from your Google Authenticator app.
              </p>

              <div className="input-group" style={{ marginTop: '20px' }}>
                <label htmlFor="mfa-code">{isRecoveryCode ? 'Single-use recovery code' : '6-digit authenticator code'}</label>
                <input
                  id="mfa-code"
                  ref={mfaInputRef}
                  className="polished-mfa-input"
                  inputMode={isRecoveryCode ? 'text' : 'numeric'}
                  autoComplete="one-time-code"
                  aria-describedby="mfa-help mfa-error"
                  aria-invalid={Boolean(err)}
                  value={code}
                  onChange={(e) => {
                    const val = isRecoveryCode
                      ? e.target.value.toUpperCase().replace(/[^0-9A-Z-]/g, '').slice(0, 16)
                      : e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
                    setCode(val);
                  }}
                  placeholder={isRecoveryCode ? 'XXXX-XXXX' : '••••••'}
                  autoFocus
                />
                <p id="mfa-help" className="login-auth-subtitle">Paste a current authenticator code. Recovery codes can be used once; remove spaces or dashes if needed.</p>
              </div>

              {err && <div id="mfa-error" className="polished-error-banner" role="alert">{err}</div>}

              <button
                className="polished-submit-btn"
                disabled={busy || code.length < (isRecoveryCode ? 8 : 6)}
                onClick={handleMfaSubmit}
                style={{ marginTop: '16px' }}
              >
                {busy ? 'Verifying Code…' : 'Verify & Access Console'}
              </button>

              <div className="mfa-footer-actions">
                <button
                  type="button"
                  className="text-action-link"
                  onClick={() => {
                    setIsRecoveryCode(!isRecoveryCode);
                    setCode('');
                    setErr('');
                  }}
                >
                  {isRecoveryCode ? 'Use 6-digit Authenticator Code' : 'Use emergency recovery code'}
                </button>
                <button
                  type="button"
                  onClick={() => { if (cancelPending) cancelPending(); setCode(""); setErr(""); }}
                  className="text-secondary-link"
                >
                  ← Sign in as different user
                </button>
              </div>
            </div>
          )}

          {/* Minimalist Google Authenticator Setup Modal */}
          {showQrModal && (
            <div className="polished-modal-backdrop">
              <div className="polished-modal-dialog">
                <div className="modal-header-row">
                  <div>
                    <h3 className="modal-title">Configure Google Authenticator</h3>
                    <p className="modal-sub">Account: <strong>{setupUsername}</strong></p>
                  </div>
                  <button type="button" className="modal-close-icon" onClick={() => setShowQrModal(false)}>
                    ×
                  </button>
                </div>

                {qrLoading ? (
                  <div className="modal-loader">Generating cryptographic secret…</div>
                ) : qrData ? (
                  <div className="modal-flow-content">
                    <div className="modal-step-section">
                      <span className="step-tag">Step 1</span>
                      <p className="step-instruction">Scan this QR code with Google Authenticator on your mobile phone:</p>
                      <div className="qr-render-box">
                        <QrCodeSvg value={qrData.otpauth_url} size={200} />
                      </div>
                    </div>

                    <div className="modal-step-section">
                      <span className="step-tag">Step 2</span>
                      <p className="step-instruction">Manual setup key (if camera is unavailable):</p>
                      <div className="secret-copy-box">
                        <code>{qrData.secret}</code>
                        <button
                          type="button"
                          className="chip-btn"
                          onClick={() => copyToClipboard(qrData.secret, setCopiedKey)}
                        >
                          {copiedKey ? 'Copied' : 'Copy Key'}
                        </button>
                      </div>
                    </div>

                    <div className="modal-step-section recovery-section">
                      <div className="label-row">
                        <span className="step-tag">Step 3</span>
                        <div className="recovery-actions">
                          <button
                            type="button"
                            className="chip-btn"
                            onClick={() => copyToClipboard(qrData.recovery_codes.join('\n'), setCopiedCodes)}
                          >
                            {copiedCodes ? 'Copied' : 'Copy Codes'}
                          </button>
                          <button
                            type="button"
                            className="chip-btn"
                            onClick={downloadRecoveryCodes}
                          >
                            Download .txt
                          </button>
                        </div>
                      </div>
                      <p className="step-instruction">Single-use emergency recovery codes:</p>
                      <div className="recovery-codes-flow">
                        {qrData.recovery_codes.map((rc, idx) => (
                          <span key={idx} className="recovery-code-pill">{rc}</span>
                        ))}
                      </div>
                    </div>

                    <div className="modal-step-section verify-section">
                      <span className="step-tag">Step 4</span>
                      <p className="step-instruction">Enter the 6-digit code shown in Google Authenticator:</p>
                      <div className="verify-input-row">
                        <input
                          className="polished-input"
                          inputMode="numeric"
                          maxLength={6}
                          placeholder="000000"
                          value={confirmCode}
                          onChange={(e) => setConfirmCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                          style={{ textAlign: 'center', letterSpacing: '4px', fontSize: '18px', fontWeight: 700 }}
                        />
                        <button
                          type="button"
                          className="polished-submit-btn compact"
                          disabled={busy || confirmCode.length < 6}
                          onClick={handleConfirmMfa}
                        >
                          {busy ? 'Activating…' : 'Activate 2FA'}
                        </button>
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
