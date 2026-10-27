import { useEffect, useState, useRef } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { safeRedirect } from '../../core/security/sanitize';
import QrCodeSvg from '../../core/ui/QrCodeSvg';

function LoginShowcase() {
  return (
    <div className="login-split-showcase">
      <div className="showcase-brand">
        <div className="showcase-logo">E</div>
        <div>
          <div className="showcase-title">
            ExamOS <span className="showcase-pill">Enterprise</span>
          </div>
          <small style={{ color: '#64748b', fontSize: '11.5px', fontWeight: 500 }}>High-Assurance Examination OS</small>
        </div>
      </div>

      <div className="showcase-main">
        <div className="showcase-headline">
          Mission-Critical Security & <span>Zero-Trust Kiosk Enclave</span>
        </div>
        <p className="showcase-desc">
          Hardware-rooted cryptographic attestation, strict peripheral lockdown, and real-time supervisory telemetry engineered for national assessments and institutional examinations.
        </p>

        {/* Dynamic Vector Graphic Diagram */}
        <div className="showcase-vector-wrapper">
          <svg viewBox="0 0 460 160" width="100%" height="auto" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#2563eb" />
                <stop offset="100%" stopColor="#1d4ed8" />
              </linearGradient>
              <linearGradient id="cardGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ffffff" />
                <stop offset="100%" stopColor="#f8fafc" />
              </linearGradient>
            </defs>

            {/* Hardware Layer Card */}
            <rect x="15" y="15" width="125" height="130" rx="10" fill="url(#cardGrad)" stroke="#bfdbfe" strokeWidth="1.2" />
            <circle cx="77" cy="46" r="18" fill="#eff6ff" stroke="#60a5fa" strokeWidth="1.5" />
            <path d="M77 37 L87 42 V49 C87 55 82 59 77 61 C72 59 67 55 67 49 V42 Z" fill="url(#shieldGrad)" />
            <text x="77" y="80" fill="#0f172a" fontSize="12" fontWeight="700" textAnchor="middle">TPM 2.0</text>
            <text x="77" y="96" fill="#64748b" fontSize="9.5" textAnchor="middle">Hardware Root</text>
            <rect x="35" y="112" width="85" height="18" rx="4" fill="#ecfdf5" stroke="#bbf7d0" />
            <text x="77" y="124" fill="#15803d" fontSize="9" fontWeight="700" textAnchor="middle">PCR-7 LOCKED</text>

            {/* Connecting cryptographic pipe */}
            <path d="M140 80 L165 80" stroke="#3b82f6" strokeWidth="2" strokeDasharray="3 3" />
            <circle cx="152" cy="80" r="4" fill="#3b82f6" />

            {/* OS Kiosk Enclave Layer Card */}
            <rect x="165" y="15" width="130" height="130" rx="10" fill="url(#cardGrad)" stroke="#c7d2fe" strokeWidth="1.2" />
            <rect x="180" y="30" width="100" height="52" rx="6" fill="#f8fafc" stroke="#e2e8f0" />
            <rect x="185" y="35" width="90" height="8" rx="2" fill="#edf2f7" />
            <circle cx="191" cy="39" r="2" fill="#ef4444" />
            <circle cx="197" cy="39" r="2" fill="#f59e0b" />
            <circle cx="203" cy="39" r="2" fill="#10b981" />
            <path d="M210 60 L225 50 L240 60" stroke="#2563eb" strokeWidth="1.5" fill="none" />
            <text x="230" y="102" fill="#0f172a" fontSize="12" fontWeight="700" textAnchor="middle">Cage Enclave</text>
            <text x="230" y="117" fill="#64748b" fontSize="9.5" textAnchor="middle">Wayland Lockdown</text>
            <text x="230" y="132" fill="#4338ca" fontSize="9" fontWeight="700" textAnchor="middle">AIR-GAPPED</text>

            {/* Connecting pipe */}
            <path d="M295 80 L320 80" stroke="#6366f1" strokeWidth="2" strokeDasharray="3 3" />
            <circle cx="308" cy="80" r="4" fill="#6366f1" />

            {/* Real-time Ledger Card */}
            <rect x="320" y="15" width="125" height="130" rx="10" fill="url(#cardGrad)" stroke="#bbf7d0" strokeWidth="1.2" />
            <circle cx="382" cy="46" r="18" fill="#ecfdf5" stroke="#10b981" strokeWidth="1.5" />
            <path d="M376 46 L380 50 L389 40" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <text x="382" y="80" fill="#0f172a" fontSize="12" fontWeight="700" textAnchor="middle">Audit Ledger</text>
            <text x="382" y="96" fill="#64748b" fontSize="9.5" textAnchor="middle">SHA-256 Chained</text>
            <rect x="340" y="112" width="85" height="18" rx="4" fill="#f0fdf4" stroke="#bbf7d0" />
            <text x="382" y="124" fill="#15803d" fontSize="9" fontWeight="700" textAnchor="middle">TAMPER-PROOF</text>
          </svg>
        </div>

        <div className="showcase-features">
          <div className="showcase-feat-item">
            <div className="showcase-feat-icon">🛡️</div>
            <div className="showcase-feat-text">
              <h4>Hardware-Rooted Attestation</h4>
              <p>Cryptographic quote verification on TPM 2.0 PCR-0/4/7 prior to test station unlock.</p>
            </div>
          </div>
          <div className="showcase-feat-item">
            <div className="showcase-feat-icon">🔒</div>
            <div className="showcase-feat-text">
              <h4>Zero-Trust Kiosk Enclave</h4>
              <p>Cage-Wayland session suppresses all OS shortcuts, virtual terminals, and unauthorized processes.</p>
            </div>
          </div>
          <div className="showcase-feat-item">
            <div className="showcase-feat-icon">⚡</div>
            <div className="showcase-feat-text">
              <h4>Real-Time Supervisory Command</h4>
              <p>Dynamic fleet synchronization, instant broadcast reload, and cryptographic single-use credentials.</p>
            </div>
          </div>
        </div>
      </div>

      <div className="showcase-footer">
        <div>Trusted by Assessment Boards & Higher Education</div>
        <div className="showcase-badges">
          <span className="showcase-badge">TPM 2.0</span>
          <span className="showcase-badge">FIPS 140-3</span>
          <span className="showcase-badge">ISO 27001</span>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  const {
    user,
    pending,
    backendLogin,
    backendCandidateLogin,
    verifyMfa,
    backendReady,
    mfaSetup,
    mfaConfirm,
  } = useAuth();

  const loc = useLocation();
  const navigate = useNavigate();

  const [realm, setRealm] = useState('admin'); // 'admin' | 'candidate'
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [candId, setCandId] = useState('');
  const [candPin, setCandPin] = useState('');
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
  const [setupUsername, setSetupUsername] = useState('root');
  const [confirmCode, setConfirmCode] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const mfaInputRef = useRef(null);

  if (user) {
    if (user.role === 'student' || user.candidateId) {
      return <Navigate to="/exam" replace />;
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
    if (busy || !u || !p) return;
    setBusy(true);
    setErr('');
    setInfo('');
    try {
      const res = await backendLogin({ username: u, password: p });
      if (res?.error) {
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
      setErr('ACCESS_DENIED: Candidate examination is restricted exclusively to the ExamOS secure bootable kiosk operating system. External operating systems and standard browsers cannot access candidate sessions.');
      return;
    }
    if (busy || !candId || !candPin) return;
    setBusy(true);
    setErr('');
    try {
      const res = await backendCandidateLogin({ candidateId: candId, pin: candPin });
      if (res?.ok) {
        navigate('/student/home');
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

  const openQrSetup = async (targetUser) => {
    const userToEnroll = targetUser || pending || u || 'root';
    setSetupUsername(userToEnroll);
    setQrLoading(true);
    setErr('');
    setConfirmCode('');
    setShowQrModal(true);
    try {
      const data = await mfaSetup(userToEnroll);
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
        username: qrData.username,
        secret: qrData.secret,
        code: confirmCode,
        recoveryCodes: qrData.recovery_codes,
      });
      if (res?.status === 'SUCCESS' || res?.ok) {
        setInfo(`Google Authenticator configured for ${qrData.username}! You can now use your authenticator app to log in.`);
        setShowQrModal(false);
        if (pending) {
          setCode(confirmCode);
        }
      } else {
        setErr(res?.error || 'Invalid authenticator code. Check your device clock.');
      }
    } catch (e) {
      setErr(e.message || 'Failed to activate Google Authenticator');
    }
    setBusy(false);
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
      `ExamOS Enterprise — Emergency Single-Use Recovery Codes\n` +
      `====================================================\n` +
      `Account:   ${qrData.username}\n` +
      `Generated: ${new Date().toISOString()}\n\n` +
      `Keep these codes in a secure, confidential offline location.\n` +
      `Each code can be used exactly once if your phone is lost:\n\n` +
      qrData.recovery_codes.map((c, i) => `[Code ${i + 1}]  ${c}`).join('\n') +
      `\n\nExamOS Hardware-Rooted Security (RFC 6238 TOTP)`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `examos-recovery-codes-${qrData.username}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const serverStatus = (
    <span className={`login-server ${backendReady ? 'online' : 'offline'}`}>
      <span className="dot" style={{ boxShadow: backendReady ? '0 0 8px #10b981' : 'none' }} />
      {backendReady ? 'Server Online (Port 8895)' : 'Server Disconnected'}
    </span>
  );

  return (
    <div className="login-split-page">
      {/* Left Column: Enterprise Security Enclave & Brand Showcase */}
      <LoginShowcase />

      {/* Right Column: Clean Light-Theme Authentication Form */}
      <div className="login-split-form-pane">
        <div className="login-form-box">
          {!pending ? (
            <>
              <div className="login-head">
                <div className="brand" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '18px', fontWeight: 800 }}>
                  <span className="logo" style={{ width: '30px', height: '30px', fontSize: '14px' }}>E</span> ExamOS
                </div>
                {serverStatus}
              </div>

              <div className="login-realm">
                <button
                  type="button"
                  className={realm === 'admin' ? 'on' : ''}
                  onClick={() => { setRealm('admin'); setErr(''); }}
                >
                  🛡️ Administrator Console
                </button>
                <button
                  type="button"
                  className={realm === 'candidate' ? 'on' : ''}
                  onClick={() => { setRealm('candidate'); setErr(''); }}
                >
                  🎓 Candidate Station
                </button>
              </div>

              {realm === 'admin' ? (
                <form onSubmit={handleAdminSubmit} className="stack">
                  <h2>Sign In to Console</h2>
                  <p className="login-desc">Enter your credentials to access the ExamOS administrative console.</p>

                  <label>
                    Username
                    <input
                      className="input"
                      value={u}
                      onChange={(e) => setU(e.target.value)}
                      autoComplete="username"
                      maxLength={64}
                      placeholder="e.g. admin, instadmin, root..."
                      autoFocus
                    />
                  </label>

                  <label className="pw">
                    Password
                    <input
                      className="input"
                      type={showPw ? 'text' : 'password'}
                      value={p}
                      onChange={(e) => setP(e.target.value)}
                      autoComplete="current-password"
                      maxLength={128}
                      placeholder="••••••••••••"
                    />
                    <button type="button" className="mini" onClick={() => setShowPw(!showPw)}>
                      {showPw ? 'Hide' : 'Show'}
                    </button>
                  </label>

                  {err && <div className="err" role="alert">{err}</div>}
                  {info && <div className="alert success sm">{info}</div>}

                  <button
                    className="btn primary wide"
                    disabled={busy || !u || !p}
                  >
                    {busy ? 'Verifying Credentials…' : 'Sign In'}
                  </button>

                  <div className="login-links">
                    <Link to="/recovery">Lost Phone / Recovery Code</Link>
                    <button
                      type="button"
                      className="link"
                      onClick={() => openQrSetup(u || 'root')}
                    >
                      📱 Setup Google Authenticator QR
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleCandidateSubmit} className="stack">
                  <h2>Candidate Examination Login</h2>
                  <p className="login-desc">Enter your assigned candidate ID and 6-digit security PIN.</p>

                  {isInsideExamOS ? (
                    <div className="login-kiosk">
                      <span>🔒 ExamOS Hardware Kiosk Enclave Active</span>
                      <span className="right">CAGE-WAYLAND</span>
                    </div>
                  ) : (
                    <div className="login-denied">
                      <div className="head">⚠️ ExamOS Kiosk Runtime Required</div>
                      <div>Candidate examinations are restricted exclusively to the verified ExamOS bootable kiosk operating system. Standard desktop browsers and outside operating systems cannot access examination sessions.</div>
                      <small>Please boot this workstation from the official ExamOS USB or ISO drive.</small>
                    </div>
                  )}

                  <label>
                    Candidate Registration ID
                    <input
                      className="input"
                      value={candId}
                      onChange={(e) => setCandId(e.target.value.trim())}
                      maxLength={64}
                      placeholder="e.g. CAND-001"
                      autoFocus
                    />
                  </label>

                  <label>
                    Examination Security PIN
                    <input
                      className="input"
                      type="password"
                      value={candPin}
                      onChange={(e) => setCandPin(e.target.value)}
                      maxLength={32}
                      placeholder="6-digit examination PIN"
                    />
                  </label>

                  {err && <div className="err" role="alert">{err}</div>}

                  <button
                    className="btn primary wide"
                    disabled={busy || !candId || !candPin || !isInsideExamOS}
                  >
                    {!isInsideExamOS
                      ? 'ExamOS Kiosk Runtime Required'
                      : busy
                      ? 'Authenticating Station…'
                      : 'Enter Examination Workspace'}
                  </button>
                </form>
              )}
            </>
          ) : (
            <div className="login-mfa">
              <div className="login-head" style={{ marginBottom: '16px' }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', backgroundColor: 'rgba(37, 99, 235, 0.12)', border: '1px solid rgba(37, 99, 235, 0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px' }}>
                  🔐
                </div>
                <div>
                  <h2 style={{ fontSize: '18px', margin: 0 }}>Two-Factor Authentication</h2>
                  <div className="who" style={{ fontSize: '12px', color: '#64748b' }}>Signing in as: <strong>{pending}</strong></div>
                </div>
              </div>

              <p style={{ fontSize: '13px', color: '#64748b', marginBottom: '18px' }}>
                {isRecoveryCode
                  ? 'Enter one of your 8 single-use emergency recovery codes (e.g. ABCD-1234).'
                  : 'Open the Google Authenticator app on your phone and enter the 6-digit verification code.'}
              </p>

              <label style={{ fontSize: '12px', fontWeight: 700, color: '#0f172a', display: 'block', marginBottom: '6px' }}>
                {isRecoveryCode ? 'Emergency Recovery Code' : 'Google Authenticator 6-Digit Code'}
              </label>

              <input
                ref={mfaInputRef}
                className="code-input"
                inputMode={isRecoveryCode ? 'text' : 'numeric'}
                value={code}
                onChange={(e) => {
                  const val = isRecoveryCode
                    ? e.target.value.toUpperCase().replace(/[^0-9A-Z-]/g, '').slice(0, 16)
                    : e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
                  setCode(val);
                }}
                autoComplete="one-time-code"
                placeholder={isRecoveryCode ? 'XXXX-XXXX' : '000000'}
                style={{
                  fontSize: '22px',
                  letterSpacing: '8px',
                  textAlign: 'center',
                  fontFamily: 'monospace',
                  fontWeight: 650,
                  padding: '12px',
                  width: '100%',
                  borderRadius: '10px',
                  border: '1px solid #cbd5e1',
                  background: '#ffffff',
                  marginBottom: '14px',
                }}
              />

              {err && <div className="err" role="alert">{err}</div>}

              <button
                className="btn primary wide"
                disabled={busy || code.length < (isRecoveryCode ? 8 : 6)}
                onClick={handleMfaSubmit}
              >
                {busy ? 'Verifying Code…' : 'Verify & Access Console'}
              </button>

              <div className="bottom" style={{ marginTop: '16px' }}>
                <button
                  type="button"
                  className="toggle-link"
                  onClick={() => {
                    setIsRecoveryCode(!isRecoveryCode);
                    setCode('');
                    setErr('');
                  }}
                  style={{ background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer', fontSize: '12px', padding: 0 }}
                >
                  {isRecoveryCode ? '← Use 6-Digit Code from Authenticator App' : 'Lost your phone? Use Emergency Recovery Code'}
                </button>
                <div className="pair" style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px' }}>
                  <button
                    type="button"
                    onClick={() => window.location.reload()}
                    className="ghost"
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0, fontSize: '12px' }}
                  >
                    ← Sign in as different user
                  </button>
                  <button
                    type="button"
                    onClick={() => openQrSetup(pending)}
                    className="ghost"
                    style={{ background: 'none', border: 'none', color: '#10b981', cursor: 'pointer', padding: 0, fontSize: '12px' }}
                  >
                    Scan QR Code on Phone
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Google Authenticator Enrollment Modal */}
          {showQrModal && (
            <div className="qr-modal">
              <div className="qr-card">
                <div className="qr-head">
                  <div>
                    <h3>📱 Google Authenticator Setup</h3>
                    <div className="enroll">Enrolling account: <strong>{setupUsername}</strong></div>
                  </div>
                  <button type="button" className="close-btn" onClick={() => setShowQrModal(false)}>×</button>
                </div>

                {qrLoading ? (
                  <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                    <div style={{ fontSize: '14px', marginBottom: '8px' }}>Generating cryptographic key…</div>
                  </div>
                ) : qrData ? (
                  <div>
                    <div className="qr-step">
                      <div className="qr-step-title">Step 1: Scan with Google Authenticator on your phone</div>
                      <div className="qr-frame" style={{ display: 'flex', justifyContent: 'center', padding: '16px' }}>
                        <QrCodeSvg value={qrData.otpauth_url} size={220} />
                      </div>
                      <div className="qr-hint" style={{ marginTop: '10px' }}>
                        Open <strong>Google Authenticator</strong> → tap <strong>+</strong> → tap <strong>Scan a QR code</strong>
                      </div>
                    </div>

                    <div style={{ marginBottom: '16px' }}>
                      <div className="qr-step-title">Or enter setup key manually in Google Authenticator:</div>
                      <div className="qr-secret">
                        <input readOnly value={qrData.secret} style={{ letterSpacing: '1px', fontWeight: 600 }} />
                        <button
                          type="button"
                          className="btn sm"
                          onClick={() => copyToClipboard(qrData.secret, setCopiedKey)}
                        >
                          {copiedKey ? '✓ Copied' : 'Copy Key'}
                        </button>
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
                        In Google Authenticator: tap <strong>+</strong> → <strong>Enter a setup key</strong> → Account: <code>{qrData.username || 'root'}</code>, Key: paste the code above, Type: <strong>Time-based</strong>.
                      </div>
                    </div>

                    <div className="qr-step warn">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <div className="qr-step-title" style={{ color: '#b45309' }}>Step 2: Save Emergency Recovery Codes</div>
                        <div style={{ display: 'flex', gap: '4px' }}>
                          <button
                            type="button"
                            className="btn sm mini"
                            onClick={() => copyToClipboard(qrData.recovery_codes.join('\n'), setCopiedCodes)}
                          >
                            {copiedCodes ? '✓ Copied' : 'Copy All'}
                          </button>
                          <button
                            type="button"
                            className="btn sm mini"
                            onClick={downloadRecoveryCodes}
                          >
                            Download .txt
                          </button>
                        </div>
                      </div>
                      <div className="recovery">
                        {qrData.recovery_codes.map((rc, idx) => (
                          <div key={idx}><span className="idx">{idx + 1}.</span> {rc}</div>
                        ))}
                      </div>
                      <div style={{ fontSize: '10px', color: '#b45309', marginTop: '6px' }}>
                        Each code is single-use. If you ever lose your phone, a recovery code will restore access.
                      </div>
                    </div>

                    <div className="qr-step verify">
                      <div className="verify-title">Step 3: Enter the 6-digit code from Google Authenticator</div>
                      <div className="verify-row">
                        <input
                          inputMode="numeric"
                          maxLength={6}
                          placeholder="000000"
                          value={confirmCode}
                          onChange={(e) => setConfirmCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                          style={{
                            fontSize: '18px',
                            letterSpacing: '5px',
                            textAlign: 'center',
                            fontFamily: 'monospace',
                            fontWeight: 650,
                            padding: '10px',
                            flex: 1,
                          }}
                        />
                        <button
                          type="button"
                          className="btn primary verify-btn"
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
