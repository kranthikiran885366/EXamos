import { useEffect, useState, useRef } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { safeRedirect } from '../../core/security/sanitize';
import QrCodeSvg from '../../core/ui/QrCodeSvg';

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
  const [qrData, setQrData] = useState(null); // { username, secret, otpauth_url, recovery_codes }
  const [setupUsername, setSetupUsername] = useState('root');
  const [confirmCode, setConfirmCode] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const mfaInputRef = useRef(null);

  // If already authenticated, redirect
  if (user) {
    if (user.role === 'student' || user.candidateId) {
      return <Navigate to="/exam" replace />;
    }
    return <Navigate to={safeRedirect(loc.state?.from)} replace />;
  }

  // Auto-focus MFA input on appearance
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

  // Open Google Authenticator Enrollment modal
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

  // Confirm Google Authenticator code and activate in database
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

  return (
    <div className="loginwrap">
      <div className="login" style={{ maxWidth: '480px' }}>
        {/* Brand & Server Status Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <div className="brand" style={{ margin: 0, fontSize: '1.75rem' }}>
            <span className="logo">E</span>ExamOS
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '20px',
              backgroundColor: backendReady ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${backendReady ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              fontSize: '11px',
              fontFamily: 'monospace',
              color: backendReady ? '#10b981' : '#ef4444',
            }}
          >
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: backendReady ? '#10b981' : '#ef4444',
                boxShadow: backendReady ? '0 0 8px #10b981' : 'none',
              }}
            />
            {backendReady ? 'Server Online (Port 8000)' : 'Server Disconnected'}
          </div>
        </div>

        <div className="login-tag" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <span>Defense-Grade Secure Examination Console</span>
          <span style={{ fontSize: '10px', fontFamily: 'monospace', opacity: 0.75 }}>TPM 2.0 PCR-7</span>
        </div>

        {!pending ? (
          <>
            {/* Realm Selector Tabs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '1.5rem', backgroundColor: 'rgba(0,0,0,0.2)', padding: '4px', borderRadius: '8px' }}>
              <button
                type="button"
                className={`btn sm ${realm === 'admin' ? 'primary' : ''}`}
                onClick={() => { setRealm('admin'); setErr(''); }}
                style={{ flex: 1, padding: '8px 12px', borderRadius: '6px', fontWeight: 600 }}
              >
                🛡️ Administrator Console
              </button>
              <button
                type="button"
                className={`btn sm ${realm === 'candidate' ? 'primary' : ''}`}
                onClick={() => { setRealm('candidate'); setErr(''); }}
                style={{ flex: 1, padding: '8px 12px', borderRadius: '6px', fontWeight: 600 }}
              >
                🎓 Candidate Kiosk Station
              </button>
            </div>

            {realm === 'admin' ? (
              /* Administrative Login Form */
              <form onSubmit={handleAdminSubmit}>
                <div style={{ marginBottom: '1rem' }}>
                  <h2 style={{ fontSize: '1.3rem', margin: '0 0 4px 0' }}>Sign In to Console</h2>
                  <p className="muted" style={{ fontSize: '12px', margin: 0 }}>
                    Direct cryptographic authentication against the ExamOS C server.
                  </p>
                </div>

                <label>
                  Username
                  <input
                    value={u}
                    onChange={(e) => setU(e.target.value)}
                    autoComplete="username"
                    maxLength={64}
                    placeholder="root, ananya, instadmin, controller..."
                    autoFocus
                  />
                </label>

                <label>
                  Password
                  <span className="pw">
                    <input
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
                  </span>
                </label>

                {err && <div className="err" role="alert" style={{ marginBottom: '12px' }}>{err}</div>}
                {info && <div className="alert success sm" style={{ marginBottom: '12px' }}>{info}</div>}

                <button
                  className="btn primary wide"
                  disabled={busy || !u || !p}
                  style={{ height: '44px', fontSize: '14px', fontWeight: 600, marginTop: '4px' }}
                >
                  {busy ? 'Verifying Credentials…' : 'Sign In'}
                </button>

                {/* Google Authenticator Setup & Recovery Links */}
                <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Link to="/recovery" style={{ fontSize: '12px', color: '#94a3b8' }}>
                    Lost Phone / Recovery Code
                  </Link>
                  <button
                    type="button"
                    onClick={() => openQrSetup(u || 'root')}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#38bdf8',
                      fontSize: '12px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: 0,
                    }}
                  >
                    <span>📱 Setup Google Authenticator QR</span>
                  </button>
                </div>

                {/* Account Credentials Quick Reference */}
                <details className="dev" style={{ marginTop: '1.25rem', padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <summary style={{ cursor: 'pointer', fontSize: '11px', color: '#94a3b8' }}>
                    🔑 Initial Provisioned Administrator Accounts
                  </summary>
                  <div style={{ padding: '8px 0', fontSize: '11px', display: 'grid', gap: '5px' }}>
                    <div><code>root</code> / <code>Exam0S!Root#2026</code> · Tier-5 Platform Owner</div>
                    <div><code>ananya</code> / <code>Exam0S!Dean#2026</code> · Academic Dean</div>
                    <div><code>instadmin</code> / <code>Exam0S!InstAdmin#2026</code> · Institution Admin</div>
                    <div><code>controller</code> / <code>Exam0S!ExamCtrl#2026</code> · Exam Controller</div>
                    <div><code>security</code> / <code>Exam0S!SecEng#2026</code> · Security Officer</div>
                    <div style={{ marginTop: '4px', color: '#38bdf8' }}>
                      Tip: Click "Setup Google Authenticator QR" to scan the live QR code with your phone!
                    </div>
                  </div>
                </details>
              </form>
            ) : (
              /* Candidate Exam Portal */
              <form onSubmit={handleCandidateSubmit}>
                <div style={{ marginBottom: '1rem' }}>
                  <h2 style={{ fontSize: '1.3rem', margin: '0 0 4px 0' }}>Candidate Examination Login</h2>
                  <p className="muted" style={{ fontSize: '12px', margin: 0 }}>
                    Enter assigned registration ID and 6-digit security PIN.
                  </p>
                </div>

                {isInsideExamOS ? (
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      backgroundColor: 'rgba(56, 189, 248, 0.08)',
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                      marginBottom: '1rem',
                      fontSize: '11px',
                      color: '#38bdf8',
                    }}
                  >
                    <span>🔒 ExamOS Hardware Kiosk Enclave Active</span>
                    <span style={{ marginLeft: 'auto', fontFamily: 'monospace', fontWeight: 600 }}>CAGE-WAYLAND</span>
                  </div>
                ) : (
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(239, 68, 68, 0.12)',
                      border: '1px solid #ef4444',
                      marginBottom: '1rem',
                      fontSize: '12px',
                      color: '#fca5a5',
                      lineHeight: '1.5',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, color: '#f87171' }}>
                      <span>⚠️</span>
                      <span>ExamOS Kiosk Runtime Required</span>
                    </div>
                    <div>
                      Candidate examinations are restricted exclusively to the bootable ExamOS appliance operating system. Standard desktop browsers and outside operating systems cannot take candidate exams.
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                      Please boot this computer from the verified ExamOS bootable USB / ISO drive.
                    </div>
                  </div>
                )}

                <label>
                  Candidate Registration ID
                  <input
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
                    type="password"
                    value={candPin}
                    onChange={(e) => setCandPin(e.target.value)}
                    maxLength={32}
                    placeholder="6-digit examination PIN"
                  />
                </label>

                {err && <div className="err" role="alert" style={{ marginBottom: '12px' }}>{err}</div>}

                <button
                  className="btn primary wide"
                  disabled={busy || !candId || !candPin || !isInsideExamOS}
                  style={{
                    height: '44px',
                    fontSize: '14px',
                    fontWeight: 600,
                    marginTop: '4px',
                    opacity: !isInsideExamOS ? 0.6 : 1,
                    cursor: !isInsideExamOS ? 'not-allowed' : 'pointer',
                  }}
                >
                  {!isInsideExamOS
                    ? 'ExamOS Kiosk Runtime Required'
                    : busy
                    ? 'Authenticating Station…'
                    : 'Enter Examination Workspace'}
                </button>

                <details className="dev" style={{ marginTop: '1.25rem', padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  <summary style={{ cursor: 'pointer', fontSize: '11px', color: '#94a3b8' }}>
                    📝 Candidate Test Credentials
                  </summary>
                  <div style={{ padding: '6px 0', fontSize: '11px' }}>
                    <div><code>CAND-001</code> / PIN: <code>123456</code> · Aarav Sharma</div>
                  </div>
                </details>
              </form>
            )}
          </>
        ) : (
          /* Two-Step Verification Form */
          <form onSubmit={handleMfaSubmit}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <div
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(56, 189, 248, 0.15)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '20px',
                }}
              >
                🔐
              </div>
              <div>
                <h2 style={{ fontSize: '1.25rem', margin: 0 }}>Two-Factor Authentication</h2>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  Signing in as: <strong style={{ color: '#38bdf8' }}>{pending}</strong>
                </div>
              </div>
            </div>

            <p className="muted" style={{ fontSize: '12px', marginBottom: '1.25rem' }}>
              {isRecoveryCode
                ? 'Enter one of your 8 single-use emergency recovery codes (e.g. ABCD-1234).'
                : 'Open the Google Authenticator app on your phone and enter the 6-digit code for ExamOS.'}
            </p>

            <label>
              {isRecoveryCode ? 'Emergency Recovery Code' : 'Google Authenticator 6-Digit Code'}
              <input
                ref={mfaInputRef}
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
                  fontSize: '20px',
                  letterSpacing: isRecoveryCode ? '2px' : '6px',
                  textAlign: 'center',
                  fontFamily: 'monospace',
                  padding: '12px',
                  fontWeight: 600,
                }}
              />
            </label>

            {err && <div className="err" role="alert" style={{ marginBottom: '12px' }}>{err}</div>}

            <button
              className="btn primary wide"
              disabled={busy || code.length < (isRecoveryCode ? 8 : 6)}
              style={{ height: '44px', fontSize: '14px', fontWeight: 600, marginTop: '4px' }}
            >
              {busy ? 'Verifying Code…' : 'Verify & Access Console'}
            </button>

            <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <button
                type="button"
                onClick={() => {
                  setIsRecoveryCode(!isRecoveryCode);
                  setCode('');
                  setErr('');
                }}
                style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', textAlign: 'left', padding: 0 }}
              >
                {isRecoveryCode ? '← Use 6-Digit Code from Authenticator App' : 'Lost your phone? Use Emergency Recovery Code'}
              </button>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                <button
                  type="button"
                  onClick={() => window.location.reload()}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}
                >
                  ← Sign in as different user
                </button>
                <button
                  type="button"
                  onClick={() => openQrSetup(pending)}
                  style={{ background: 'none', border: 'none', color: '#10b981', cursor: 'pointer', padding: 0 }}
                >
                  Scan QR Code on Phone
                </button>
              </div>
            </div>
          </form>
        )}

        {/* ----------------- GOOGLE AUTHENTICATOR ENROLLMENT MODAL ----------------- */}
        {showQrModal && (
          <div
            style={{
              position: 'fixed',
              inset: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.85)',
              backdropFilter: 'blur(5px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 1000,
              padding: '16px',
            }}
          >
            <div
              style={{
                backgroundColor: 'var(--card, #0f172a)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '12px',
                padding: '24px',
                maxWidth: '460px',
                width: '100%',
                maxHeight: '90vh',
                overflowY: 'auto',
                boxShadow: '0 25px 50px rgba(0, 0, 0, 0.6)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.25rem', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>📱</span> Google Authenticator Setup
                  </h3>
                  <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
                    Enrolling account: <strong style={{ color: '#38bdf8' }}>{setupUsername}</strong>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setShowQrModal(false)}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '22px', cursor: 'pointer', padding: '0 4px' }}
                >
                  ×
                </button>
              </div>

              {qrLoading ? (
                <div style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
                  <div style={{ fontSize: '14px', marginBottom: '8px' }}>Generating cryptographic key…</div>
                </div>
              ) : qrData ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Step 1: Scan QR Code */}
                  <div style={{ backgroundColor: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#38bdf8', marginBottom: '8px' }}>
                      Step 1: Scan with Google Authenticator on your phone
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '12px', backgroundColor: '#ffffff', borderRadius: '8px' }}>
                      <QrCodeSvg value={qrData.otpauth_url} size={180} />
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', textAlign: 'center', marginTop: '8px' }}>
                      Open Google Authenticator → tap <strong>+</strong> → tap <strong>Scan a QR code</strong>
                    </div>
                  </div>

                  {/* Step 2: Secret Key */}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#94a3b8', marginBottom: '4px' }}>
                      Or enter setup key manually:
                    </div>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <input
                        readOnly
                        value={qrData.secret}
                        style={{ fontFamily: 'monospace', fontSize: '12px', letterSpacing: '1px' }}
                      />
                      <button
                        type="button"
                        className="btn sm"
                        onClick={() => copyToClipboard(qrData.secret, setCopiedKey)}
                        style={{ minWidth: '70px' }}
                      >
                        {copiedKey ? '✓ Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  {/* Step 3: Emergency Backup Codes */}
                  <div style={{ backgroundColor: 'rgba(234, 179, 8, 0.05)', border: '1px solid rgba(234, 179, 8, 0.2)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: '#eab308' }}>
                        Step 2: Save Emergency Recovery Codes
                      </div>
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
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: '4px',
                        padding: '8px',
                        backgroundColor: 'rgba(0, 0, 0, 0.3)',
                        borderRadius: '6px',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        color: '#f8fafc',
                      }}
                    >
                      {qrData.recovery_codes.map((rc, idx) => (
                        <div key={idx} style={{ padding: '2px 4px' }}>
                          <span style={{ color: '#64748b' }}>{idx + 1}.</span> {rc}
                        </div>
                      ))}
                    </div>
                    <div style={{ fontSize: '10px', color: '#eab308', marginTop: '6px' }}>
                      Each code is single-use. If you ever lose your phone, a recovery code will restore access.
                    </div>
                  </div>

                  {/* Step 4: Live Verification */}
                  <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: '14px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#10b981', marginBottom: '6px' }}>
                      Step 3: Enter the 6-digit code from Google Authenticator
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
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
                          fontWeight: 600,
                        }}
                      />
                      <button
                        type="button"
                        className="btn primary"
                        disabled={busy || confirmCode.length < 6}
                        onClick={handleConfirmMfa}
                        style={{ minWidth: '120px' }}
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
  );
}
