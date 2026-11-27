import { useState, useEffect } from 'react';
import { useNavigate, Link, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { Page, Card, Alert, Field, Input, CopyField } from '../../core/ui/kit';
import { acceptInvitation } from '../users/service';
import QrCodeSvg from '../../core/ui/QrCodeSvg';
import SppioLogo from '../../core/ui/SppioLogo';
import usePageMeta from '../../core/ui/usePageMeta';

export function MfaPage() {
  usePageMeta({
    title: 'Two-factor authentication | SPPIO',
    description: 'Verify your SPPIO management console session.',
    path: '/mfa',
  });
  const { verifyMfa, pending, cancelPending, backendReady } = useAuth();
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  const [isRecoveryCode, setIsRecoveryCode] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // If no pending login, redirect to login
    if (!pending) {
      navigate('/login', { replace: true });
    }
  }, [pending, navigate]);

  const run = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (busy) return;
    setErr('');
    setBusy(true);
    try {
      const r = await verifyMfa(code.trim());
      if (r?.error) {
        setErr(r.error);
        setBusy(false);
        return;
      }
      navigate('/', { replace: true });
    } catch (x) {
      setErr(x.message || String(x));
      setBusy(false);
    }
  };

  return (
    <div className="loginwrap">
      <div className="login" style={{ maxWidth: '440px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <Link to="/" aria-label="SPPIO home" style={{ display: 'inline-flex', alignItems: 'center' }}>
            <SppioLogo width={132} accent="#B54F34" ink="#302337" />
          </Link>
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
            {backendReady ? 'Server Online' : 'Offline'}
          </div>
        </div>

        <div className="login-tag" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <span>Two-Factor Authentication</span>
          <span style={{ fontSize: '10px', fontFamily: 'monospace', opacity: 0.75 }}>
            {isRecoveryCode ? 'Emergency Recovery' : 'RFC 6238 TOTP'}
          </span>
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.25rem', margin: '0 0 6px 0' }}>Security Verification</h2>
          <p className="muted" style={{ fontSize: '12px', margin: 0, lineHeight: 1.5 }}>
            {isRecoveryCode
              ? 'Enter one of your 8-character single-use emergency recovery codes.'
              : `Enter the 6-digit code for ${pending || 'your account'} from Google Authenticator.`}
          </p>
        </div>

        <form onSubmit={run} className="stack">
          <label>
            {isRecoveryCode ? 'Emergency Recovery Code' : 'Authentication Code'}
            <input
              className="input"
              type="text"
              inputMode={isRecoveryCode ? 'text' : 'numeric'}
              autoComplete="one-time-code"
              maxLength={isRecoveryCode ? 16 : 6}
              value={code}
              onChange={(e) => {
                const val = isRecoveryCode
                  ? e.target.value.toUpperCase().replace(/[^0-9A-Z-]/g, '').slice(0, 16)
                  : e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
                setCode(val);
              }}
              autoFocus
              placeholder={isRecoveryCode ? 'ABCD-1234' : '123456'}
              style={{ fontFamily: 'monospace', letterSpacing: '2px', textAlign: 'center', fontSize: '18px' }}
            />
          </label>

          {err && <div className="err" role="alert" style={{ marginTop: '12px', marginBottom: '12px' }}>{err}</div>}

          <button
            className="btn primary wide"
            disabled={busy || code.length < (isRecoveryCode ? 8 : 6)}
            style={{ height: '44px', fontSize: '14px', fontWeight: 600, marginTop: '12px' }}
          >
            {busy ? 'Verifying Code…' : 'Verify & Continue'}
          </button>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '16px', alignItems: 'center' }}>
            <button
              type="button"
              className="text-action-link"
              onClick={() => {
                setIsRecoveryCode(!isRecoveryCode);
                setCode('');
                setErr('');
              }}
              style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', fontSize: '12px' }}
            >
              {isRecoveryCode ? 'Use 6-digit Authenticator Code' : 'Use emergency recovery code'}
            </button>
            <button
              type="button"
              onClick={() => {
                if (cancelPending) cancelPending();
                navigate('/login');
              }}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '12px' }}
            >
              ← Sign in as different user
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function RecoveryPage() {
  usePageMeta({
    title: 'Account recovery | SPPIO',
    description: 'Reset your SPPIO console password using a single-use recovery code.',
    path: '/recovery',
  });
  const { resetWithRecovery, backendReady } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async (e) => {
    e.preventDefault();
    if (busy) return;
    setErr('');
    setOk('');
    if (password !== confirm) return setErr('Passwords do not match.');
    if (password.length < 12) return setErr('Password must be at least 12 characters.');
    setBusy(true);
    try {
      const r = await resetWithRecovery(username.trim(), code.trim(), password);
      if (r?.error) {
        setErr(r.error);
        setBusy(false);
        return;
      }
      setOk('Password reset successfully. You can now sign in with your new password.');
      setBusy(false);
    } catch (x) {
      setErr(x.message || String(x));
      setBusy(false);
    }
  };

  return (
    <div className="loginwrap">
      <div className="login" style={{ maxWidth: '480px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <Link to="/" aria-label="SPPIO home" style={{ display: 'inline-flex', alignItems: 'center' }}>
            <SppioLogo width={132} accent="#B54F34" ink="#302337" />
          </Link>
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
            {backendReady ? 'Server Online' : 'Offline'}
          </div>
        </div>

        <div className="login-tag" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <span>Emergency Account Recovery</span>
          <span style={{ fontSize: '10px', fontFamily: 'monospace', opacity: 0.75 }}>Single-Use Codes</span>
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.25rem', margin: '0 0 6px 0' }}>Reset Password with Recovery Code</h2>
          <p className="muted" style={{ fontSize: '12px', margin: 0, lineHeight: 1.5 }}>
            Use an unused recovery code generated during authenticator setup. Each code works once. If a code was already used or is no longer accepted, try another unused code; if none remain, contact your administrator.
          </p>
        </div>

        <form onSubmit={run} className="stack">
          <label>
            Username
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              maxLength={64}
              placeholder="Enter username"
            />
          </label>

          <label>
            Recovery Code (Single-Use)
            <input
              className="input"
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase().replace(/[^0-9A-Z-]/g, '').slice(0, 20))}
              autoComplete="one-time-code"
              maxLength={20}
              placeholder="ABCD-1234"
              style={{ fontFamily: 'monospace', letterSpacing: '1px' }}
            />
          </label>

          <div>
            <label style={{ marginBottom: 0 }}>
              New Password
              <span className="pw">
                <input
                  className="input"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  maxLength={128}
                  placeholder="At least 12 characters"
                />
                <button type="button" className="mini" onClick={() => setShowPw(!showPw)}>
                  {showPw ? 'Hide' : 'Show'}
                </button>
              </span>
            </label>
            <p className="muted" style={{ fontSize: '11px', margin: '6px 0 0', lineHeight: 1.5 }}>
              Use at least 12 characters. Choose a password you have not used for this account before.
            </p>
          </div>

          <label>
            Confirm New Password
            <input
              className="input"
              type={showPw ? 'text' : 'password'}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              maxLength={128}
              placeholder="Re-enter new password"
            />
          </label>

          {err && <div className="err" role="alert" style={{ marginTop: '12px', marginBottom: '12px' }}>{err}</div>}
          {ok && (
            <div className="alert success sm" role="status" style={{ marginTop: '12px', marginBottom: '12px' }}>
              ✅ {ok}{' '}
              <Link to="/login" style={{ color: '#10b981', fontWeight: 700 }}>Continue to sign in</Link>
            </div>
          )}

          <button
            className="btn primary wide"
            disabled={busy || Boolean(ok) || !username.trim() || !code.trim() || password.length < 12}
            style={{ height: '44px', fontSize: '14px', fontWeight: 600, marginTop: '16px' }}
          >
            {busy ? 'Verifying & Resetting…' : 'Reset Password & Re-enable Access'}
          </button>

          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Link to="/login" style={{ fontSize: '12px', color: '#38bdf8', textDecoration: 'none' }}>
              ← Return to Sign In
            </Link>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>
              Tamper-evident audit logging active
            </span>
          </div>

          <details className="dev" style={{ marginTop: '1.25rem', padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(255,255,255,0.03)' }}>
            <summary style={{ cursor: 'pointer', fontSize: '11px', color: '#94a3b8' }}>
              💡 About Emergency Recovery
            </summary>
            <div style={{ padding: '6px 0', fontSize: '11px', lineHeight: 1.6, color: '#94a3b8' }}>
              Recovery codes are single-use. The server verifies the code and resets the account password; this page does not reveal whether a username exists.
            </div>
          </details>
        </form>
      </div>
    </div>
  );
}

export function ResetPasswordPage() {
  return <RecoveryPage />;
}

export function InvitePage() {
  const { token: routeToken } = useParams();
  const [token, setToken] = useState(routeToken && routeToken !== 'new' ? routeToken : '');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = async (e) => {
    e.preventDefault(); if (busy) return; setErr(''); setOk('');
    if (password !== confirm) return setErr('Passwords do not match.');
    setBusy(true);
    try {
      const r = await acceptInvitation(token, { username, password });
      setResult(r);
      setOk('Account created. Save your authenticator secret and recovery codes, then sign in.');
      setBusy(false);
    } catch (x) { setErr(x.message || String(x)); setBusy(false); }
  };
  return <Page title="Accept invitation" desc="Create your account from a valid invitation token.">
    <Card title="Invitation" pad>
      <form onSubmit={run} className="stack">
        <Field label="Invitation token"><Input value={token} onChange={(e) => setToken(e.target.value)} autoFocus maxLength={80} /></Field>
        <Field label="Username"><Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" maxLength={40} /></Field>
        <Field label="Password" help="12+ characters with upper, lower, number and symbol."><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" maxLength={128} /></Field>
        <Field label="Confirm password"><Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" maxLength={128} /></Field>
        {err && <Alert tone="danger">{err}</Alert>}
        {ok && <Alert tone="success">{ok}</Alert>}
        {!result && <button className="btn primary" disabled={busy || !token || !username || password.length < 12}>{busy ? 'Creating…' : 'Create account'}</button>}
        {result && <Link to="/login" className="btn primary">Continue to sign in</Link>}
      </form>
    </Card>
    {result && <Card title="Authenticator and recovery codes" desc="Store these somewhere safe. They will not be shown again." pad>
      <div className="stack">
        <div style={{ textAlign: 'center', margin: '10px 0' }}>
          <QrCodeSvg
            value={result.otpauth_url || `otpauth://totp/ExamOS:${encodeURIComponent(username)}?secret=${result.totp}&issuer=ExamOS&algorithm=SHA1&digits=6&period=30`}
            size={180}
          />
          <div className="muted sm" style={{ marginTop: '6px' }}>Scan with Google Authenticator or Microsoft Authenticator</div>
        </div>
        <CopyField label="Authenticator secret (TOTP)" value={result.totp} />
        <div className="codegrid">{(result.recovery || []).map((c) => <code key={c}>{c}</code>)}</div>
        <Alert tone="warn">Each recovery code works once. Use one if you lose access to your authenticator app.</Alert>
      </div>
    </Card>}
  </Page>;
}

export function UnauthorizedPage() {
  return (
    <div className="loginwrap" style={{ minHeight: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="login" style={{ maxWidth: '480px', textAlign: 'center', padding: '32px 24px' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>🛡️</div>
        <h2 style={{ fontSize: '1.4rem', color: '#ef4444', margin: '0 0 10px 0' }}>Access Denied</h2>
        <p className="muted" style={{ fontSize: '13px', lineHeight: 1.6, marginBottom: '24px' }}>
          Your current account role does not possess the cryptographic permissions required to access this enclaved resource. This security boundary event has been signed and written to the immutable ledger.
        </p>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
          <Link to="/" className="btn primary" style={{ minWidth: '140px' }}>Return to Home</Link>
          <Link to="/login" className="btn" style={{ minWidth: '140px' }}>Sign in with different Role</Link>
        </div>
      </div>
    </div>
  );
}

export function ExpiredPage() {
  return (
    <div className="loginwrap" style={{ minHeight: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="login" style={{ maxWidth: '480px', textAlign: 'center', padding: '32px 24px' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏱️</div>
        <h2 style={{ fontSize: '1.4rem', color: '#f59e0b', margin: '0 0 10px 0' }}>Session Expired</h2>
        <p className="muted" style={{ fontSize: '13px', lineHeight: 1.6, marginBottom: '24px' }}>
          Your authenticated session has expired to preserve hardware boundary integrity. Please sign in again with your credentials and 2FA token.
        </p>
        <Link to="/login" className="btn primary wide" style={{ display: 'inline-block', lineHeight: '40px' }}>
          Sign In Again
        </Link>
      </div>
    </div>
  );
}
