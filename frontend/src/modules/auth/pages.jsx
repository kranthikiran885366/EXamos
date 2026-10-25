import { useState, useEffect } from 'react';
import { useNavigate, Link, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { Page, Card, Alert, Field, Input, CopyField } from '../../core/ui/kit';
import { acceptInvitation } from '../users/service';
import QrCodeSvg from '../../core/ui/QrCodeSvg';

export function MfaPage() {
  const { verifyMfa } = useAuth();
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (e) => {
    e.preventDefault(); if (busy) return; setErr(''); setBusy(true);
    try {
      const r = await verifyMfa(code);
      if (r?.error) { setErr(r.error); setBusy(false); return; }
      navigate('/');
    } catch (x) { setErr(x.message || String(x)); setBusy(false); }
  };
  return <Page title="Two-step verification" desc="Enter the 6-digit code from your authenticator app, or a recovery code.">
    <Card title="Verify" pad>
      <form onSubmit={run} className="stack">
        <Field label="Authentication code">
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={12} value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9a-zA-Z-]/g, '').slice(0, 12))} autoFocus placeholder="123456" />
        </Field>
        {err && <Alert tone="danger">{err}</Alert>}
        <button className="btn primary" disabled={busy || code.length < 6}>{busy ? 'Verifying…' : 'Verify and sign in'}</button>
      </form>
    </Card>
    <p className="muted sm">Lost your authenticator? Use a recovery code, or ask support to start an account recovery.</p>
  </Page>;
}

export function RecoveryPage() {
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
      // Auto-redirect to login after 3s
      setTimeout(() => navigate('/login'), 3000);
    } catch (x) {
      setErr(x.message || String(x));
      setBusy(false);
    }
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
            Use one of the emergency recovery codes generated when Google Authenticator was configured for your account.
          </p>
        </div>

        <form onSubmit={run}>
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              maxLength={64}
              placeholder="e.g. root, ananya"
            />
          </label>

          <label>
            Recovery Code (Single-Use)
            <input
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase().replace(/[^0-9A-Z-]/g, '').slice(0, 20))}
              autoComplete="one-time-code"
              maxLength={20}
              placeholder="ABCD-1234"
              style={{ fontFamily: 'monospace', letterSpacing: '1px' }}
            />
          </label>

          <label>
            New Password
            <span className="pw">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                maxLength={128}
                placeholder="12+ chars with upper, lower, digit & symbol"
              />
              <button type="button" className="mini" onClick={() => setShowPw(!showPw)}>
                {showPw ? 'Hide' : 'Show'}
              </button>
            </span>
          </label>

          <label>
            Confirm New Password
            <input
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
            <div className="alert success sm" style={{ marginTop: '12px', marginBottom: '12px' }}>
              ✅ {ok}{' '}
              <Link to="/login" style={{ color: '#10b981', fontWeight: 700 }}>Sign in now</Link>
            </div>
          )}

          <button
            className="btn primary wide"
            disabled={busy || !username.trim() || !code.trim() || password.length < 12}
            style={{ height: '44px', fontSize: '14px', fontWeight: 600, marginTop: '16px' }}
          >
            {busy ? 'Verifying & Resetting…' : 'Reset Password & Re-enable Access'}
          </button>

          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Link to="/login" style={{ fontSize: '12px', color: '#38bdf8', textDecoration: 'none' }}>
              ← Return to Sign In
            </Link>
            <span style={{ fontSize: '11px', color: '#94a3b8' }}>
              Audit logged on PostgreSQL
            </span>
          </div>

          <details className="dev" style={{ marginTop: '1.25rem', padding: '10px 12px', borderRadius: '6px', backgroundColor: 'rgba(255,255,255,0.03)' }}>
            <summary style={{ cursor: 'pointer', fontSize: '11px', color: '#94a3b8' }}>
              💡 About Emergency Recovery
            </summary>
            <div style={{ padding: '6px 0', fontSize: '11px', lineHeight: 1.6, color: '#94a3b8' }}>
              Recovery codes are single-use 8-character tokens hashed with SHA-256. Upon successful verification, the used code is permanently invalidated and a security audit entry is written to the cryptographic chain.
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
  return <Page title="Access denied" desc="Your role does not include this module. The attempt was recorded in the audit trail.">
    <Card title="Denied" pad>
      <p className="muted">Contact your institution administrator if you believe you should have access.</p>
      <Link to="/" className="btn">Return home</Link>
    </Card>
  </Page>;
}

export function ExpiredPage() {
  return <Page title="Session expired" desc="Your session has expired. Please sign in again.">
    <Card title="Expired" pad>
      <p className="muted">Your session has expired due to inactivity or the maximum session duration.</p>
      <Link to="/login" className="btn primary">Sign in again</Link>
    </Card>
  </Page>;
}
