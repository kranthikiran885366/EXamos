import { useState } from 'react';
import { useAuth } from '../auth/AuthContext';
export default function LockScreen() {
  const { user, unlock, logout } = useAuth();
  const [pw, setPw] = useState(''); const [err, setErr] = useState('');
  const go = async (e) => { e.preventDefault(); const r = await unlock(pw); if (r.error) { setErr(r.error); setPw(''); } };
  return (
    <div className="lockwrap"><form className="card lock" onSubmit={go}>
      <h2>Session locked</h2><p className="muted">{user.name}, you were inactive. Enter your password to continue.</p>
      <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus autoComplete="current-password" maxLength={128} />
      {err && <div className="err" role="alert">{err}</div>}
      <div className="row"><button className="btn primary">Unlock</button><button type="button" className="btn" onClick={() => logout('LOGOUT_FROM_LOCK')}>Sign out</button></div>
    </form></div>
  );
}
