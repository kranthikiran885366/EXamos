import { useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { clean } from '../security/sanitize';

// Step-up auth, justification and one optional input for consequential actions.
export default function ReauthModal({ title, text, confirmLabel = 'Confirm', onConfirm, onClose, needPassword = true, needReason = true, field }) {
  const { reauth } = useAuth();
  const [pw, setPw] = useState(''); const [why, setWhy] = useState(''); const [val, setVal] = useState(field?.options?.[0]?.v ?? field?.options?.[0] ?? '');
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return;
    const reason = clean(why, 200);
    if (needReason && reason.length < 8) return setErr('Enter a reason of at least 8 characters.');
    if (field && !String(val).trim()) return setErr(`${field.label} is required.`);
    setBusy(true);
    if (needPassword) { const r = await reauth(pw); if (r.error) { setErr(r.error); setBusy(false); setPw(''); return; } }
    await onConfirm(reason, val); setBusy(false);
  };
  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-label={title}>
      <form className="modal" onSubmit={submit}>
        <h3>{title}</h3>{text && <p className="muted">{text}</p>}
        {field && <label>{field.label}{field.options
          ? <select value={val} onChange={(e) => setVal(e.target.value)}>{field.options.map((o) => <option key={o.v ?? o} value={o.v ?? o}>{o.l ?? o}</option>)}</select>
          : <input type={field.type || 'text'} value={val} onChange={(e) => setVal(e.target.value)} maxLength={200} autoComplete="off" />}</label>}
        {needReason && <label>Reason<input value={why} onChange={(e) => setWhy(e.target.value)} maxLength={200} autoFocus /></label>}
        {needPassword && <label>Confirm your password<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" maxLength={128} /></label>}
        {err && <div className="err" role="alert">{err}</div>}
        <div className="row end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Working…' : confirmLabel}</button></div>
      </form>
    </div>
  );
}
