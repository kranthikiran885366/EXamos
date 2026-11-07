import { useMemo, useState } from 'react';
import Badge from './Badge';
import ReauthModal from './ReauthModal';
import { useAuth } from '../auth/AuthContext';
import { can } from '../security/rbac';
import { clean } from '../security/sanitize';

export function useRun() {
  const [msg, setMsg] = useState(null);
  const run = async (fn) => { try { const r = await fn(); setMsg({ ok: true, text: typeof r === 'string' ? r : 'Done.' }); return true; } catch (e) { setMsg({ ok: false, text: e.message || String(e) }); return false; } };
  return [msg, run, setMsg];
}
export const Flash = ({ msg, onClose }) => msg && <div className={msg.ok ? 'okmsg' : 'err'} role="status">{msg.text} <button className="x" onClick={onClose} aria-label="Dismiss">×</button></div>;

export function Form({ title, fields, onSubmit, onClose, submitLabel = 'Save' }) {
  const [v, setV] = useState(() => Object.fromEntries(fields.map((f) => [f.name, f.default ?? (f.type === 'checkbox' ? false : f.type === 'multiselect' ? [] : '')])));
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const go = async (e) => { e.preventDefault(); if (busy) return; setBusy(true); setErr(''); try { await onSubmit(v); } catch (x) { setErr(x.message); setBusy(false); } };
  const opt = (o) => (typeof o === 'string' ? { v: o, l: o } : o);
  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-label={title}>
      <form className="modal crud-form" onSubmit={go}>
        <div className="crud-form-head"><h3>{title}</h3></div>
        <div className="crud-form-fields">
          {fields.map((f) => (
            <label key={f.name} className={`crud-form-field${f.type === 'checkbox' ? ' chk' : ''}`}>
              {f.type === 'checkbox' ? <><input type="checkbox" checked={v[f.name]} onChange={(e) => set(f.name, e.target.checked)} /> {f.label}</> : f.label}
              {f.type === 'select' && <select value={v[f.name]} onChange={(e) => set(f.name, e.target.value)}><option value="">Select…</option>{f.options.map((o) => <option key={opt(o).v} value={opt(o).v}>{opt(o).l}</option>)}</select>}
              {f.type === 'multiselect' && <select multiple size={Math.min(6, f.options.length || 2)} value={v[f.name]} onChange={(e) => set(f.name, [...e.target.selectedOptions].map((o) => o.value))}>{f.options.map((o) => <option key={opt(o).v} value={opt(o).v}>{opt(o).l}</option>)}</select>}
              {f.type === 'textarea' && <textarea rows={f.rows || 4} value={v[f.name]} onChange={(e) => set(f.name, e.target.value)} placeholder={f.placeholder} />}
              {!['select', 'multiselect', 'textarea', 'checkbox'].includes(f.type) && <input type={f.type || 'text'} value={v[f.name]} onChange={(e) => set(f.name, e.target.value)} placeholder={f.placeholder} min={f.min} max={f.max} maxLength={f.type === 'password' ? 128 : 500} autoComplete="off" />}
              {f.help && <small className="muted">{f.help}</small>}
            </label>
          ))}
          {err && <div className="err crud-form-error" role="alert">{err}</div>}
        </div>
        <div className="crud-form-actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : submitLabel}</button>
        </div>
      </form>
    </div>
  );
}

// Generic data table with search, create form and permission-gated row actions.
export default function Crud({ title, desc, rows, columns, search, create, actions = [], toolbar, top, head, pageSize = 40 }) {
  const { user } = useAuth();
  const [q, setQ] = useState(''); const [limit, setLimit] = useState(pageSize);
  const [form, setForm] = useState(false); const [pend, setPend] = useState(null); const [msg, run, setMsg] = useRun();
  const shown = useMemo(() => (q ? rows.filter((r) => (search ? search(r) : JSON.stringify(r)).toLowerCase().includes(q.toLowerCase())) : rows), [rows, q, search]);
  const acts = (r) => (typeof actions === 'function' ? actions(r) : actions).filter((a) => !a.show || a.show(r));
  const click = (a, r) => (a.field || a.reason || a.stepUp ? setPend({ a, r }) : run(() => a.run(r)));
  return (
    <div className="pad">
      <div className="head"><div><h1>{title}</h1><p className="muted">{desc}</p></div><div className="row">{head}{create && <button className="btn primary" disabled={!can(user.role, create.perm)} title={can(user.role, create.perm) ? '' : 'Your role cannot do this'} onClick={() => setForm(true)}>{create.label}</button>}</div></div>
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {top}
      <div className="card">
        <div className="toolbar"><input placeholder={`Filter ${title.toLowerCase()}…`} value={q} onChange={(e) => setQ(clean(e.target.value, 60))} maxLength={60} aria-label="Filter" />{toolbar}<span className="grow" /><span className="muted">{shown.length} of {rows.length}</span></div>
        <div className="scroll"><table><thead><tr>{columns.map((c) => <th key={c.label}>{c.label}</th>)}{!!actions.length && <th />}</tr></thead>
          <tbody>{shown.slice(0, limit).map((r) => (
            <tr key={r.id}>{columns.map((c) => <td key={c.label}>{c.render ? c.render(r) : c.badge ? <Badge>{r[c.key]}</Badge> : String(r[c.key] ?? '—')}</td>)}
              {!!actions.length && <td className="acts">{acts(r).map((a) => <button key={a.label} className={'mini' + (a.danger ? ' danger' : '')} disabled={a.perm && !can(user.role, a.perm)} title={a.perm && !can(user.role, a.perm) ? 'Your role cannot do this' : ''} onClick={() => click(a, r)}>{a.label}</button>)}</td>}</tr>))}
            {!shown.length && <tr><td colSpan={columns.length + 1} className="muted">{rows.length ? 'No matches. Clear the filter to see everything.' : 'Nothing here yet.'}</td></tr>}</tbody></table></div>
        {shown.length > limit && <div className="more"><button className="btn" onClick={() => setLimit(limit + pageSize)}>Show more</button></div>}
      </div>
      {form && <Form title={create.label} fields={create.fields} submitLabel={create.submitLabel || 'Create'} onClose={() => setForm(false)} onSubmit={async (v) => { setMsg({ ok: true, text: await create.submit(v) }); setForm(false); }} />}
      {pend && <ReauthModal title={pend.a.label} text={pend.a.text} confirmLabel={pend.a.label} needPassword={!!pend.a.stepUp} needReason={!!pend.a.reason} field={pend.a.field}
        onClose={() => setPend(null)} onConfirm={async (reason, val) => { const { a, r } = pend; setPend(null); await run(() => a.run(r, reason, val)); }} />}
    </div>
  );
}
export const Tabs = ({ tabs, value, onChange }) => <div className="tabs" role="tablist">{tabs.map((t) => <button key={t} role="tab" aria-selected={value === t} className={value === t ? 'on' : ''} onClick={() => onChange(t)}>{t}</button>)}</div>;
