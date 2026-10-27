import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { clean } from '../security/sanitize';

/* ------------------------------------------------------------------ icons */
const P = {
  grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  building: 'M4 21V5l8-3 8 3v16M9 9h1M14 9h1M9 13h1M14 13h1M9 17h1M14 17h1M2 21h20',
  users: 'M16 20v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1M9.5 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM17 4.2a3.5 3.5 0 0 1 0 6.6M21 20v-1a4 4 0 0 0-3-3.8',
  key: 'M14 7a4 4 0 1 1-3.2 6.4L4 20H2v-3l6.6-6.8A4 4 0 0 1 14 7zM16 6h.01',
  check: 'M20 6 9 17l-5-5',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  pulse: 'M2 12h4l2-7 4 14 2-7h8',
  shield: 'M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z',
  package: 'M21 8 12 3 3 8v8l9 5 9-5V8zM3 8l9 5 9-5M12 13v8',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  checklist: 'M9 5h11M9 12h11M9 19h11M4 5l1 1 2-2M4 12l1 1 2-2M4 19l1 1 2-2',
  home: 'M3 11 12 3l9 8M5 10v10h14V10',
  pin: 'M12 22s7-6.2 7-12A7 7 0 0 0 5 10c0 5.8 7 12 7 12zM12 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  layers: 'M12 2 2 7l10 5 10-5-10-5zM2 12l10 5 10-5M2 17l10 5 10-5',
  badge: 'M12 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8.2 13.8 6 22l6-2 6 2-2.2-8.2',
  exam: 'M6 2h9l5 5v15H6zM14 2v6h6M9 13h6M9 17h6',
  candidate: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 22a8 8 0 0 1 16 0',
  history: 'M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 7v5l3 2',
  alert: 'M12 3 2 21h20L12 3zM12 9v5M12 18h.01',
  device: 'M4 4h13v12H4zM8 20h5M9 23h8M20 9h2v12h-2z',
  plus: 'M12 5v14M5 12h14',
  usb: 'M12 21V7M9 4l3-2 3 2v3H9zM6 12l3-2 3 2v3H6zM15 15l3-2 3 2v3h-6z',
  boot: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  cpu: 'M6 6h12v12H6zM10 10h4v4h-4zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4',
  policy: 'M6 2h9l5 5v13H6zM14 2v6h6M9 13h6M9 17h4',
  radar: 'M12 12 4 4M12 3a9 9 0 1 0 9 9M12 8a4 4 0 1 0 4 4',
  bug: 'M8 6h8v10a4 4 0 0 1-8 0zM9 6a3 3 0 0 1 6 0M4 10h3M17 10h3M4 16h3M17 16h3M8 4 6 2M16 4l2-2M8 20l-2 2M16 20l2 2',
  server: 'M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01',
  bell: 'M18 8a6 6 0 1 0-12 0c0 7-3 8-3 8h18s-3-1-3-8M10 21h4',
  chart: 'M3 3v18h18M7 15l3-4 3 3 4-6',
  life: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.9 4.9l4.2 4.2M14.9 14.9l4.2 4.2M19.1 4.9l-4.2 4.2M9.1 14.9l-4.2 4.2',
  ticket: 'M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4zM12 6v12',
  stethoscope: 'M6 3v6a5 5 0 0 0 10 0V3M4 3h4M14 3h4M11 14v4a4 4 0 0 0 8 0v-2M19 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  status: 'M4 12h3l2-5 4 10 2-5h5',
  recover: 'M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 8v5l3 2',
  mail: 'M3 5h18v14H3zM3 6l9 7 9-7',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 22a8 8 0 0 1 16 0',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  close: 'M18 6 6 18M6 6l12 12',
  menu: 'M3 6h18M3 12h18M3 18h18',
  arrow: 'M9 18l6-6-6-6',
  external: 'M14 3h7v7M10 14 21 3M21 14v7H3V3h7',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
  refresh: 'M21 12a9 9 0 1 1-3-6.7M21 4v5h-5',
  download: 'M12 3v12M7 10l5 5 5-5M4 21h16',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  warn: 'M12 3 2 21h20L12 3zM12 9v5M12 18h.01',
  filter: 'M3 5h18l-7 8v6l-4 2v-8z',
  chevron: 'M6 9l6 6 6-6',
};
export function Icon({ name = 'grid', size = 18, className = '' }) {
  return <svg className={'ico ' + className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={P[name] || P.grid} /></svg>;
}

/* ------------------------------------------------------------------ primitives */
export const tone = (v) => {
  const s = String(v ?? '').toLowerCase().replace(/[_-]/g, ' ');
  if (['pass', 'passed', 'attested', 'active', 'verified', 'compliant', 'published', 'live', 'signed', 'healthy', 'ready', 'enforced', 'closed', 'complete', 'completed', 'resolved', 'stable', 'allow', 'approved', 'accepted', 'delivered', 'paid', 'valid', 'ok', 'success', 'sent', 'strong', 'on', 'enabled', 'low', 'secure', 'intact', 'current', 'acknowledged', 'returned'].includes(s)) return 'g';
  if (['review', 'pending', 'draft', 'investigating', 'canary', 'warning', 'stale', 'scheduled', 'partial', 'blocked', 'medium', 'not run', 'not_run', 'unknown', 'queued', 'assigned', 'waiting', 'pilot', 'trial', 'issued', 'prepared', 'quarantined', 'expiring', 'degraded', 'in progress', 'in_progress', 'open', 'new', 'needs review'].includes(s)) return 'a';
  if (['fail', 'failed', 'unreachable', 'isolated', 'critical', 'revoked', 'suspended', 'offline', 'deny', 'high', 'rejected', 'expired', 'lost', 'damaged', 'retired', 'terminated', 'error', 'invalid', 'tampered', 'overdue', 'retired', 'deactivated', 'locked', 'failed payment'].includes(s)) return 'r';
  return 'n';
};
export function Badge({ children, value, className = '', dot = true }) {
  const v = value ?? children;
  return <span className={'badge ' + tone(v) + ' ' + className}>{dot && <i />}{v}</span>;
}
export const Pill = ({ children, className = '' }) => <span className={'pill ' + className}>{children}</span>;
export const Dot = ({ v }) => <span className={'dot ' + tone(v)} />;

export function Page({ title, desc, actions, children, breadcrumb, wide = false, className = '' }) {
  return <div className={'page ' + (wide ? 'wide ' : '') + className}>
    {(title || actions) && <div className="pagehead">
      <div className="pagehead-main">
        {breadcrumb}
        {title && <h1>{title}</h1>}
        {desc && <p className="muted">{desc}</p>}
      </div>
      {actions && <div className="pagehead-actions">{actions}</div>}
    </div>}
    {children}
  </div>;
}
export const PageHeader = Page;

export function Card({ title, desc, actions, children, className = '', pad = true, id }) {
  return <section className={'card ' + className} id={id}>
    {(title || actions) && <div className="ctitle"><div className="ctitle-main"><b>{title}</b>{desc && <small className="muted">{desc}</small>}</div>{actions && <div className="ctitle-actions">{actions}</div>}</div>}
    {padding(children, pad)}
  </section>;
}
const padding = (children, pad) => (pad ? <div className="cardpad">{children}</div> : children);

export function Stat({ label, value, unit, sub, icon, tone: t = 'blue', to, onClick, spark }) {
  const body = <>
    <div className="stat-top"><small>{label}</small>{icon && <span className={'stat-ico ' + t}><Icon name={icon} size={15} /></span>}</div>
    <div className="stat-value">{value}{unit && <em>{unit}</em>}</div>
    {sub && <div className="stat-sub">{sub}</div>}
    {spark}
  </>;
  if (to) return <Link to={to} className={'card stat ' + t}>{body}</Link>;
  if (onClick) return <button className={'card stat ' + t + ' asbtn'} onClick={onClick}>{body}</button>;
  return <div className={'card stat ' + t}>{body}</div>;
}
export const StatGrid = ({ children, cols = 4 }) => <div className="statgrid" style={{ '--cols': cols }}>{children}</div>;

export function Alert({ tone: t = 'info', title, children, action, icon = true }) {
  return <div className={'alert ' + t} role={t === 'danger' ? 'alert' : 'status'}>
    {icon && <span className="alert-ico"><Icon name={t === 'danger' ? 'warn' : t === 'warn' ? 'warn' : t === 'success' ? 'check' : 'shield'} size={16} /></span>}
    <div className="alert-body">{title && <b>{title}</b>}{children && <div>{children}</div>}</div>
    {action && <div className="alert-action">{action}</div>}
  </div>;
}

export function Empty({ icon = 'grid', title = 'Nothing here yet', children, action }) {
  return <div className="empty"><span className="empty-ico"><Icon name={icon} size={22} /></span><b>{title}</b>{children && <p className="muted">{children}</p>}{action && <div>{action}</div>}</div>;
}
export const Loading = ({ label = 'Loading…' }) => <div className="loading" role="status"><span className="spinner" /> {label}</div>;
export const Skeleton = ({ rows = 4 }) => <div className="skeleton" aria-hidden="true">{[...Array(rows)].map((_, i) => <i key={i} />)}</div>;

export function Tabs({ tabs, value, onChange, right }) {
  const items = tabs.map((t) => (typeof t === 'string' ? { key: t, label: t } : t));
  return <div className="tabsbar"><div className="tabs" role="tablist">
    {items.map((t) => <button key={t.key} role="tab" aria-selected={value === t.key} className={value === t.key ? 'on' : ''} onClick={() => onChange(t.key)} disabled={t.disabled}>
      {t.label}{t.count !== undefined && <em>{t.count}</em>}
    </button>)}
  </div>{right && <div className="tabs-right">{right}</div>}</div>;
}

export function Steps({ steps, current = 0 }) {
  return <ol className="steps">{steps.map((s, i) => <li key={s} className={i < current ? 'done' : i === current ? 'now' : ''}><span>{i < current ? '✓' : i + 1}</span><b>{s}</b></li>)}</ol>;
}
export function Progress({ value = 0, max = 100, label, tone: t }) {
  const p = Math.max(0, Math.min(100, max ? (value / max) * 100 : 0));
  return <div className="progress-wrap">{label && <div className="progress-label"><span>{label}</span><b>{Math.round(p)}%</b></div>}<div className="progress"><i className={t || (p >= 90 ? 'g' : p >= 60 ? 'a' : 'r')} style={{ width: p + '%' }} /></div></div>;
}
export function KeyValue({ items, cols = 2 }) {
  return <dl className="kv-grid" style={{ '--cols': cols }}>{items.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v ?? '—'}</dd></div>)}</dl>;
}
export function Timeline({ items }) {
  return <ol className="timeline">{items.map((it, i) => <li key={it.id || i}><span className={'tl-dot ' + (it.tone || '')} /><div><b>{it.title}</b>{it.meta && <small className="muted">{it.meta}</small>}{it.body && <p>{it.body}</p>}</div></li>)}</ol>;
}

/* ------------------------------------------------------------------ forms */
export function Field({ label, help, error, required, children, className = '' }) {
  return <label className={'field ' + className}>{label && <span className="field-label">{label}{required && <em> *</em>}</span>}{children}{help && <small className="field-help">{help}</small>}{error && <small className="field-error">{error}</small>}</label>;
}
export const Input = ({ className = '', ...p }) => <input className={'input ' + className} {...p} />;
export const Select = ({ options = [], className = '', placeholder, ...p }) => <select className={'input ' + className} {...p}>{placeholder !== false && <option value="">{placeholder || 'Select…'}</option>}{options.map((o) => { const v = typeof o === 'string' ? o : o.v; const l = typeof o === 'string' ? o : o.l; return <option key={v} value={v}>{l}</option>; })}</select>;
export const Textarea = ({ className = '', ...p }) => <textarea className={'input ' + className} {...p} />;
export const Checkbox = ({ label, ...p }) => <label className="check"><input type="checkbox" {...p} /><span>{label}</span></label>;

export function CopyButton({ value, label = 'Copy', small = true }) {
  const [done, setDone] = useState(false);
  return <button type="button" className={small ? 'mini' : 'btn'} onClick={async () => { try { await navigator.clipboard.writeText(String(value)); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* clipboard may be blocked */ } }}>{done ? 'Copied' : label}</button>;
}

/* ------------------------------------------------------------------ dialogs */
export function Modal({ title, desc, children, footer, onClose, wide = false, className = '' }) {
  useEffect(() => {
    const k = (e) => { if (e.key === 'Escape') onClose?.(); };
    window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k);
  }, [onClose]);
  return <div className="scrim" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose?.(); }}>
    <div className={'modal ' + (wide ? 'wide ' : '') + className}>
      <div className="modal-head"><div><h3>{title}</h3>{desc && <p className="muted sm">{desc}</p>}</div><button className="iconbtn" onClick={onClose} aria-label="Close"><Icon name="close" size={16} /></button></div>
      <div className="modal-body">{children}</div>
      {footer && <div className="modal-foot">{footer}</div>}
    </div>
  </div>;
}

export function ActionDialog({ title, desc, confirmLabel = 'Confirm', danger = false, reasonLabel = 'Reason', requireReason = true, field, typed, password = false, onConfirm, onClose }) {
  const { reauth } = useAuth();
  const [why, setWhy] = useState(''); const [val, setVal] = useState(field?.default ?? field?.options?.[0]?.v ?? field?.options?.[0] ?? '');
  const [type, setType] = useState(''); const [pw, setPw] = useState(''); const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setErr('');
    const r = clean(why, 300);
    if (requireReason && r.length < 8) return setErr('Enter a reason of at least 8 characters.');
    if (field && !String(val).trim()) return setErr(`${field.label} is required.`);
    if (typed && type !== typed) return setErr(`Type “${typed}” exactly to confirm.`);
    setBusy(true);
    try {
      if (password) { const x = await reauth(pw); if (x.error) { setErr(x.error); setBusy(false); setPw(''); return; } }
      await onConfirm(r, val); onClose();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return <Modal title={title} desc={desc} onClose={onClose} footer={<><button type="button" className="btn" onClick={onClose}>Cancel</button><button type="submit" form="action-form" className={'btn ' + (danger ? 'danger-solid' : 'primary')} disabled={busy}>{busy ? 'Working…' : confirmLabel}</button></>}>
    <form id="action-form" onSubmit={submit}>
      {field && <Field label={field.label} help={field.help}>{field.options ? <Select value={val} onChange={(e) => setVal(e.target.value)} options={field.options} placeholder={field.placeholder} /> : field.type === 'textarea' ? <Textarea rows={3} value={val} maxLength={field.max || 500} onChange={(e) => setVal(e.target.value)} /> : <Input type={field.type || 'text'} value={val} maxLength={field.max || 200} onChange={(e) => setVal(e.target.value)} />}</Field>}
      {typed && <Field label={`Type “${typed}” to confirm`}><Input value={type} onChange={(e) => setType(e.target.value)} autoComplete="off" /></Field>}
      {requireReason && <Field label={reasonLabel} help="Recorded in the audit trail."><Input value={why} onChange={(e) => setWhy(e.target.value)} maxLength={300} autoFocus /></Field>}
      {password && <Field label="Confirm your password"><Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" maxLength={128} /></Field>}
      {err && <Alert tone="danger">{err}</Alert>}
    </form>
  </Modal>;
}

/* ------------------------------------------------------------------ flash */
export function useFlash() {
  const [msg, setMsg] = useState(null); const [busy, setBusy] = useState(false);
  const run = async (fn, okText = 'Done.') => {
    setBusy(true);
    try { const r = await fn(); setMsg({ ok: true, text: typeof r === 'string' ? r : (r?.message || okText) }); return r; }
    catch (e) { setMsg({ ok: false, text: e?.message || String(e) }); return null; }
    finally { setBusy(false); }
  };
  return { msg, setMsg, run, busy };
}
export function Flash({ msg, onClose, children }) {
  if (!msg && !children) return null;
  const ok = msg?.ok !== false;
  return <div className={(ok ? 'flash ok' : 'flash err')} role={ok ? 'status' : 'alert'}>
    <span>{ok ? '✓' : '!'}</span><div>{msg?.text ?? children}</div>
    {onClose && <button className="iconbtn" onClick={onClose} aria-label="Dismiss"><Icon name="close" size={14} /></button>}
  </div>;
}

/* ------------------------------------------------------------------ data table */
const asText = (r) => Object.values(r).map((v) => (v && typeof v === 'object' ? '' : String(v ?? ''))).join(' ');
export function DataTable({
  rows = [], columns = [], search, filters = [], pageSize: initialPage = 25,
  actions, empty, toolbar, title, desc, onRow, dense = false, rowKey,
  defaultSort, selectable = false, bulk, footer, className = '', sticky = false,
}) {
  const [q, setQ] = useState('');
  const [fv, setFv] = useState({});
  const [sort, setSort] = useState(defaultSort || null);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(initialPage);
  const [sel, setSel] = useState([]);

  const filtered = useMemo(() => {
    let out = Array.isArray(rows) ? rows : [];
    for (const f of filters) {
      const v = fv[f.key];
      if (v !== undefined && v !== '') out = out.filter((r) => String(f.get ? f.get(r) : r[f.key]) === String(v));
    }
    const s = q.trim().toLowerCase();
    if (s) {
      const match = search
        ? (typeof search === 'function' ? (r) => search(r).toLowerCase().includes(s) : (r) => search.some((k) => String(r[k] ?? '').toLowerCase().includes(s)))
        : (r) => asText(r).toLowerCase().includes(s);
      out = out.filter(match);
    }
    if (sort) out = [...out].sort((a, b) => {
      const col = columns.find((c) => c.key === sort.key); const av = col?.sortValue ? col.sortValue(a) : a[sort.key]; const bv = col?.sortValue ? col.sortValue(b) : b[sort.key];
      if (av === bv) return 0; return (av > bv ? 1 : -1) * (sort.dir === 'asc' ? 1 : -1);
    });
    return out;
  }, [rows, q, fv, sort, filters, search, columns]);

  const pages = Math.max(1, Math.ceil(filtered.length / size));
  const cur = Math.min(page, pages);
  const slice = filtered.slice((cur - 1) * size, cur * size);
  const act = (r) => (typeof actions === 'function' ? actions(r) : actions || []).filter((a) => !a.show || a.show(r));
  const hasActs = (typeof actions === 'function') || (actions && actions.length);
  const keyOf = (r, i) => (rowKey ? rowKey(r) : (r.id ?? r.key ?? r.code ?? r.username ?? r.name ?? i));
  const allSel = slice.length > 0 && slice.every((r) => sel.includes(keyOf(r)));
  const toggle = (k) => setSel((s) => (s.includes(k) ? s.filter((x) => x !== k) : [...s, k]));

  return <div className={'card tablecard ' + className}>
    {(title || toolbar || filters.length || search) && <div className="tablebar">
      <div className="tablebar-main">
        {title && <div className="tabletitle"><b>{title}</b>{desc && <small className="muted">{desc}</small>}</div>}
        {search && <label className="searchbox"><Icon name="search" size={14} /><input placeholder="Search…" value={q} onChange={(e) => { setQ(clean(e.target.value, 80)); setPage(1); }} maxLength={80} aria-label="Search" /></label>}
        {filters.map((f) => <Select key={f.key} aria-label={f.label} className="filter" value={fv[f.key] ?? ''} onChange={(e) => { setFv({ ...fv, [f.key]: e.target.value }); setPage(1); }} placeholder={f.label} options={f.options} />)}
        {(q || Object.values(fv).some(Boolean)) && <button className="mini" onClick={() => { setQ(''); setFv({}); setPage(1); }}>Clear</button>}
      </div>
      {toolbar && <div className="tablebar-actions">{toolbar}</div>}
    </div>}
    {selectable && sel.length > 0 && <div className="bulkbar"><b>{sel.length} selected</b><span className="grow" />{bulk?.map((b) => <button key={b.label} className={'btn ' + (b.danger ? 'danger' : '')} onClick={() => b.run(sel)}>{b.label}</button>)}<button className="mini" onClick={() => setSel([])}>Clear</button></div>}
    <div className={'scroll ' + (sticky ? 'sticky' : '')}>
      <table className={dense ? 'dense' : ''}>
        <thead><tr>
          {selectable && <th className="selcell"><input type="checkbox" checked={allSel} onChange={() => setSel(allSel ? [] : slice.map(keyOf))} aria-label="Select page" /></th>}
          {columns.map((c) => <th key={c.key || c.label} style={c.width ? { width: c.width } : undefined} className={c.sortable ? 'sortable' : ''} aria-sort={sort && sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}>
            {c.sortable ? <button onClick={() => setSort({ key: c.key, dir: sort?.key === c.key && sort?.dir === 'asc' ? 'desc' : 'asc' })}>{c.label}{sort && sort.key === c.key ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ''}</button> : c.label}
          </th>)}
          {hasActs && <th className="actscell"><span className="sr">Actions</span></th>}
        </tr></thead>
        <tbody>
          {slice.map((r, i) => <tr key={keyOf(r, i)} className={onRow ? 'clickable' : ''} onClick={onRow ? (e) => { if (e.target.closest('button,input,a,select,label')) return; onRow(r); } : undefined}>
            {selectable && <td className="selcell"><input type="checkbox" checked={sel.includes(keyOf(r, i))} onChange={() => toggle(keyOf(r, i))} aria-label="Select row" /></td>}
            {columns.map((c) => <td key={c.key || c.label} className={(c.align ? 'ta-' + c.align : '') + (c.mono ? ' mono' : '')}>{c.render ? c.render(r) : (c.badge ? <Badge value={r[c.key]} /> : (r[c.key] ?? '—'))}</td>)}
            {hasActs && <td className="actscell">{act(r).length > 0 && <RowActions actions={act(r)} row={r} />}</td>}
          </tr>)}
          {!slice.length && <tr><td colSpan={columns.length + (hasActs ? 1 : 0) + (selectable ? 1 : 0)}>{empty || <Empty title={rows.length ? 'No matches' : 'Nothing here yet'}>{rows.length ? 'Adjust the search or filters to see more.' : 'Records will appear here once they are created.'}</Empty>}</td></tr>}
        </tbody>
      </table>
    </div>
    <div className="tablefoot">
      <span className="muted">{filtered.length ? `${(cur - 1) * size + 1}–${Math.min(cur * size, filtered.length)} of ${filtered.length}` : '0 records'}</span>
      <span className="grow" />
      <Select className="page-size" aria-label="Rows per page" value={size} onChange={(e) => { setSize(Number(e.target.value)); setPage(1); }} placeholder={false} options={[10, 25, 50, 100].map((n) => ({ v: n, l: `${n} / page` }))} />
      <div className="pager"><button className="mini" disabled={cur <= 1} onClick={() => setPage(cur - 1)} aria-label="Previous page">‹</button><span>{cur} / {pages}</span><button className="mini" disabled={cur >= pages} onClick={() => setPage(cur + 1)} aria-label="Next page">›</button></div>
    </div>
    {footer}
  </div>;
}

export function RowActions({ actions, row }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState(null);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const dismiss = () => setOpen(false);
    document.addEventListener('mousedown', close);
    window.addEventListener('scroll', dismiss, true);
    window.addEventListener('resize', dismiss);
    return () => { document.removeEventListener('mousedown', close); window.removeEventListener('scroll', dismiss, true); window.removeEventListener('resize', dismiss); };
  }, [open]);
  const shown = actions.slice(0, 2); const rest = actions.slice(2);
  const openMenu = (e) => {
    if (open) { setOpen(false); return; }
    const r = e.currentTarget.getBoundingClientRect();
    const height = 10 + rest.length * 31;
    const below = window.innerHeight - r.bottom;
    setPos({ position: 'fixed', left: Math.max(8, Math.min(r.right - 176, window.innerWidth - 190)), right: 'auto', top: below < height + 12 ? Math.max(8, r.top - height - 4) : r.bottom + 4, zIndex: 200 });
    setOpen(true);
  };
  return <div className="rowacts" ref={ref}>
    {shown.map((a) => <button key={a.label} className={'mini ' + (a.danger ? 'danger' : '')} onClick={() => a.onClick ? a.onClick(row) : a.run(row)} disabled={a.disabled} title={a.title}>{a.label}</button>)}
    {rest.length > 0 && <span className="moremenu"><button className="mini" onClick={openMenu} aria-expanded={open} aria-haspopup="menu">⋯</button>{open && <span className="menu" role="menu" style={pos}>{rest.map((a) => <button key={a.label} role="menuitem" className={a.danger ? 'danger' : ''} disabled={a.disabled} onClick={() => { setOpen(false); a.onClick ? a.onClick(row) : a.run(row); }}>{a.label}</button>)}</span>}</span>}
  </div>;
}

/* ------------------------------------------------------------------ misc */
export function SectionTitle({ children, right }) { return <div className="section-title"><h2>{children}</h2>{right}</div>; }
export function CopyField({ label, value }) { return <div className="copyfield"><small>{label}</small><div><code>{value}</code><CopyButton value={value} /></div></div>; }
export function InlineNote({ children, tone: t = 'info' }) { return <div className={'inline-note ' + t}>{children}</div>; }
export function Spacer() { return <span className="grow" />; }
export function Meta({ items }) { return <div className="meta-row">{items.map(([k, v]) => <span key={k}><small>{k}</small><b>{v}</b></span>)}</div>; }

// Tiny context so pages can share a "current institution" label without prop drilling.
export const UiContext = createContext({ tenant: null });
export const useUi = () => useContext(UiContext);

/* ------------------------------------------------------------------ landing page components */
export function LandNav() {
  return (
    <nav className="landnav">
      <div className="bar">
        <div className="brand"><span className="logo">E</span>ExamOS</div>
        <nav style={{ display: 'flex', gap: 22 }}>
          <a href="#features">Features</a>
          <a href="#modules">Modules</a>
          <a href="#why">Security</a>
          <a href="#trust">Trust</a>
          <a className="btn ghost" href="/login">Sign in</a>
        </nav>
      </div>
    </nav>
  );
}
export function Hero() {
  return (
    <section className="hero">
      <div className="hero-copy">
        <span className="kicker">ExamOS Console · Secure examination platform</span>
        <h1>Secure exam delivery,<br /><span className="grad">engineered for trust.</span></h1>
        <p>Device attestation, signed policies, two-person approvals and a hash-chained audit trail — all running in the browser through IndexedDB, with no backend required. Prevention-first secure examination delivery for high-stakes academic and corporate assessments.</p>
        <div className="hero-actions">
          <button className="btn primary wide-sm" onClick={() => { window.location.href = '/login'; }}>Get started</button>
          <button className="btn outl wide-sm" onClick={() => { document.getElementById('features')?.scrollIntoView(); }}>Explore features</button>
        </div>
        <div className="hero-stats">
          <div className="hs"><span className="num">152+</span><span className="lab">Devices enrolled</span></div>
          <div className="hs"><span className="num">120+</span><span className="lab">Candidates seeded</span></div>
          <div className="hs"><span className="num">SHA-256</span><span className="lab">Hash-chained audit log</span></div>
        </div>
      </div>
      <div className="hero-visual">
        <div className="hv-card">
          <div className="hv-stat"><span className="big">152</span><span className="cap">Devices</span></div>
          <div className="hv-stat"><span className="big">120</span><span className="cap">Candidates</span></div>
          <div className="hv-stat"><span className="big">SHA-256</span><span className="cap">Audit chain</span></div>
        </div>
        <div className="hv-preview">
          <div className="hv-frame">
            <div className="hv-bar"><Icon name="grid" size={13} /><span className="hv-title">ExamOS Console</span><span className="hv-chip online">Online</span></div>
            <div className="hv-body"><div className="hv-grid"><div className="hv-cell">Dashboard</div><div className="hv-cell">Exams</div><div className="hv-cell">Devices</div><div className="hv-cell">Security</div><div className="hv-cell">Reports</div><div className="hv-cell">Support</div></div></div>
          </div>
        </div>
      </div>
    </section>
  );
}
export function Feature({ icon, title, desc, tag }) {
  return (
    <div className="feat">
      <span className="ico">{icon}</span>
      <h3>{title}</h3>
      <p>{desc}</p>
      <span className="tag">{tag}</span>
    </div>
  );
}
export function FeatureGrid() {
  return (
    <section id="features" className="features">
      <div className="sec-head">
        <div><h2>Everything you need to run secure exams</h2><p className="sub">Real validation, RBAC, ECDSA signing, TOTP, nonce/replay protection, receipts and a verified audit chain.</p></div>
      </div>
      <div className="featgrid">
        <Feature icon="🔐" title="Signed policies" desc="ECDSA P-256 signed, versioned kiosk policies with anti-downgrade and two-person rollback." tag="Security" />
        <Feature icon="🚀" title="Staged releases" desc="SBOM-scanned releases with staged rollout, revoke and device recovery." tag="Release" />
        <Feature icon="👥" title="Two-person approval" desc="Separation of duties for role changes, releases, policy rollbacks and config changes." tag="Governance" />
        <Feature icon="📱" title="TPM attestation" desc="Simulated device agent with heartbeats, PCR quotes and isolation incidents." tag="Trust" />
        <Feature icon="📊" title="Audit chain" desc="Every write is persisted in a SHA-256 hash chain that can be independently verified." tag="Compliance" />
        <Feature icon="💻" title="Frontend-only" desc="No backend. All logic runs in the browser through per-module services and IndexedDB persistence." tag="Architecture" />
      </div>
    </section>
  );
}
export function ModuleCard({ icon, title, desc, path, perm }) {
  return (
    <div className="mod">
      <span className="ico">{icon}</span>
      <h3>{title}</h3>
      <p>{desc}</p>
      <Link to={path} className="btn modbtn">Open {title}</Link>
    </div>
  );
}
export function ModulesGrid() {
  const modules = [
    { icon: '🏛️', title: 'Administration', desc: 'Tenants, users, roles, approvals and platform settings.', path: '/admin/institutions', perm: 'inst.view' },
    { icon: '📋', title: 'Examinations', desc: 'Exam lifecycle, schedules, candidates and policies.', path: '/college/exams', perm: 'exam.view' },
    { icon: '🎓', title: 'Student portal', desc: 'Assigned exams, device checks, sessions and submissions.', path: '/student/home', perm: 'student.view' },
    { icon: '👮', title: 'Operations', desc: 'Live exam monitoring, incidents and submissions queue.', path: '/operator/overview', perm: 'ops.view' },
    { icon: '🔌', title: 'Devices', desc: 'Enrollment, compatibility, attestation and USB inventory.', path: '/devices', perm: 'device.view' },
    { icon: '🛡️', title: 'Security', desc: 'Events, incidents, vulnerabilities and evidence vault.', path: '/security/overview', perm: 'security.view' },
    { icon: '📦', title: 'Releases', desc: 'Signed builds, rollout, validation and evidence.', path: '/admin/releases', perm: 'release.view' },
    { icon: '📈', title: 'Reports', desc: 'Exam, device and security reports with exports.', path: '/reports', perm: 'report.generate' },
  ];
  return (
    <section id="modules" className="modules">
      <div className="sec-head">
        <div><h2>Console modules</h2><p className="sub">One folder per module: service.js (rules + persistence) and Page.jsx (UI). Role-gated navigation throughout.</p></div>
      </div>
      <div className="modgrid">{modules.map((m) => <ModuleCard key={m.title} {...m} />)}</div>
    </section>
  );
}
export function WhySection() {
  return (
    <section id="why" className="why">
      <div className="sec-head">
        <div><h2>Built for high-stakes exams</h2><p>Every write is audited. Policies and releases are cryptographically signed. Devices converge to policy via heartbeats and fresh attestation before a session can start.</p></div>
      </div>
      <div className="whygrid">
        <div className="item"><div className="n">ECDSA</div><div className="l">Signed policies &amp; releases</div></div>
        <div className="item"><div className="n">2-Person</div><div className="l">Approval &amp; rollback</div></div>
        <div className="item"><div className="n">TPM</div><div className="l">Attestation &amp; PCR quotes</div></div>
        <div className="item"><div className="n">SHA-256</div><div className="l">Hash-chained audit log</div></div>
      </div>
    </section>
  );
}
export function TrustSection() {
  const items = [
    { icon: 'shield', label: 'Zero-trust by design', desc: 'No implicit trust. Every device attests before a session starts; every write is signed and chained.' },
    { icon: 'lock', label: 'Role-based access control', desc: 'Nine-tier RBAC with MFA, TOTP, failed-login throttling and account lockout.' },
    { icon: 'cpu', label: 'Hardware-bound identity', desc: 'TPM 2.0 PCR quotes bind each appliance to its firmware and OS measurements.' },
    { icon: 'alert', label: 'Tamper-evident ledger', desc: 'HMAC-SHA256 authenticated audit chain with truncation anchors prevents silent deletion.' },
  ];
  return (
    <section id="trust" className="trust">
      <div className="sec-head">
        <div><h2>Trust, verified</h2><p>Prevention-first security across the entire examination lifecycle.</p></div>
      </div>
      <div className="trustgrid">
        {items.map((it) => (
          <div key={it.label} className="titem">
            <div className="tico"><Icon name={it.icon} size={18} /></div>
            <div><h3>{it.label}</h3><p className="muted sm">{it.desc}</p></div>
          </div>
        ))}
      </div>
    </section>
  );
}
export function CtaSection() {
  return (
    <section className="landcta">
      <div className="cta-card">
        <h2>Ready to run secure exams?</h2>
        <p>Log in to the console and explore a pre-seeded workspace with devices, candidates, a live exam and sessions.</p>
        <div className="cta-actions">
          <button className="btn primary" onClick={() => { window.location.href = '/login'; }}>Sign in to console</button>
          <a href="#features" className="btn ghost">Learn more</a>
        </div>
      </div>
    </section>
  );
}
export function LandFoot() {
  return (
    <footer className="landfoot">
      <div className="lf-grid">
        <div><strong>ExamOS Console</strong><br /><span className="muted sm">Prevention-first secure examination platform</span></div>
        <nav className="lf-nav"><a href="#features">Features</a><a href="#modules">Modules</a><a href="#why">Security</a><a href="/login">Sign in</a></nav>
        <div className="lf-note">Frontend-only · IndexedDB persistence · Session in memory only · No backend required</div>
      </div>
    </footer>
  );
}
