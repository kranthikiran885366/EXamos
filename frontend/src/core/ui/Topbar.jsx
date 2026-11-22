import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, matchPath, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { useTenant, useCol } from '../db/tenant';
import { ROUTES, TITLES } from '../nav';
import { can, roleLabel } from '../security/rbac';
import { clean } from '../security/sanitize';
import { put } from '../db/db';
import { visibleTo } from '../../modules/notifications/service';
import { ago } from './format';
import { Icon, Badge } from './kit';

function useClickOutside(ref, fn) {
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) fn(); };
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h);
  }, [ref, fn]);
}

export default function Topbar({ onMenu, onCollapse, collapsed, backend }) {
  const { user, lock, logout, backendMode, backendReady } = useAuth();
  const { tenant, tenants, setTenantId } = useTenant();
  const loc = useLocation(); const nav = useNavigate();
  const incidents = useCol('incidents');
  const notifications = useCol('notifications');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(null); // 'search' | 'notifications' | 'user'
  const wrap = useRef(null); useClickOutside(wrap, () => setOpen(null));
  const [online, setOnline] = useState(typeof navigator !== 'undefined' ? navigator.onLine : true);

  const exams = useCol('exams');
  const devices = useCol('devices');
  const candidates = useCol('candidates');
  const tickets = useCol('support');
  const institutions = useCol('tenants', false);
  const usbs = useCol('usbs');

  useEffect(() => {
    const on = () => setOnline(true), off = () => setOnline(false);
    window.addEventListener('online', on); window.addEventListener('offline', off);
    return () => { window.removeEventListener('online', on); window.removeEventListener('offline', off); };
  }, []);
  useEffect(() => { const k = (e) => { if (e.key === 'Escape') setOpen(null); if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen('search'); } }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, []);

  const crit = incidents.filter((i) => i.severity === 'critical' && ['open', 'investigating', 'contained'].includes(i.status)).length;
  const openInc = incidents.filter((i) => ['open', 'investigating', 'contained'].includes(i.status)).length;
  const mine = visibleTo(user, notifications).filter((n) => !(n.readBy || []).includes(user.id));
  const unread = mine.length;

  const crumb = useMemo(() => {
    const def = ROUTES.find((r) => matchPath({ path: r.path, end: true }, loc.pathname)) || ROUTES.find((r) => matchPath({ path: r.path }, loc.pathname));
    const label = TITLES[loc.pathname] || def?.label || 'Page';
    return { group: def?.group || 'ExamOS', label, def };
  }, [loc.pathname]);

  const results = useMemo(() => {
    const s = q.trim().toLowerCase(); if (s.length < 2) return [];
    const out = [];
    const routeExam = (examId) => {
      if (user.role === 'student') return `/student/exams/${examId}`;
      if (['invigilator', 'ops_admin'].includes(user.role)) return `/operator/exams/${examId}/live`;
      return `/college/exams/${examId}`;
    };
    if (can(user.role, 'exam.view') || can(user.role, 'student.view')) {
      exams.filter((e) => `${e.code} ${e.title}`.toLowerCase().includes(s)).slice(0, 4).forEach((e) => {
        out.push({ to: routeExam(e.id), label: `${e.code} · ${e.title}`, kind: 'Exam' });
      });
    }
    if (can(user.role, 'device.view')) devices.filter((d) => `${d.hostname} ${d.serial}`.toLowerCase().includes(s)).slice(0, 3).forEach((d) => out.push({ to: `/devices/${d.id}`, label: d.hostname, kind: 'Device' }));
    if (can(user.role, 'candidate.view')) candidates.filter((c) => `${c.rollNo} ${c.name}`.toLowerCase().includes(s)).slice(0, 3).forEach((c) => out.push({ to: `/college/candidates?q=${encodeURIComponent(c.rollNo)}`, label: `${c.rollNo} · ${c.name}`, kind: 'Candidate' }));
    if (can(user.role, 'support.view')) tickets.filter((t) => `${t.no} ${t.subject}`.toLowerCase().includes(s)).slice(0, 3).forEach((t) => out.push({ to: `/support/requests/${t.id}`, label: `${t.no} · ${t.subject}`, kind: 'Request' }));
    if (can(user.role, 'inst.view')) institutions.filter((i) => i.name.toLowerCase().includes(s)).slice(0, 3).forEach((i) => out.push({ to: `/admin/institutions/${i.id}`, label: i.name, kind: 'Institution' }));
    if (can(user.role, 'usb.view')) usbs.filter((u) => `${u.assetId} ${u.serial}`.toLowerCase().includes(s)).slice(0, 2).forEach((u) => out.push({ to: `/usb-inventory/${u.id}`, label: u.assetId, kind: 'USB' }));
    return out.slice(0, 10);
  }, [q, exams, devices, candidates, tickets, institutions, usbs, user.role]);

  const markAll = async () => {
    for (const n of mine) await put('notifications', { ...n, readBy: [...(n.readBy || []), user.id] });
  };
  const go = (to) => { setOpen(null); setQ(''); nav(to); };

  return <header className="topbar" ref={wrap}>
    <button className="iconbtn mobile-only" onClick={onMenu} aria-label="Open navigation"><Icon name="menu" /></button>
    <button className="iconbtn desktop-only" onClick={onCollapse} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}><Icon name="menu" /></button>

    <div className="crumbs">
      <span>{crumb.group}</span><Icon name="arrow" size={12} /><b>{crumb.label}</b>
    </div>

    <div className="gsearch">
      <label className={'searchbox' + (open === 'search' ? ' focused' : '')}>
        <Icon name="search" size={15} />
        <input value={q} onChange={(e) => { setQ(clean(e.target.value, 80)); setOpen('search'); }} onFocus={() => setOpen('search')} placeholder="Search exams, devices, candidates…" maxLength={80} aria-label="Global search" />
        <kbd>⌘K</kbd>
      </label>
      {open === 'search' && q.trim().length >= 2 && <div className="dropdown search-results">
        {results.length ? results.map((r) => <button key={r.to + r.label} onClick={() => go(r.to)}><span className="sr-kind">{r.kind}</span><span>{r.label}</span></button>) : <div className="dropdown-empty">No authorised records match “{q}”.</div>}
        <div className="dropdown-foot">Search is limited to records your role can access.</div>
      </div>}
    </div>

    <div className="topbar-right">
      <span className={'conn ' + (online ? 'ok' : 'bad')} title={online ? 'Network reachable' : 'Offline'}><i />{online ? 'Online' : 'Offline'}</span>
      <span className={'conn backend-conn ' + (backendReady ? 'ok' : 'bad')} title={backendReady ? 'Backend C server reachable' : 'Backend unreachable'}><i />{backendReady ? 'Backend' : 'Local only'}</span>
      <Link to={can(user.role, 'security.view') ? '/security/incident-response' : '/operator/incidents'} className={'topstatus ' + (crit ? 'bad' : openInc ? 'warn' : 'ok')}>
        <i />{crit ? `${crit} critical` : openInc ? `${openInc} open` : 'Operational'}
      </Link>

      <div className="menu-anchor">
        <button className="iconbtn bell" aria-label={`${unread} unread notifications`} onClick={() => setOpen(open === 'notifications' ? null : 'notifications')}><Icon name="bell" size={18} />{unread > 0 && <em />}</button>
        {open === 'notifications' && <div className="dropdown notif">
          <div className="dropdown-head"><b>Notifications</b><span className="grow" />{unread > 0 && <button className="mini" onClick={markAll}>Mark all read</button>}</div>
          {mine.slice(0, 6).map((n) => <button key={n.id} className="notif-item" onClick={async () => { await put('notifications', { ...n, readBy: [...(n.readBy || []), user.id] }); go(n.link || '/notifications'); }}>
            <span className={'notif-dot ' + (n.tone || 'info')} /><span><b>{n.title}</b><small>{n.body}</small><em>{ago(n.createdAt)}</em></span>
          </button>)}
          {!mine.length && <div className="dropdown-empty">You are all caught up.</div>}
          <Link className="dropdown-foot" to="/notifications" onClick={() => setOpen(null)}>Open inbox</Link>
        </div>}
      </div>

      <div className="menu-anchor">
        <button className="userbtn" onClick={() => setOpen(open === 'user' ? null : 'user')} aria-expanded={open === 'user'}>
          <span className="avatar">{user.initials}</span>
          <span className="user-meta"><b>{user.name}</b><small>{roleLabel(user.role)}</small></span>
          <Icon name="chevron" size={13} />
        </button>
        {open === 'user' && <div className="dropdown user-menu">
          <div className="user-menu-head"><b>{user.name}</b><small>{user.id} · {roleLabel(user.role)}</small></div>
          <Link to="/account" onClick={() => setOpen(null)}>Account settings</Link>
          <Link to="/account/security" onClick={() => setOpen(null)}>Security &amp; MFA</Link>
          <Link to="/account/sessions" onClick={() => setOpen(null)}>Active sessions</Link>
          {can(user.role, 'notification.view') && <Link to="/notifications" onClick={() => setOpen(null)}>Notifications</Link>}
          <button onClick={() => { setOpen(null); lock(); }}>Lock session</button>
          <button className="danger" onClick={() => logout()}>Sign out</button>
        </div>}
      </div>
    </div>

    {tenants.length > 1 && <select className="tenant-select" aria-label="Institution" value={tenant?.id || ''} onChange={(e) => setTenantId(e.target.value)}>
      {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}{t.status !== 'active' ? ` (${t.status})` : ''}</option>)}
    </select>}
    {tenants.length === 1 && <span className="tenant-chip" title={tenant?.name}><Badge value={tenant?.status || 'active'} />{tenant?.name?.slice(0, 18)}</span>}
  </header>;
}
