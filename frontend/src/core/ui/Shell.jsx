import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { TenantProvider, useTenant, useCol } from '../db/tenant';
import { useSessionGuard } from '../security/sessionGuard';
import { can } from '../security/rbac';
import { startEngine, stopEngine } from '../../modules/ops/engine';
import { Icon } from './kit';
import Sidebar from './Sidebar';
import Topbar from './Topbar';
import LockScreen from './LockScreen';

export const APP_VERSION = '3.0.0';

function Inner() {
  const { user, locked, lock, logout, touchSession, backendMode, backendReady } = useAuth();
  const { tenant } = useTenant();
  const meta = useCol('meta', false);
  const rawPlatform = meta.find((m) => m.id === 'platform');
  const platform = rawPlatform?.value || rawPlatform || {};
  const [drawer, setDrawer] = useState(false);
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('examos.sidebar') === '1'; } catch { return false; } });
  const loc = useLocation();
  const warning = useSessionGuard({
    active: !!user && !locked, idleMs: 10 * 60e3, maxMs: 8 * 3600e3, warnMs: 60e3,
    onIdle: lock, onExpire: () => logout('SESSION_EXPIRED'),
  });
  useEffect(() => { startEngine(); return stopEngine; }, []);
  useEffect(() => { setDrawer(false); }, [loc.pathname]);
  useEffect(() => { try { localStorage.setItem('examos.sidebar', collapsed ? '1' : '0'); } catch { /* storage may be blocked */ } }, [collapsed]);
  useEffect(() => { if (user) touchSession(); }, [user, loc.pathname, touchSession]);

  const env = (platform.environment || 'production') === 'production' ? 'PROD' : platform.environment === 'staging' ? 'STG' : 'DEV';
  const backendLabel = backendMode === 'admin' ? 'Backend (C server)' : backendMode === 'candidate' ? 'Candidate exam' : 'Local';
  const backendOnline = backendReady ? 'online' : 'offline';
  return (
    <div className={'app' + (collapsed ? ' rail' : '')}>
      <div className={'side-wrap' + (drawer ? ' mobile-open' : '')}>
        <Sidebar user={user} collapsed={collapsed} version={APP_VERSION} env={env} onNavigate={() => setDrawer(false)} backend={{ mode: backendMode, online: backendOnline }} />
      </div>
      {drawer && <button className="scrim-nav" aria-label="Close navigation" onClick={() => setDrawer(false)} />}
      <div className="main">
        <Topbar onMenu={() => setDrawer(true)} collapsed={collapsed} onCollapse={() => setCollapsed(!collapsed)} backend={{ mode: backendMode, online: backendOnline }} />
        {platform.maintenance?.enabled && <div className="maintenance" role="status"><Icon name="warn" size={15} /><b>Maintenance mode</b><span>{platform.maintenance.message || 'Some actions are temporarily read-only.'}</span></div>}
        {warning > 0 && !locked && <div className="session-warn" role="status"><Icon name="clock" size={15} /><span>Your session locks in {Math.ceil(warning / 1000)}s due to inactivity.</span><button className="mini" onClick={() => { touchSession(); }}>Stay signed in</button></div>}
        <main className="content" id="main">{locked ? <LockScreen /> : <Outlet />}</main>
        <footer className="appfoot">
          <span>ExamOS Console v{APP_VERSION} · {env} · {tenant?.name || 'No institution selected'}</span>
          <span>{can(user.role, 'audit.view') ? 'Audit logging active' : 'Session audited'} · {backendMode === 'none' ? 'Local secure workspace' : `Backend: ${backendLabel} (${backendOnline})`}</span>
        </footer>
      </div>
    </div>
  );
}
export default function Shell() { return <TenantProvider><Inner /></TenantProvider>; }
