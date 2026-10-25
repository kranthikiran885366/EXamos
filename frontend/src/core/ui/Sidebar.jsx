import { NavLink } from 'react-router-dom';
import { GROUPS } from '../nav';
import { can } from '../security/rbac';
import { Icon } from './kit';

export default function Sidebar({ user, collapsed, onNavigate, version, env, backend }) {
  return (
    <aside className={'side' + (collapsed ? ' collapsed' : '')} aria-label="Main navigation">
      <div className="brand">
        <span className="logo">▣</span>
        <span className="brand-text">ExamOS <em>{env || 'ENT'}</em></span>
        <span className={`backend-status ${backend?.online === 'online' ? 'online' : 'offline'}`} title={`Backend: ${backend?.mode || 'none'} — ${backend?.online}`}>
          {backend?.mode === 'none' ? '● LOCAL' : backend?.online === 'online' ? '● BACKEND' : '● BACKEND OFFLINE'}
        </span>
      </div>
      <div className="side-scroll">
        {GROUPS.map((g) => {
          const items = g.items.filter((i) => can(user.role, i.perm));
          if (!items.length) return null;
          return (
            <div className="navgroup" key={g.label}>
              <div className="navgroup-label">{g.label}</div>
              <nav aria-label={g.label}>
                {items.map((i) => (
                  <NavLink key={i.path} to={i.path} end={i.end} onClick={onNavigate} className={({ isActive }) => 'nav' + (isActive ? ' on' : '')} title={collapsed ? i.label : undefined}>
                    <Icon name={i.icon} size={17} />
                    <span className="nav-label">{i.label}</span>
                  </NavLink>
                ))}
              </nav>
            </div>
          );
        })}
      </div>
      <div className="side-foot">
        <NavLink to="/support" onClick={onNavigate} className={({ isActive }) => 'nav' + (isActive ? ' on' : '')}>
          <Icon name="life" size={17} /><span className="nav-label">Support &amp; docs</span>
        </NavLink>
        <div className="version">Console v{version}</div>
      </div>
    </aside>
  );
}
