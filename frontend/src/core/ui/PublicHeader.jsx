import { useEffect, useId, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import SppioLogo from './SppioLogo';

const PRIMARY_NAV = [
  { key: 'products', label: 'Products', hash: '#suite' },
  { key: 'solutions', label: 'Solutions', to: '/solutions' },
  { key: 'capabilities', label: 'Capabilities', hash: '#capabilities' },
  { key: 'architecture', label: 'Architecture', to: '/architecture' },
  { key: 'company', label: 'Company', hash: '#company' },
];

export default function PublicHeader({ active = null }) {
  const { pathname } = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const drawerId = useId();
  const onLanding = pathname === '/' || pathname === '/landing';

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  const hrefFor = (item) => (item.to ? item.to : onLanding ? item.hash : `/landing${item.hash}`);
  const briefingHref = onLanding ? '#contact' : '/landing#contact';

  return (
    <header className="sppio-header" role="banner">
      <a className="sppio-skip-link" href="#main-content">Skip to content</a>
      <div className="sppio-container">
        <div className="sppio-header-inner">
          <Link to="/" className="sppio-brand-link" aria-label="SPPIO home">
            <SppioLogo width={164} accent="#B54F34" ink="#302337" />
          </Link>

          <nav className="sppio-nav" aria-label="Primary">
            {PRIMARY_NAV.map((item) => {
              const isActive = active === item.key;
              return (
                <Link
                  key={item.key}
                  to={hrefFor(item)}
                  className={`sppio-nav-item${isActive ? ' is-active' : ''}`}
                  aria-current={isActive ? 'page' : undefined}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="sppio-header-actions">
            <Link to="/register-institution?tab=track" className="sppio-nav-item sppio-nav-item--quiet">
              Track application
            </Link>
            <Link to="/login" className="sppio-btn-ghost">Sign in</Link>
            <Link to={briefingHref} className="sppio-btn-primary">Request briefing</Link>
            <button
              type="button"
              className="sppio-mobile-toggle"
              aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
              aria-expanded={menuOpen}
              aria-controls={drawerId}
              onClick={() => setMenuOpen((open) => !open)}
            >
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                {menuOpen ? <path d="M18 6L6 18M6 6l12 12" /> : <path d="M3 12h18M3 6h18M3 18h18" />}
              </svg>
            </button>
          </div>
        </div>

        {menuOpen && (
          <nav id={drawerId} className="sppio-mobile-drawer" aria-label="Mobile">
            {PRIMARY_NAV.map((item) => (
              <Link key={item.key} to={hrefFor(item)} onClick={() => setMenuOpen(false)}>
                {item.label}
              </Link>
            ))}
            <span className="sppio-mobile-divider" aria-hidden="true" />
            <Link to="/register-institution" onClick={() => setMenuOpen(false)}>Institution onboarding</Link>
            <Link to="/register-institution?tab=track" onClick={() => setMenuOpen(false)}>Track application</Link>
            <Link to="/login" onClick={() => setMenuOpen(false)}>Sign in</Link>
            <Link to={briefingHref} onClick={() => setMenuOpen(false)} className="sppio-mobile-cta">Request briefing</Link>
          </nav>
        )}
      </div>
    </header>
  );
}
