import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function SolutionsPage() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [stationCount, setStationCount] = useState(500);
  const [stationInput, setStationInput] = useState('500');
  const [centerCount, setCenterCount] = useState(5);
  const [centerInput, setCenterInput] = useState('5');

  const updateNumberInput = (raw, minimum, maximum, setRaw, setValue) => {
    setRaw(raw);
    if (!raw) return;
    const value = Number(raw);
    if (Number.isFinite(value)) setValue(Math.min(maximum, Math.max(minimum, value)));
  };

  const normalizeNumberInput = (raw, minimum, maximum, fallback, setRaw, setValue) => {
    const value = Number(raw);
    const normalized = raw && Number.isFinite(value) ? Math.min(maximum, Math.max(minimum, value)) : fallback;
    setValue(normalized);
    setRaw(String(normalized));
  };

  const totalCandidates = stationCount * 3;
  const auditEntries = totalCandidates * 450;
  const estimatedLedgerMB = Math.round((auditEntries * 256) / (1024 * 1024) * 10) / 10;

  const solutions = [
    {
      badge: 'Enterprise Technical Recruitment',
      action: 'Request a technical briefing',
      actionHref: '/#contact',
      title: 'Engineering Hiring & Campus Assessment',
      subtitle: 'Assessment controls and review workflows for technical hiring.',
      desc: 'A technical hiring deployment may combine a dedicated assessment environment, configured monitoring, event review, and interviewer-led follow-up. Module availability, hardware support, and data handling depend on the deployment profile.',
      highlights: [
        'SPPIO-Forensics™ line-by-line keystroke replay and time-lapse code construction playback',
        'Optional monitoring can surface signals for human review; it does not prove misconduct on its own',
        'Peripheral restrictions depend on supported devices and configured policy',
        'Recruiter workflows and exports depend on enabled modules',
      ],
    },
    {
      badge: 'Senior Tech Hiring & Viva Defense',
      action: 'Request a technical briefing',
      actionHref: '/#contact',
      title: 'Technical Viva Defense & Code Authorship Verification',
      subtitle: 'Structured review of assessment activity and candidate discussion.',
      desc: 'Teams can use configured event histories and interviewer-led discussion to inform technical evaluation. These signals do not independently establish authorship or intent.',
      highlights: [
        'Interactive code playback allowing interviewers to challenge specific algorithmic decisions',
        'Event collection and retention depend on enabled modules and policy',
        'Hardware checks require compatible workstations and deployment configuration',
        'Review audit exports against organizational retention and access requirements',
      ],
    },
    {
      badge: 'National Testing Agencies',
      action: 'Start institutional onboarding',
      actionHref: '/register-institution',
      title: 'Distributed Assessment Fleet Planning',
      subtitle: 'Massive concurrent scale across geographically dispersed assessment centers.',
      desc: 'Plan supported workstation models, site connectivity, operational support, and submission reconciliation for geographically distributed assessments. Validate boot and attestation behavior on the target hardware before rollout.',
      highlights: [
        'Hardware measurement coverage depends on compatible devices and policy',
        'Offline availability and synchronization behavior depend on deployment configuration',
        'Confirm submission reconciliation and audit requirements before rollout',
        'Peripheral and network controls must be validated for each station profile',
      ],
    },
    {
      badge: 'Higher Education & Universities',
      action: 'Start institutional onboarding',
      actionHref: '/register-institution',
      title: 'Institutional Examination Enclaves',
      subtitle: 'Multi-campus assessment governance with role-based segregation.',
      desc: 'Institutions can map academic roles, approval requirements, and assessment workflows to the configured platform controls. Confirm tenancy boundaries and permissions with a representative deployment.',
      highlights: [
        'Departmental tenancy isolation with independent supervisor roles in SPPIO-Command™',
        'Configure role separation and approval rules to match institutional policy',
        'Station restrictions depend on the selected kiosk profile and supported hardware',
        'Review authentication and cryptographic assurance evidence for the deployed release',
      ],
    },
    {
      badge: 'Professional Licensure Boards',
      action: 'Request a technical briefing',
      actionHref: '/#contact',
      title: 'High-Integrity Credentialing & Certification',
      subtitle: 'Audit and workflow planning for certification programs.',
      desc: 'Certification teams can assess event handling, role separation, retention, and audit exports against their regulatory and operational requirements. No certification or audit outcome is implied.',
      highlights: [
        'Confirm identity and attestation behavior for supported workstation models',
        'Monitoring scope depends on enabled features, consent, and retention policy',
        'Validate audit export format and verification procedures with intended reviewers',
        'Confirm local data cleanup behavior for the selected station profile',
      ],
    },
  ];

  return (
    <div id="top" tabIndex="-1" className="sppio-website">
      {/* ---------------- Header ---------------- */}
      <header className="sppio-header" role="banner">
        <div className="sppio-container">
          <div className="sppio-header-inner">
            <Link to="/" className="sppio-brand-link" aria-label="SPPIO Home">
              <SppioLogo width={164} accent="#B54F34" ink="#302337" />
            </Link>

            <nav className="sppio-nav" aria-label="Primary navigation">
              <Link to="/landing#suite" className="sppio-nav-item">Products</Link>
              <Link to="/solutions" className="sppio-nav-item" style={{ color: '#B54F34' }}>Solutions</Link>
              <Link to="/landing#capabilities" className="sppio-nav-item">Capabilities</Link>
              <Link to="/architecture" className="sppio-nav-item">Architecture</Link>
              <Link to="/landing#deployments" className="sppio-nav-item">Deployments</Link>
              <Link to="/landing#company" className="sppio-nav-item">Company</Link>
            </nav>

            <div className="sppio-header-actions">
              <Link to="/register-institution" className="sppio-nav-item" style={{ color: '#B54F34', fontWeight: 700 }}>Institution Onboarding</Link>
              <Link to="/register-institution?tab=track" className="sppio-nav-item">Track Application</Link>
              <Link to="/login" className="sppio-btn-ghost">
                Sign In
              </Link>
              <a href="/landing#contact" className="sppio-btn-primary">
                Request Briefing
              </a>
              <button type="button" className="sppio-mobile-toggle" aria-label="Toggle navigation" aria-expanded={mobileMenuOpen} aria-controls="solutions-mobile-navigation" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  {mobileMenuOpen ? <path d="M18 6L6 18M6 6l12 12" /> : <path d="M3 12h18M3 6h18M3 18h18" />}
                </svg>
              </button>
            </div>
          </div>
          {mobileMenuOpen && <nav id="solutions-mobile-navigation" className="sppio-mobile-drawer" aria-label="Mobile navigation">
            <Link to="/landing#suite" onClick={() => setMobileMenuOpen(false)}>Products</Link>
            <Link to="/solutions" onClick={() => setMobileMenuOpen(false)}>Solutions</Link>
            <Link to="/landing#capabilities" onClick={() => setMobileMenuOpen(false)}>Capabilities</Link>
            <Link to="/architecture" onClick={() => setMobileMenuOpen(false)}>Architecture</Link>
            <Link to="/landing#deployments" onClick={() => setMobileMenuOpen(false)}>Deployments</Link>
            <Link to="/landing#company" onClick={() => setMobileMenuOpen(false)}>Company</Link>
            <Link to="/register-institution" onClick={() => setMobileMenuOpen(false)}>Institution Onboarding</Link>
            <Link to="/register-institution?tab=track" onClick={() => setMobileMenuOpen(false)}>Track Application</Link>
            <Link to="/login" onClick={() => setMobileMenuOpen(false)}>Sign In</Link>
          </nav>}
        </div>
      </header>

      {/* ---------------- Hero Section ---------------- */}
      <section className="sppio-hero-section" style={{ padding: '72px 0 80px' }}>
        <div className="sppio-container">
          <div className="sppio-kicker-badge">
            <span className="sppio-kicker-dot" />
            <span>Open Aperture · Corporate Recruitment &amp; Institutional Solutions</span>
          </div>

          <h1 className="sppio-hero-headline" style={{ maxWidth: '820px' }}>
            Securing global recruitment.<br />
            <span className="sppio-highlight">Engineered for authentic engineering talent.</span>
          </h1>

          <p className="sppio-hero-lead" style={{ maxWidth: '720px' }}>
            Explore example workflows for institutional examinations, enterprise hiring, and technical evaluation. Product capabilities and assurance depend on the selected deployment.
          </p>

          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '24px' }}>
            <a href="#solutions-grid" className="sppio-btn-primary">
              Explore Recruitment &amp; Testing Solutions ↓
            </a>
            <a href="#calculator" className="sppio-btn-ghost">
              Fleet Capacity Calculator
            </a>
          </div>
        </div>
      </section>

      {/* ---------------- Solutions List ---------------- */}
      <section id="solutions-grid" className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Enterprise Verticals</span>
              <h2 className="sppio-section-title">Corporate Hiring &amp; Institutional Deployments</h2>
            </div>
            <p className="sppio-section-desc">
              Whether hiring top-tier software engineers or running high-stakes licensure exams, SPPIO provides a unified hardware-rooted security foundation.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '36px' }}>
            {solutions.map((sol, idx) => (
              <div
                key={idx}
                style={{
                  background: '#FFFFFF',
                  border: '1px solid #DCD5D2',
                  borderRadius: '16px',
                  padding: '40px',
                  boxShadow: '0 8px 24px rgba(48, 35, 55, 0.04)',
                  position: 'relative',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
                  <span className="sppio-tag" style={{ background: 'rgba(181, 79, 52, 0.12)', color: '#B54F34', borderColor: 'rgba(181, 79, 52, 0.3)', fontWeight: 750 }}>
                    {sol.badge}
                  </span>
                  <SppioSymbol size={22} accent="#B54F34" />
                </div>

                <h3 style={{ fontSize: '24px', fontWeight: 800, color: '#302337', margin: '0 0 6px', letterSpacing: '-0.02em' }}>
                  {sol.title}
                </h3>
                <h4 style={{ fontSize: '15px', fontWeight: 600, color: '#B54F34', margin: '0 0 16px' }}>
                  {sol.subtitle}
                </h4>
                <p style={{ fontSize: '15px', color: '#756F79', lineHeight: 1.65, margin: '0 0 24px', maxWidth: '800px' }}>
                  {sol.desc}
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', paddingTop: '20px', borderTop: '1px solid #EBE5E2' }}>
                  {sol.highlights.map((h, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#B54F34', marginTop: '8px', flexShrink: 0 }} />
                      <span style={{ fontSize: '13.5px', color: '#302337', fontWeight: 550 }}>{h}</span>
                    </div>
                  ))}
                </div>
                <Link to={sol.actionHref} className="sppio-btn-primary" style={{ display: 'inline-block', marginTop: '20px' }}>{sol.action} →</Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------- Interactive Fleet Calculator ---------------- */}
      <section id="calculator" className="sppio-section" style={{ background: '#302337', color: '#F6F2ED' }}>
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow" style={{ color: '#FFAE99' }}>Capacity Planning</span>
              <h2 className="sppio-section-title" style={{ color: '#FFFFFF' }}>Fleet Scale &amp; Cryptographic Estimator</h2>
            </div>
            <p className="sppio-section-desc" style={{ color: '#C3B7C6' }}>
              Planning estimate only. Values are assumption-based, not measured capacity or storage commitments.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '32px', alignItems: 'center' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
              <div>
                <label htmlFor="estimator-stations-range" style={{ display: 'block', fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
                  Concurrent testing stations
                </label>
                <input
                  id="estimator-stations-range"
                  type="range"
                  min="50"
                  max="5000"
                  step="1"
                  value={stationCount}
                  onChange={(e) => {
                    const value = Number(e.target.value);
                    setStationCount(value);
                    setStationInput(String(value));
                  }}
                  style={{ width: '100%', accentColor: '#B54F34', cursor: 'pointer' }}
                />
                <label htmlFor="estimator-stations-number" style={{ display: 'block', fontSize: '12px', marginTop: '10px' }}>Number of stations</label>
                <input id="estimator-stations-number" type="number" min="50" max="5000" step="1" value={stationInput} onChange={(e) => updateNumberInput(e.target.value, 50, 5000, setStationInput, setStationCount)} onBlur={() => normalizeNumberInput(stationInput, 50, 5000, stationCount, setStationInput, setStationCount)} style={{ width: '100%', boxSizing: 'border-box', marginTop: '4px', padding: '9px', borderRadius: '6px' }} />
              </div>

              <div>
                <label htmlFor="estimator-centers-range" style={{ display: 'block', fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
                  Testing centers
                </label>
                <input
                  id="estimator-centers-range"
                  type="range"
                  min="1"
                  max="50"
                  step="1"
                  value={centerCount}
                  onChange={(e) => {
                    const value = Number(e.target.value);
                    setCenterCount(value);
                    setCenterInput(String(value));
                  }}
                  style={{ width: '100%', accentColor: '#B54F34', cursor: 'pointer' }}
                />
                <label htmlFor="estimator-centers-number" style={{ display: 'block', fontSize: '12px', marginTop: '10px' }}>Number of centers</label>
                <input id="estimator-centers-number" type="number" min="1" max="50" step="1" value={centerInput} onChange={(e) => updateNumberInput(e.target.value, 1, 50, setCenterInput, setCenterCount)} onBlur={() => normalizeNumberInput(centerInput, 1, 50, centerCount, setCenterInput, setCenterCount)} style={{ width: '100%', boxSizing: 'border-box', marginTop: '4px', padding: '9px', borderRadius: '6px' }} />
              </div>

              <div style={{ fontSize: '13px', color: '#D5CCD8', lineHeight: 1.6 }}>
                Planning estimate only, not a capacity guarantee. Assumptions: 3 candidates per station per day, 450 audit events per candidate, and 256 bytes per event. Actual throughput and storage vary by workload and deployment.
              </div>
            </div>

            <div style={{ background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '16px', padding: '36px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                <div>
                  <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    Daily Candidate Capacity
                  </span>
                  <div style={{ fontSize: '32px', fontWeight: 800, color: '#FFFFFF', margin: '6px 0 2px' }}>
                    {totalCandidates.toLocaleString()}
                  </div>
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>                  Candidates / day (assumed)</span>
                </div>

                <div>
                  <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    Stations per Center
                  </span>
                  <div style={{ fontSize: '32px', fontWeight: 800, color: '#FFFFFF', margin: '6px 0 2px' }}>
                    {Math.round(stationCount / centerCount)}
                  </div>
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>Average distribution</span>
                </div>

                <div>
                  <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    Chained Ledger Events
                  </span>
                  <div style={{ fontSize: '32px', fontWeight: 800, color: '#FFFFFF', margin: '6px 0 2px' }}>
                    {auditEntries.toLocaleString()}
                  </div>
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>                  Events / day (assumed)</span>
                </div>

                <div>
                  <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    Cryptographic Ledger Storage
                  </span>
                  <div style={{ fontSize: '32px', fontWeight: 800, color: '#FFFFFF', margin: '6px 0 2px' }}>
                    ~{estimatedLedgerMB} MB
                  </div>
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>At assumed 256 bytes per event</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- Footer ---------------- */}
      <footer className="sppio-footer" role="contentinfo">
        <div className="sppio-container">
          <div className="sppio-footer-grid">
            <div className="sppio-footer-brand">
              <SppioLogo width={160} accent="#B54F34" ink="#FFFFFF" />
              <p>
                Open Aperture architecture. High-assurance infrastructure engineered for national, institutional, and corporate assessment integrity.
              </p>
            </div>
            <div className="sppio-footer-col">
              <h5>Public Pages</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/landing">Platform Overview</Link></li>
                <li><Link to="/architecture">Silicon Attestation</Link></li>
                <li><Link to="/solutions">Enterprise Solutions</Link></li>
              </ul>
            </div>
            <div className="sppio-footer-col">
              <h5>Institutional Use</h5>
              <ul className="sppio-footer-links">
                <li><a href="#solutions-grid">National Testing</a></li>
                <li><a href="#solutions-grid">University Licensure</a></li>
                <li><a href="#calculator">Fleet Capacity Estimator</a></li>
              </ul>
            </div>
            <div className="sppio-footer-col">
              <h5>Console Access</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/login" style={{ color: '#FFAE99', fontWeight: 700 }}>Console Sign In →</Link></li>
                <li><Link to="/candidate-login">Candidate Station Login</Link></li>
                <li><Link to="/register-institution">Institution Onboarding</Link></li>
                <li><Link to="/register-institution?tab=track">Track Application</Link></li>
                <li><a href="/landing#contact">Schedule Consultation</a></li>
              </ul>
            </div>
          </div>

          <div className="sppio-footer-bottom">
            <div>© 2026 SPPIO Systems Enclave. All rights reserved. Open Aperture architecture.</div>
            <div className="sppio-legal-links">
              <Link to="/landing">Platform Home</Link>
              <a href="#top" onClick={(e) => { e.preventDefault(); document.getElementById('top')?.focus(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Back to Top ↑</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
