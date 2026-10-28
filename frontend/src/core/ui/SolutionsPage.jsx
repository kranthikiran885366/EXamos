import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function SolutionsPage() {
  const [stationCount, setStationCount] = useState(500);
  const [centerCount, setCenterCount] = useState(5);

  const totalCandidates = stationCount * 3; // 3 batches per day
  const auditEntries = stationCount * 450; // average 450 ledger entries per candidate
  const estimatedLedgerMB = Math.round((auditEntries * 256) / (1024 * 1024) * 10) / 10;

  const solutions = [
    {
      badge: 'National Testing Agencies',
      title: 'Decentralized High-Stakes Testing Fleets',
      subtitle: 'Massive concurrent scale across geographically dispersed assessment centers.',
      desc: 'National competitive and civil service examinations require foolproof containment across heterogeneous hardware. SPPIO bootable drives turn any standard commodity x86_64 workstation into a cryptographically sealed testing enclave within 45 seconds.',
      highlights: [
        'Unattended hardware attestation and golden policy verification on boot',
        'Air-gap execution resilience with zero dependency on WAN stability',
        'Batch cryptographic submission reconciliation with asymmetric signatures',
        'Suppression of external mass storage, unauthorized networking, and OS escape',
      ],
    },
    {
      badge: 'Higher Education & Universities',
      title: 'Institutional Examination Enclaves',
      subtitle: 'Multi-campus assessment governance with role-based segregation.',
      desc: 'Universities operate complex academic schedules across diverse faculties and departments. SPPIO provides a unified multi-tenancy control plane with nine-tier RBAC, dual-custody approval for grade/policy changes, and student session attestation.',
      highlights: [
        'Departmental tenancy isolation with independent supervisor roles',
        'Two-person approval rule for policy rollback and score release',
        'Zero-trust student kiosk mode preventing secondary monitor sharing',
        'Integrated multi-factor authentication and FIPS-compliant cryptography',
      ],
    },
    {
      badge: 'Professional Licensure Boards',
      title: 'High-Integrity Credentialing & Certification',
      subtitle: 'Non-repudiable audit trails for high-consequence licensure.',
      desc: 'Medical, legal, and financial certification bodies demand mathematically provable integrity. SPPIO ensures that every candidate interaction, proctoring alert, and score generation is permanently chained in a verifiable tamper-evident ledger.',
      highlights: [
        'Non-repudiable candidate identity binding via hardware cryptographic quotes',
        'Continuous real-time supervisory tracking and peripheral monitoring',
        'Immutable audit export readable by independent third-party auditors',
        'Zero residual client footprint post-examination reboot',
      ],
    },
  ];

  return (
    <div className="sppio-website">
      {/* ---------------- Header ---------------- */}
      <header className="sppio-header" role="banner">
        <div className="sppio-container">
          <div className="sppio-header-inner">
            <Link to="/" className="sppio-brand-link" aria-label="SPPIO Home">
              <SppioLogo width={164} accent="#B54F34" ink="#302337" />
            </Link>

            <nav className="sppio-nav" aria-label="Primary navigation">
              <Link to="/landing" className="sppio-nav-item">Platform</Link>
              <Link to="/architecture" className="sppio-nav-item">Architecture</Link>
              <Link to="/solutions" className="sppio-nav-item" style={{ color: '#B54F34' }}>Solutions</Link>
              <a href="/landing#contact" className="sppio-nav-item">Briefing</a>
            </nav>

            <div className="sppio-header-actions">
              <Link to="/login" className="sppio-btn-ghost">
                Console Sign In
              </Link>
              <a href="/landing#contact" className="sppio-btn-primary">
                Request Briefing
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* ---------------- Hero Section ---------------- */}
      <section className="sppio-hero-section" style={{ padding: '72px 0 80px' }}>
        <div className="sppio-container">
          <div className="sppio-kicker-badge">
            <span className="sppio-kicker-dot" />
            <span>Open Aperture · Institutional Solutions</span>
          </div>

          <h1 className="sppio-hero-headline" style={{ maxWidth: '820px' }}>
            Built for national scale.<br />
            <span className="sppio-highlight">Engineered for absolute certainty.</span>
          </h1>

          <p className="sppio-hero-lead" style={{ maxWidth: '720px' }}>
            From nation-wide competitive examinations to university campus enclaves and professional licensure boards. Discover how SPPIO secures high-stakes assessments across the globe.
          </p>

          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '24px' }}>
            <a href="#solutions-grid" className="sppio-btn-primary">
              Explore Solutions ↓
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
              <h2 className="sppio-section-title">Tailored Institutional Deployments</h2>
            </div>
            <p className="sppio-section-desc">
              Every deployment leverages the same uncompromising hardware-rooted foundation, customized for your organizational governance.
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
              Estimate concurrent station throughput, candidate capacity, and cryptographic ledger requirements.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '48px', alignItems: 'center' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
              <div>
                <label style={{ display: 'flex', justifyContent: 'space-between', fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
                  <span>Concurrent Testing Stations:</span>
                  <span style={{ color: '#FFAE99', fontFamily: 'monospace', fontSize: '16px' }}>{stationCount} Stations</span>
                </label>
                <input
                  type="range"
                  min="50"
                  max="5000"
                  step="50"
                  value={stationCount}
                  onChange={(e) => setStationCount(Number(e.target.value))}
                  style={{ width: '100%', accentColor: '#B54F34', cursor: 'pointer' }}
                />
              </div>

              <div>
                <label style={{ display: 'flex', justifyContent: 'space-between', fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
                  <span>Testing Centers:</span>
                  <span style={{ color: '#FFAE99', fontFamily: 'monospace', fontSize: '16px' }}>{centerCount} Centers</span>
                </label>
                <input
                  type="range"
                  min="1"
                  max="50"
                  step="1"
                  value={centerCount}
                  onChange={(e) => setCenterCount(Number(e.target.value))}
                  style={{ width: '100%', accentColor: '#B54F34', cursor: 'pointer' }}
                />
              </div>

              <div style={{ fontSize: '13px', color: '#A69BA9', lineHeight: 1.6 }}>
                💡 <em>All stations run in local offline-first isolation. No central network bottleneck occurs even if hundreds of stations submit simultaneously.</em>
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
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>Candidates / 3 shifts</span>
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
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>Chained audit blocks per day</span>
                </div>

                <div>
                  <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    Cryptographic Ledger Storage
                  </span>
                  <div style={{ fontSize: '32px', fontWeight: 800, color: '#FFFFFF', margin: '6px 0 2px' }}>
                    ~{estimatedLedgerMB} MB
                  </div>
                  <span style={{ fontSize: '12px', color: '#A69BA9' }}>Extremely lightweight</span>
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
                <li><a href="/landing#contact">Schedule Consultation</a></li>
              </ul>
            </div>
          </div>

          <div className="sppio-footer-bottom">
            <div>© 2026 SPPIO Systems Enclave. All rights reserved. Open Aperture architecture.</div>
            <div className="sppio-legal-links">
              <Link to="/landing">Platform Home</Link>
              <a href="#top" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Back to Top ↑</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
