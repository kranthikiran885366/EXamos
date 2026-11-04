import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function ArchitecturePage() {
  const [activeStep, setActiveStep] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const quoteSteps = [
    {
      step: '01 / Cold Boot Silicon Attestation',
      title: 'SPPIO-TrustEngine™ Hardware Attestation',
      desc: 'A supported platform can measure selected firmware and boot components. Coverage and verification depend on hardware, firmware configuration, and the policy used by the deployment.',
      boundary: 'SPPIO-TrustEngine™ Silicon Roots',
      enforcement: 'Hardware-Enforced State Hashing',
      status: 'CONFIGURATION-DEPENDENT',
      compliance: 'Certification evidence not published',
    },
    {
      step: '02 / Peripheral & Port Lockdown',
      title: 'SPPIO-PhysicalGuard™ Interface Control',
      desc: 'A deployment may apply peripheral allowlists or restrictions. Supported devices, enforcement behavior, and exceptions must be verified for the target workstation models.',
      boundary: 'SPPIO-PhysicalGuard™ Port Whitelist',
      enforcement: 'Deterministic Device Whitelisting',
      status: 'CONFIGURATION-DEPENDENT',
      compliance: 'Deployment configuration required',
    },
    {
      step: '03 / Single-Task Graphical Enclave',
      title: 'SPPIO-Isolation™ Base OS & Kiosk™ Sandbox',
      desc: 'The intended station profile uses a dedicated assessment environment. Isolation behavior depends on the selected image, device, and configured policies and should be tested before operational use.',
      boundary: 'SPPIO-Isolation™ Base OS & Kiosk™',
      enforcement: 'Zero-Escape Application Sandbox',
      status: 'DEPLOYMENT-DEPENDENT',
      compliance: 'Behavior depends on deployment profile',
    },
    {
      step: '04 / Vision Intelligence & Code Forensics',
      title: 'SPPIO-Proctor™ & SPPIO-Forensics™ Engine',
      desc: 'Optional monitoring and event-capture features depend on the enabled product modules, consent, and retention policy. Verify data flows and retention with the institution before use.',
      boundary: 'SPPIO-Proctor™ & Forensics™ Telemetry',
      enforcement: 'Client-Side AI Sensor Pipeline',
      status: 'POLICY-DEPENDENT',
      compliance: 'Data handling scope not documented here',
    },
  ];

  const threatMatrix = [
    {
      threat: 'Host OS Escape & Multitasking',
      legacy: 'Software lockdown browser runs atop vulnerable Windows/macOS with background task exploits.',
      sppio: 'A dedicated station image is intended to limit access to unrelated host functions; test the supported hardware and image configuration.',
      status: 'DESIGN CONTROL',
    },
    {
      threat: 'Virtual Machine / Sandbox Evasion',
      legacy: 'Easily tricked by patched hypervisors, nested virtualization, and GPU pass-through hooks.',
      sppio: 'Platform measurements may help identify unsupported or changed boot states where the hardware and policy support them.',
      status: 'HARDWARE-DEPENDENT',
    },
    {
      threat: 'Hardware Keyloggers & Secondary Displays',
      legacy: 'OS drivers automatically mount USBs and external display splitters without detection.',
      sppio: 'Peripheral restrictions are intended to reduce selected device risks; verify which devices and ports are covered.',
      status: 'POLICY-DEPENDENT',
    },
    {
      threat: 'Recruitment Proxy Fraud & AI Assistance',
      legacy: 'Remote proctors cannot verify if candidate is typing or receiving whisper coaching / off-screen ChatGPT answers.',
      sppio: 'Optional monitoring and review tools may provide signals for human assessment; they do not prove misconduct on their own.',
      status: 'REVIEW SIGNALS',
    },
    {
      threat: 'Post-Exam Retrospective Alteration',
      legacy: 'Standard database updates where rogue operators can alter responses or delete audit logs.',
      sppio: 'Hash-linked records can make certain modifications detectable. Independent backups and protected signing keys remain necessary.',
      status: 'AUDIT CONTROL',
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
              <Link to="/solutions" className="sppio-nav-item">Solutions</Link>
              <Link to="/landing#capabilities" className="sppio-nav-item">Capabilities</Link>
              <Link to="/architecture" className="sppio-nav-item" style={{ color: '#B54F34' }}>Architecture</Link>
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
              <button type="button" className="sppio-mobile-toggle" aria-label="Toggle navigation" aria-expanded={mobileMenuOpen} aria-controls="architecture-mobile-navigation" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  {mobileMenuOpen ? <path d="M18 6L6 18M6 6l12 12" /> : <path d="M3 12h18M3 6h18M3 18h18" />}
                </svg>
              </button>
            </div>
          </div>
          {mobileMenuOpen && <nav id="architecture-mobile-navigation" className="sppio-mobile-drawer" aria-label="Mobile navigation">
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
            <span>Open Aperture · Corporate Recruitment &amp; Institutional Architecture</span>
          </div>

          <h1 className="sppio-hero-headline" style={{ maxWidth: '820px' }}>
            Zero-trust execution.<br />
            <span className="sppio-highlight">Silicon-rooted recruitment &amp; assessment integrity.</span>
          </h1>

          <p className="sppio-hero-lead" style={{ maxWidth: '720px' }}>
            An overview of the intended system boundaries and controls for assessment workstations. Actual protections depend on supported hardware, deployment configuration, and the policies enabled for each institution.
          </p>

          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '24px' }}>
            <a href="#attestation" className="sppio-btn-primary">
              Inspect Attestation Protocol ↓
            </a>
            <a href="#threat-model" className="sppio-btn-ghost">
              Review Threat Model
            </a>
          </div>
        </div>
      </section>

      {/* ---------------- Section 1: Attestation Sequence ---------------- */}
      <section id="attestation" className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Attestation Engine</span>
              <h2 className="sppio-section-title">Cryptographic Boot Verification Sequence</h2>
            </div>
            <p className="sppio-section-desc">
              Every station undergoes rigorous physical cryptoprocessor validation before allowing any candidate interaction.
            </p>
          </div>

          <div className="sppio-capabilities-layout">
            {/* Step selector */}
            <div className="sppio-cap-nav">
              {quoteSteps.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  className={`sppio-cap-tab ${activeStep === idx ? 'active' : ''}`}
                  aria-pressed={activeStep === idx}
                  onClick={() => setActiveStep(idx)}
                >
                  <span className="sppio-cap-number">0{idx + 1}</span>
                  <div className="sppio-cap-summary">
                    <h4>{s.title}</h4>
                    <p>{s.step}</p>
                  </div>
                </button>
              ))}
            </div>

            {/* Display box */}
            <div className="sppio-cap-display">
              <div className="sppio-display-tag">
                <SppioSymbol size={16} accent="#B54F34" />
                <span>Protocol Phase {activeStep + 1} of 4</span>
              </div>
              <h3 className="sppio-display-headline">{quoteSteps[activeStep].title}</h3>
              <p className="sppio-display-body">{quoteSteps[activeStep].desc}</p>

              <div style={{ background: '#302337', borderRadius: '12px', padding: '24px', color: '#F6F2ED', border: '1px solid #48394F' }}>
                <div style={{ color: '#FFAE99', marginBottom: '16px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                  Security Domain &amp; Enforcement Assurance
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                  <div style={{ background: 'rgba(255, 255, 255, 0.04)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em' }}>Security Domain</div>
                    <div style={{ fontSize: '13.5px', fontWeight: 600, color: '#FFFFFF', marginTop: '6px' }}>{quoteSteps[activeStep].boundary}</div>
                  </div>
                  <div style={{ background: 'rgba(255, 255, 255, 0.04)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em' }}>Enforcement Model</div>
                    <div style={{ fontSize: '13.5px', fontWeight: 600, color: '#FFFFFF', marginTop: '6px' }}>{quoteSteps[activeStep].enforcement}</div>
                  </div>
                  <div style={{ background: 'rgba(255, 255, 255, 0.04)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em' }}>Verification Status</div>
                    <div style={{ fontSize: '13.5px', fontWeight: 700, color: '#4ADE80', marginTop: '6px' }}>{quoteSteps[activeStep].status}</div>
                  </div>
                  <div style={{ background: 'rgba(255, 255, 255, 0.04)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em' }}>Certification scope</div>
                    <div style={{ fontSize: '13.5px', fontWeight: 600, color: '#FFFFFF', marginTop: '6px' }}>{quoteSteps[activeStep].compliance}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- Section 2: Threat Matrix ---------------- */}
      <section id="threat-model" className="sppio-section" style={{ background: '#FFFFFF' }}>
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Threat Model &amp; Defense</span>
              <h2 className="sppio-section-title">Controls and threat considerations</h2>
            </div>
            <p className="sppio-section-desc">
              No single control eliminates every attack path. The table describes intended control areas, not independent test results or a guarantee of prevention.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {threatMatrix.map((tm, idx) => (
              <div
                key={idx}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1.2fr 1.4fr 1.4fr 0.8fr',
                  gap: '24px',
                  alignItems: 'center',
                  padding: '24px',
                  background: '#F6F2ED',
                  border: '1px solid #DCD5D2',
                  borderRadius: '12px',
                }}
              >
                <div>
                  <strong style={{ fontSize: '16px', color: '#302337', display: 'block', marginBottom: '4px' }}>
                    {tm.threat}
                  </strong>
                </div>
                <div>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#C0392B', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: '4px' }}>
                    Traditional Lockdowns
                  </span>
                  <p style={{ margin: 0, fontSize: '13px', color: '#756F79', lineHeight: 1.45 }}>{tm.legacy}</p>
                </div>
                <div>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#1B7A4B', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: '4px' }}>
                    SPPIO Enclave
                  </span>
                  <p style={{ margin: 0, fontSize: '13px', color: '#302337', lineHeight: 1.45, fontWeight: 550 }}>{tm.sppio}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="sppio-tag" style={{ background: '#302337', color: '#FFAE99', borderColor: '#48394F', fontSize: '11px' }}>
                    {tm.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------- Section 3: Chained Ledger ---------------- */}
      <section id="ledger" className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-company-grid">
            <div className="sppio-company-text">
              <span className="sppio-section-eyebrow">Cryptographic Non-Repudiation</span>
              <h2 className="sppio-section-title" style={{ color: '#302337' }}>
                Audit Event Chain
              </h2>
              <p className="sppio-company-lead" style={{ color: '#756F79' }}>
                A hash-linked audit chain can make certain record changes detectable. It does not by itself prevent deletion, guarantee non-repudiation, or replace independently protected backups and signing keys. The implementation and evidence available for this deployment should be reviewed before relying on it.
              </p>

              <div className="sppio-pillars">
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong style={{ color: '#302337' }}>Truncation Anchors</strong>
                    <p style={{ color: '#756F79' }}>Checkpoint signing and key custody depend on the configured deployment. Algorithm and assurance evidence are not published here.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong style={{ color: '#302337' }}>Offline CLI Verifier</strong>
                    <p style={{ color: '#756F79' }}>Independent audit verification tool runs offline without network connectivity.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong style={{ color: '#302337' }}>Two-Person Dual-Custody</strong>
                    <p style={{ color: '#756F79' }}>Separation of duties requires dual administrative sign-off for policy changes.</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="sppio-geometry-study" style={{ background: '#302337', color: '#F6F2ED', borderColor: '#48394F' }}>
              <SppioSymbol size={64} accent="#B54F34" />
              <h4 style={{ fontSize: '18px', fontWeight: 800, marginTop: '20px', marginBottom: '8px' }}>
                Tamper-Evident Ledger Integrity
              </h4>
              <p style={{ fontSize: '13.5px', color: '#F6F2ED', margin: '12px 0 20px', lineHeight: 1.6, maxWidth: '320px', opacity: 0.9 }}>
                Conceptual audit-chain design. Checkpoint availability and key protection depend on deployment configuration.
              </p>
              <div style={{ display: 'inline-flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
                <span className="sppio-tag" style={{ background: '#48394F', color: '#FFFFFF', borderColor: '#5C4A65' }}>Sequential Event Hash-Chain</span>
                <span className="sppio-tag" style={{ background: '#48394F', color: '#FFFFFF', borderColor: '#5C4A65' }}>Cryptographic Checkpoints</span>
                <span className="sppio-tag" style={{ background: '#48394F', color: '#FFFFFF', borderColor: '#5C4A65' }}>Dual-Operator Sign-Off</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="deployment" className="sppio-section" style={{ background: '#FFFFFF' }}>
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Deployment boundaries</span>
              <h2 className="sppio-section-title">System flow and operational prerequisites</h2>
            </div>
            <p className="sppio-section-desc">Conceptual architecture only; confirm supported configurations and operational behavior with the deployment team.</p>
          </div>
          <div role="img" aria-label="Conceptual flow: candidate kiosk connects through a gateway to policy services and storage; audit events cross a separately managed audit boundary." style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px', alignItems: 'center' }}>
            {['Candidate kiosk', 'Gateway', 'Policy service', 'Application storage', 'Audit boundary'].map((node, index) => (
              <div key={node} style={{ border: '1px solid #DCD5D2', borderRadius: '10px', padding: '18px 12px', textAlign: 'center', background: index === 4 ? '#302337' : '#F6F2ED', color: index === 4 ? '#FFFFFF' : '#302337', fontWeight: 700 }}>
                {node}
                {index < 4 && <span aria-hidden="true" style={{ display: 'block', marginTop: '8px', color: '#B54F34' }}>↓</span>}
              </div>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginTop: '20px' }}>
            <div><h3>Before deployment</h3><p>Validate supported workstation models, firmware settings, required network endpoints, site connectivity, data retention, and administrator responsibilities for the chosen profile.</p></div>
            <div><h3>Offline behavior</h3><p>Offline availability and later synchronization depend on the configured product profile. Confirm which tasks can continue offline, how data is reconciled, and how conflicts are handled.</p></div>
            <div><h3>Attestation failure</h3><p>Confirm the configured launch gate, retry limits, operator escalation, and candidate help path for an attestation failure. This page does not claim a universal retry or recovery behavior.</p></div>
          </div>
          <p style={{ marginTop: '20px', padding: '14px', background: '#FBF9F7', border: '1px solid #DCD5D2', borderRadius: '8px', fontSize: '13px', lineHeight: 1.6 }}>
            No third-party certification report or independent assurance evidence is published on this page. References to cryptographic controls describe design concepts, not a certification or guarantee.
          </p>
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
              <h5>Public Architecture</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/landing">Platform Overview</Link></li>
                <li><Link to="/architecture">Silicon Attestation</Link></li>
                <li><Link to="/solutions">Enterprise Solutions</Link></li>
              </ul>
            </div>
            <div className="sppio-footer-col">
              <h5>Governance</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/architecture#threat-model">Threat Model</Link></li>
                <li><Link to="/architecture#ledger">Audit Chaining</Link></li>
                <li><a href="/landing#contact">Security Briefing</a></li>
              </ul>
            </div>
            <div className="sppio-footer-col">
              <h5>Console Access</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/login" style={{ color: '#FFAE99', fontWeight: 700 }}>Console Sign In →</Link></li>
                <li><Link to="/candidate-login">Candidate Station Login</Link></li>
                <li><Link to="/register-institution">Institution Onboarding</Link></li>
                <li><Link to="/register-institution?tab=track">Track Application</Link></li>
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
