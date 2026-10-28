import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function ArchitecturePage() {
  const [activeStep, setActiveStep] = useState(0);

  const quoteSteps = [
    {
      step: '01 / Cold Boot Silicon Attestation',
      title: 'SPPIO-TrustEngine™ Hardware Attestation',
      desc: 'Upon station power-on, platform measurement routines execute in silicon microcode. Firmware stages and bootloader components are cryptographically measured and isolated before execution begins, ensuring zero firmware tampering or hypervisor evasion.',
      boundary: 'SPPIO-TrustEngine™ Silicon Roots',
      enforcement: 'Hardware-Enforced State Hashing',
      status: 'VERIFIED AT COLD BOOT',
      compliance: 'FIPS 140-3 Hardware Boundary',
    },
    {
      step: '02 / Peripheral & Port Lockdown',
      title: 'SPPIO-PhysicalGuard™ Interface Control',
      desc: 'Enforces kernel-level peripheral whitelist policies. Suppresses unauthorized USB keystroke injectors, external storage, secondary display splitters (HDMI/DP), and Bluetooth devices to prevent recruitment prompt injection.',
      boundary: 'SPPIO-PhysicalGuard™ Port Whitelist',
      enforcement: 'Deterministic Device Whitelisting',
      status: 'INTERFACES SEALED',
      compliance: 'Strict Peripheral Lockdown',
    },
    {
      step: '03 / Single-Task Graphical Enclave',
      title: 'SPPIO-Isolation™ Base OS & Kiosk™ Sandbox',
      desc: 'The station initializes an immutable read-only system running a dedicated single-application evaluation environment. OS escape combinations, background multitasking, and unauthorized communications are suppressed during candidate coding rounds.',
      boundary: 'SPPIO-Isolation™ Base OS & Kiosk™',
      enforcement: 'Zero-Escape Application Sandbox',
      status: 'ENCLAVE ACTIVE',
      compliance: 'Zero Residual Host Footprint',
    },
    {
      step: '04 / Vision Intelligence & Code Forensics',
      title: 'SPPIO-Proctor™ & SPPIO-Forensics™ Engine',
      desc: 'Captures continuous on-device sensor intelligence: multi-face detection, acoustic anomaly tracking, and millisecond keystroke velocity telemetry for post-assessment technical viva defense and code construction replay.',
      boundary: 'SPPIO-Proctor™ & Forensics™ Telemetry',
      enforcement: 'Client-Side AI Sensor Pipeline',
      status: 'SENSORS & FORENSICS ACTIVE',
      compliance: 'Privacy-Preserving On-Device AI',
    },
  ];

  const threatMatrix = [
    {
      threat: 'Host OS Escape & Multitasking',
      legacy: 'Software lockdown browser runs atop vulnerable Windows/macOS with background task exploits.',
      sppio: 'SPPIO-Isolation™ Base OS provides a bare-metal boot into a dedicated single-task graphical enclave; zero host OS exists.',
      status: 'PREVENTED',
    },
    {
      threat: 'Virtual Machine / Sandbox Evasion',
      legacy: 'Easily tricked by patched hypervisors, nested virtualization, and GPU pass-through hooks.',
      sppio: 'SPPIO-TrustEngine™ silicon attestation validates cryptographic identity bound to the physical motherboard.',
      status: 'VERIFIED SILICON',
    },
    {
      threat: 'Hardware Keyloggers & Secondary Displays',
      legacy: 'OS drivers automatically mount USBs and external display splitters without detection.',
      sppio: 'SPPIO-PhysicalGuard™ rejects unauthorized USB keystroke injection and suppresses unapproved external video splitters.',
      status: 'BLOCKED AT KERNEL',
    },
    {
      threat: 'Recruitment Proxy Fraud & AI Assistance',
      legacy: 'Remote proctors cannot verify if candidate is typing or receiving whisper coaching / off-screen ChatGPT answers.',
      sppio: 'SPPIO-Proctor™ gaze tracking combined with SPPIO-Forensics™ keystroke playback and viva defense tools expose proxy cheating.',
      status: 'FORENSICS REPLAY',
    },
    {
      threat: 'Post-Exam Retrospective Alteration',
      legacy: 'Standard database updates where rogue operators can alter responses or delete audit logs.',
      sppio: 'SPPIO-Ledger™ continuous cryptographic chain with dual-custody authorization; any alteration breaks downstream anchors.',
      status: 'CRYPTOGRAPHIC CHAIN',
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
              <Link to="/architecture" className="sppio-nav-item" style={{ color: '#B54F34' }}>Architecture</Link>
              <Link to="/solutions" className="sppio-nav-item">Solutions</Link>
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
            <span>Open Aperture · Corporate Recruitment &amp; Institutional Architecture</span>
          </div>

          <h1 className="sppio-hero-headline" style={{ maxWidth: '820px' }}>
            Zero-trust execution.<br />
            <span className="sppio-highlight">Silicon-rooted recruitment &amp; assessment integrity.</span>
          </h1>

          <p className="sppio-hero-lead" style={{ maxWidth: '720px' }}>
            A comprehensive technical breakdown of how the SPPIO product suite—from SPPIO-Isolation™ Base OS to SPPIO-TrustEngine™, SPPIO-Proctor™, and SPPIO-Forensics™—enforces station lockdown, eliminates hiring fraud, and guarantees tamper-evident assessment delivery.
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
                    <div style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.06em' }}>Compliance Assurance</div>
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
              <h2 className="sppio-section-title">Architectural Immunity vs. Traditional Software</h2>
            </div>
            <p className="sppio-section-desc">
              Why software-only desktop lockdown applications fail, and how SPPIO’s bare-metal enclave eliminates attack vectors.
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
      <section className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-company-grid">
            <div className="sppio-company-text">
              <span className="sppio-section-eyebrow">Cryptographic Non-Repudiation</span>
              <h2 className="sppio-section-title" style={{ color: '#302337' }}>
                The Immutable Chained Ledger
              </h2>
              <p className="sppio-company-lead" style={{ color: '#756F79' }}>
                Every supervisory action, candidate answer commit, anomaly flag, and administrative approval is chained sequentially. No record can be deleted or modified retroactively without invalidating all subsequent hash anchors.
              </p>

              <div className="sppio-pillars">
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong style={{ color: '#302337' }}>Truncation Anchors</strong>
                    <p style={{ color: '#756F79' }}>Periodic RSA-4096 signed checkpoints prevent log truncation or rollbacks.</p>
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
                Continuous cryptographic state validation with sequential event chain integrity and hardware-signed checkpoint anchors.
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
                <li><Link to="/architecture">Audit Chaining</Link></li>
                <li><a href="/landing#contact">Security Briefing</a></li>
              </ul>
            </div>
            <div className="sppio-footer-col">
              <h5>Console Access</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/login" style={{ color: '#FFAE99', fontWeight: 700 }}>Console Sign In →</Link></li>
                <li><Link to="/login">Candidate Station Login</Link></li>
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
