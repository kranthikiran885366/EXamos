import { useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function ArchitecturePage() {
  const [activeStep, setActiveStep] = useState(0);

  const quoteSteps = [
    {
      step: '01 / Power-On & PCR Measurement',
      title: 'UEFI & Core Root of Trust for Measurement (CRTM)',
      desc: 'Upon cold boot, the CPU executes the CRTM in microcode. As firmware stages load, SHA-256 digests of the UEFI code, Secure Boot DB/DBX keys, and bootloader binary are extended into TPM registers PCR-0, PCR-4, and PCR-7.',
      code: 'PCR[0] = SHA256(PCR[0] || CoreFirmwareDigest)\nPCR[4] = SHA256(PCR[4] || BootManagerDigest)\nPCR[7] = SHA256(PCR[7] || SecureBootPolicyDigest)',
    },
    {
      step: '02 / Nonce Injection & Hardware Quote',
      title: 'Attestation Nonce Challenge',
      desc: 'The supervisory node injects an unpredictable 32-byte cryptographic nonce. The physical TPM 2.0 cryptoprocessor bundles current PCR values with the nonce and signs the payload using its factory Endorsement Key (EK).',
      code: 'TPM2_Quote(EK_Handle, QualifyingData=Nonce, PCR_Mask=[0,4,7])\n=> Signature: ECDSA_P256(Hash(PCRs || Nonce), EK_PrivKey)',
    },
    {
      step: '03 / Golden Policy Verification',
      title: 'Cryptographic Policy Validation',
      desc: 'The server verifies the signature against the verified TPM endorsement certificate and validates PCR hashes against golden release manifests. If a single byte differs (bootkit, rootkit, or tampered kernel), the station is quarantined.',
      code: 'VerifyCertificate(EK_Cert, TPM_Manufacturer_RootCA)\nAssert(Hash_PCR0 == Golden_PCR0 && Hash_PCR7 == Golden_PCR7)\nStatus: ENCLAVE_SEALED_VALID',
    },
    {
      step: '04 / Cage-Wayland Compositor Handshake',
      title: 'Unprivileged Display Lockdown',
      desc: 'Once authenticated, the Linux kernel boots read-only SquashFS with Cage-Wayland compositor. Virtual terminals (VT-1..6), hotkeys, and unauthorized USB endpoints are suppressed before candidate login commences.',
      code: 'Exec: cage -d -- examos-kiosk-runtime\nKernel: usbcore.authorized_default=0\nVT_Switch: IOCTL(VT_LOCKSWITCH) active',
    },
  ];

  const threatMatrix = [
    {
      threat: 'Host OS Escape & Multitasking',
      legacy: 'Software lockdown browser runs atop vulnerable Windows/macOS with background task exploits.',
      sppio: 'Bare-metal boot into dedicated Linux Cage-Wayland compositor; zero underlying host OS exists.',
      status: 'PREVENTED',
    },
    {
      threat: 'Virtual Machine / Sandbox Evasion',
      legacy: 'Easily tricked by patched hypervisors, nested virtualization, and GPU pass-through hooks.',
      sppio: 'Physical TPM 2.0 silicon attestation validates hardware Endorsement Key bound to physical motherboard.',
      status: 'VERIFIED SILICON',
    },
    {
      threat: 'Hardware Keyloggers & USB Storage',
      legacy: 'OS drivers automatically mount USB drives; software monitoring detects intrusions after the fact.',
      sppio: 'Kernel-level USB whitelist permits exclusively known input devices; mass storage endpoints are rejected in kernel.',
      status: 'BLOCKED AT KERNEL',
    },
    {
      threat: 'Post-Exam Retrospective Alteration',
      legacy: 'Standard database updates where rogue operators can alter responses or delete audit logs.',
      sppio: 'HMAC-SHA-256 chained ledger with dual-custody authorization; any alteration breaks all downstream hashes.',
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
            <span>Open Aperture · Technical Architecture</span>
          </div>

          <h1 className="sppio-hero-headline" style={{ maxWidth: '820px' }}>
            Zero-trust execution.<br />
            <span className="sppio-highlight">Silicon-rooted hardware attestation.</span>
          </h1>

          <p className="sppio-hero-lead" style={{ maxWidth: '720px' }}>
            A comprehensive technical breakdown of how SPPIO enforces station isolation, cryptographically authenticates physical device integrity, and guarantees tamper-evident examination delivery.
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

              <div style={{ background: '#302337', borderRadius: '10px', padding: '20px', color: '#F6F2ED', fontFamily: 'monospace', fontSize: '13px', lineHeight: 1.6, overflowX: 'auto', border: '1px solid #48394F' }}>
                <div style={{ color: '#FFAE99', marginBottom: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Execution Manifest
                </div>
                <pre style={{ margin: 0 }}>{quoteSteps[activeStep].code}</pre>
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
                Open Aperture Ledger Formula
              </h4>
              <p style={{ fontFamily: 'monospace', fontSize: '14px', color: '#FFAE99', margin: '12px 0 20px' }}>
                Block[n] = SHA-256(Block[n-1].Hash + EventPayload + Timestamp + Nonce)
              </p>
              <div style={{ display: 'inline-flex', gap: '8px' }}>
                <span className="sppio-tag" style={{ background: '#48394F', color: '#FFFFFF', borderColor: '#5C4A65' }}>RFC 6238 TOTP</span>
                <span className="sppio-tag" style={{ background: '#48394F', color: '#FFFFFF', borderColor: '#5C4A65' }}>ECDSA P-256</span>
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
