import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import SppioLogo, { SppioSymbol } from './SppioLogo';

export default function LandingPage() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Navigation state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [activeTechLayer, setActiveTechLayer] = useState(0);
  const [showSpecModal, setShowSpecModal] = useState(false);
  const [cockpitTab, setCockpitTab] = useState('command'); // 'command' | 'kiosk' | 'forensics' | 'physical'
  const [suiteCategory, setSuiteCategory] = useState('all'); // 'all' | 'endpoint' | 'intelligence' | 'cloud'

  // Contact form state
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    organization: '',
    fleetSize: '50-500',
    message: '',
  });
  const [formError, setFormError] = useState('');
  const [formNotice, setFormNotice] = useState('');
  const [contactErrors, setContactErrors] = useState({});

  const handleFormSubmit = (e) => {
    e.preventDefault();
    const errors = {};
    if (!formData.name.trim()) errors.name = 'Enter your name.';
    if (!formData.organization.trim()) errors.organization = 'Enter your organization.';
    if (!formData.email.trim()) errors.email = 'Enter your email address.';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) errors.email = 'Enter a valid email address.';
    if (Object.keys(errors).length) {
      setContactErrors(errors);
      setFormError('Review the required fields below.');
      setTimeout(() => document.getElementById(`contact-${Object.keys(errors)[0]}`)?.focus(), 0);
      return;
    }
    setContactErrors({});
    setFormError('');
    const subject = `SPPIO technical briefing request — ${formData.organization.trim()}`;
    const body = [
      `Name: ${formData.name.trim()}`,
      `Email: ${formData.email.trim()}`,
      `Organization: ${formData.organization.trim()}`,
      `Testing station scale: ${formData.fleetSize}`,
      '',
      formData.message.trim(),
    ].join('\n');
    window.location.href = `mailto:briefings@sppio.io?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    setFormNotice('An email draft was requested in your email app. It has not been sent; review and send it there.');
  };

  const productSuite = [
    {
      name: 'SPPIO-Isolation™ Base OS',
      category: 'endpoint',
      tag: 'Operating System',
      tagline: 'Bare-Metal Secure Assessment OS',
      desc: 'A dedicated assessment operating-system concept for supported workstations. Isolation capabilities and update behavior depend on the released image and deployment configuration.',
      hiringRole: 'Intended to limit access to unrelated host applications during supported assessment workflows.',
    },
    {
      name: 'SPPIO-PhysicalGuard™',
      category: 'endpoint',
      tag: 'Hardware Lockdown',
      tagline: 'Peripheral Port & Interface Control',
      desc: 'Kernel-level enforcement engine that suppresses unauthorized USB keystroke injectors, external storage, secondary display splitters (HDMI/DP), and Bluetooth eavesdropping devices.',
      hiringRole: 'Peripheral controls are intended to restrict configured device classes; supported devices must be verified.',
    },
    {
      name: 'SPPIO-Proctor™',
      category: 'intelligence',
      tag: 'Sensors & Vision',
      tagline: 'Vision & Multi-Sensor Intelligence',
      desc: 'Real-time client-side sensor intelligence analyzing continuous face presence, multi-face presence, gaze diversion, and acoustic anomalies without sending raw video streams off-premise.',
      hiringRole: 'Optional monitoring can provide signals for review; it cannot establish misconduct on its own.',
    },
    {
      name: 'SPPIO-Kiosk™ Sandbox',
      category: 'endpoint',
      tag: 'Application Runtime',
      tagline: 'Deterministic Single-Task Kiosk',
      desc: 'Secure candidate evaluation and IDE sandbox. Enforces strict clipboard isolation, virtual desktop suppression, hotkey locks, and a zero-leak RAM-only runtime environment.',
      hiringRole: 'Provides a configured assessment workspace; verify the available restrictions for the target device.',
    },
    {
      name: 'SPPIO-TrustEngine™',
      category: 'endpoint',
      tag: 'Hardware Attestation',
      tagline: 'Silicon Cryptographic Attestation',
      desc: 'Authenticates workstation hardware identity and platform firmware measurements against verified golden baselines before issuing assessment or interview tokens.',
      hiringRole: 'Hardware measurement features depend on supported hardware and deployment policy.',
    },
    {
      name: 'SPPIO-Ledger™',
      category: 'intelligence',
      tag: 'Audit Stream',
      tagline: 'Tamper-Evident Audit Chain',
      desc: 'Continuous cryptographic ledger chaining candidate answer commits, supervisor actions, proctoring alerts, and scoring decisions into non-repudiable sequential records.',
      hiringRole: 'Provides enterprise talent acquisition with mathematically defensible, audit-ready compliance proof for equal-opportunity hiring.',
    },
    {
      name: 'SPPIO-Forensics™',
      category: 'intelligence',
      tag: 'Traceability & Viva',
      tagline: 'Code Construction & Viva Defense Engine',
      desc: 'Millisecond keystroke velocity telemetry, time-lapse code replay, and structured technical viva examination tooling for senior engineering evaluations.',
      hiringRole: 'Enables engineering leads to replay how candidate code was constructed line-by-line and conduct structured viva defenses.',
    },
    {
      name: 'SPPIO-Core™ Server & Storage',
      category: 'cloud',
      tag: 'Enterprise Backend',
      tagline: 'High-Throughput Assessment Backend',
      desc: 'Enterprise assessment orchestrator with TLS-authenticated storage, automated batch submission reconciliation, and multi-tenant corporate partition models.',
      hiringRole: 'Scale and recovery characteristics depend on the deployment profile and must be validated for each workload.',
    },
    {
      name: 'SPPIO-Command™ Console',
      category: 'cloud',
      tag: 'Web Portal',
      tagline: 'Unified Recruiter & Proctoring Portal',
      desc: 'Role-gated centralized web portal for corporate recruiters, proctors, college administrators, and technical interviewers with live fleet telemetry and candidate tracking.',
      hiringRole: 'Gives recruitment teams a live cockpit for real-time candidate proctoring, session flags, and one-click candidate scorecards.',
    },
  ];

  const capabilities = [
    {
      number: '01',
      tag: 'Hardware Security',
      title: 'Hardware Cryptographic Attestation',
      summary: 'Physical device attestation authenticated against verified golden release policies.',
      description:
        'Where supported, platform measurements can be compared with configured release policies. Coverage depends on hardware and the verification policy; this page does not claim that every boot threat is detected.',
      specs: [
        { label: 'Attestation Root', value: 'SPPIO-TrustEngine™ Silicon' },
        { label: 'Integrity Check', value: 'Golden Policy Verification' },
        { label: 'Replay Protection', value: 'Anti-Replay Challenge Protocol' },
        { label: 'Attestation Latency', value: 'Deployment-dependent; no benchmark published' },
      ],
    },
    {
      number: '02',
      tag: 'Station Lockdown',
      title: 'Configured Station Enclave',
      summary: 'Dedicated display environment enforcing single-application containment.',
      description:
        'Built on SPPIO-Isolation™ Base OS and SPPIO-Kiosk™ Sandbox, candidate workstations run in complete isolation. Virtual terminal switching, host key shortcuts, secondary display mirroring, clipboard sharing, and unapproved peripheral access are blocked at the operating system foundation.',
      specs: [
        { label: 'Display Engine', value: 'SPPIO-Kiosk™ Compositor' },
        { label: 'Base OS', value: 'SPPIO-Isolation™ Base OS' },
        { label: 'Peripheral controls', value: 'Configured per supported device' },
        { label: 'Host Access', value: 'Zero Residual Host Footprint' },
      ],
    },
    {
      number: '03',
      tag: 'Audit Integrity',
      title: 'Hash-linked Audit Events',
      summary: 'Tamper-evident event chaining with strict separation of duties.',
      description:
        'Audit events may be hash-linked so selected changes can be detected. Hash chaining alone does not prevent deletion or guarantee non-repudiation; review key custody, backups, and verification evidence for the deployment.',
      specs: [
        { label: 'Ledger Engine', value: 'SPPIO-Ledger™ Cryptographic Chain' },
        { label: 'Approval Model', value: 'Two-Person Dual-Custody Controls' },
        { label: 'Code Forensics', value: 'SPPIO-Forensics™ Keystroke Replay' },
        { label: 'Certification evidence', value: 'Not published on this page' },
      ],
    },
    {
      number: '04',
      tag: 'Fleet Management',
      title: 'Distributed Fleet Orchestration',
      summary: 'Fleet management and policy controls depend on deployment configuration.',
      description:
        'Orchestrated through SPPIO-Command™ Console and SPPIO-Core™ Server & Storage, organizations manage thousands of concurrent testing stations across decentralized examination centers and campus recruitment drives. Resilient offline execution safeguards tests during network outages.',
      specs: [
        { label: 'Control Plane', value: 'SPPIO-Command™ Console Web Portal' },
        { label: 'Backend Scaling', value: 'SPPIO-Core™ Server & Storage' },
        { label: 'Proctoring Intelligence', value: 'SPPIO-Proctor™ Vision & Sensor' },
        { label: 'Offline and recovery behavior', value: 'Confirm for selected deployment profile' },
      ],
    },
  ];

  const techLayers = [
    {
      layer: 'LAYER 01',
      title: 'Silicon & Hardware Root',
      desc: 'SPPIO-TrustEngine™ and SPPIO-PhysicalGuard™ generate non-exportable cryptographic keys and enforce strict hardware peripheral port isolation at cold boot.',
      badge: 'SPPIO-TrustEngine™ / PhysicalGuard™',
    },
    {
      layer: 'LAYER 02',
      title: 'Kernel & Graphical Containment',
      desc: 'SPPIO-Isolation™ Base OS and SPPIO-Kiosk™ Sandbox boot read-only immutable environments suppressing virtual consoles, screen scraping, and unauthorized background processes.',
      badge: 'SPPIO-Isolation™ / Kiosk™',
    },
    {
      layer: 'LAYER 03',
      title: 'Vision & Forensics Intelligence',
      desc: 'SPPIO-Proctor™ and SPPIO-Forensics™ capture on-device biometric telemetry, gaze diversion, keystroke velocity patterns, and live code construction replay.',
      badge: 'SPPIO-Proctor™ / Forensics™',
    },
    {
      layer: 'LAYER 04',
      title: 'Server, Ledger & Web Command',
      desc: 'SPPIO-Core™ Server & Storage, SPPIO-Ledger™, and SPPIO-Command™ Console provide resilient cluster orchestration, cryptographic audit chaining, and recruiter dashboards.',
      badge: 'SPPIO-Core™ / Ledger™ / Command™',
    },
  ];

  const deployments = [
    {
      scope: 'Global Enterprise Tech Hiring',
      metric: 'Illustrative scenario',
      metricDesc: 'Example workflow only; not a customer result',
      title: 'Enterprise Technical Hiring & Viva Forensics',
      desc: 'A technical hiring program may combine configured assessment workstations, event review, and interviewer-led follow-up. This example does not represent a verified customer deployment or outcome.',
      tags: ['Corporate Recruitment', 'SPPIO-Forensics™', 'SPPIO-Proctor™', 'Anti-Proxy Verification'],
    },
    {
      scope: 'National assessment planning',
      metric: 'Illustrative scenario',
      metricDesc: 'Example workflow only; not a customer result',
      title: 'High-Assurance National Examination Enclave',
      desc: 'An examination program can evaluate supported boot and station policies, connectivity requirements, and submission reconciliation before deployment. Availability and controls must be tested for the target environment.',
      tags: ['Hardware Attestation', 'Station Controls', 'Connectivity Planning', 'Recovery Planning'],
    },
    {
      scope: 'University exam program',
      metric: 'Illustrative scenario',
      metricDesc: 'Example workflow only; not a customer result',
      title: 'Tamper-Evident Institutional Audit & Policy Governance',
      desc: 'An institution can review role separation, approval requirements, event retention, and audit exports against its own governance policy. No certification or audit outcome is implied.',
      tags: ['Role Separation', 'Audit Events', 'Access Controls', 'Evidence Review'],
    },
  ];

  return (
    <div id="top" tabIndex="-1" className="sppio-website">
      {/* ----------------- Header & Navigation ----------------- */}
      <header className="sppio-header" role="banner">
        <div className="sppio-container">
          <div className="sppio-header-inner">
            <Link to="/" className="sppio-brand-link" aria-label="SPPIO Home">
              <SppioLogo width={164} accent="#B54F34" ink="#302337" />
            </Link>

            <nav className="sppio-nav" aria-label="Primary navigation">
              <a href="#suite" className="sppio-nav-item">Products</a>
              <Link to="/solutions" className="sppio-nav-item">Solutions</Link>
              <a href="#capabilities" className="sppio-nav-item">Capabilities</a>
              <Link to="/architecture" className="sppio-nav-item">Architecture</Link>
              <a href="#deployments" className="sppio-nav-item">Deployments</a>
              <a href="#company" className="sppio-nav-item">Company</a>
            </nav>

            <div className="sppio-header-actions">
              <Link to="/register-institution" className="sppio-nav-item" style={{ color: '#B54F34', fontWeight: 700 }}>
                Institution Onboarding
              </Link>
              <Link to="/register-institution?tab=track" className="sppio-nav-item">Track Application</Link>
              <Link to="/login" className="sppio-btn-ghost">
                Sign In
              </Link>
              <a href="#contact" className="sppio-btn-primary">
                Request Briefing
              </a>
              <button
                type="button"
                className="sppio-mobile-toggle"
                aria-label="Toggle navigation"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              >
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  {mobileMenuOpen ? (
                    <path d="M18 6L6 18M6 6l12 12" />
                  ) : (
                    <path d="M3 12h18M3 6h18M3 18h18" />
                  )}
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="sppio-mobile-drawer" style={{ background: '#F6F2ED', borderBottom: '1px solid #DCD5D2', padding: '20px 32px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <a href="#suite" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Products</a>
              <Link to="/solutions" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Solutions</Link>
              <a href="#capabilities" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Capabilities</a>
              <Link to="/architecture" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Architecture</Link>
              <a href="#deployments" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Deployments</a>
              <a href="#company" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Company</a>
              <a href="#contact" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Request Briefing</a>
              <Link to="/register-institution" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Institution Onboarding</Link>
              <Link to="/register-institution?tab=track" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Track Application</Link>
              <Link to="/login" onClick={() => setMobileMenuOpen(false)} style={{ color: '#B54F34', fontWeight: 700, textDecoration: 'none' }}>Sign In →</Link>
            </div>
          </div>
        )}
      </header>

      {/* ----------------- Hero Section ----------------- */}
      <section className="sppio-hero-section">
        <div className="sppio-container">
          <div className="sppio-hero-grid">
            {/* Left: Editorial Hero Content */}
            <div className="sppio-hero-content">
              <div className="sppio-kicker-badge">
                <span className="sppio-kicker-dot" />
                <span>Open Aperture · Enterprise Recruitment &amp; High-Assurance Enclaves</span>
              </div>

              <h1 className="sppio-hero-headline">
                High-assurance systems.<br />
                <span className="sppio-highlight">Assessment workflows with clearer evidence.</span>
              </h1>

              <p className="sppio-hero-lead">
                SPPIO serves institutions running exams, employers evaluating technical talent, and teams conducting technical assessments. Explore the workflow and confirm supported controls for your deployment.
              </p>

              <div className="sppio-hero-actions">
                <a href="#contact" className="sppio-btn-primary">Request a briefing</a>
                <Link to="/login" className="sppio-btn-ghost">
                  Sign In
                </Link>
              </div>
            </div>

            {/* Illustrative product preview; not connected to live system state. */}
            <div className="sppio-hero-visual">
              <p role="note" style={{ fontSize: '12px', color: '#756F79', margin: '0 0 8px' }}>Illustrative product preview — not live system data.</p>
              <div className="sppio-aperture-frame">
                {/* Cockpit Window Titlebar */}
                <div className="sppio-cockpit-bar">
                  <div className="sppio-cockpit-dots">
                    <span className="sppio-cockpit-dot red" />
                    <span className="sppio-cockpit-dot yellow" />
                    <span className="sppio-cockpit-dot green" />
                    <span style={{ fontSize: '11.5px', color: '#A69BA9', marginLeft: '8px', fontWeight: 650, fontFamily: 'var(--sppio-font-mono)' }}>
                      SPPIO Cockpit v2.18
                    </span>
                  </div>
                  <div className="sppio-status-chip">
                    <span className="sppio-status-pulse" />
                    <span>Preview</span>
                  </div>
                </div>

                {/* Interactive Product Tabs */}
                <div className="sppio-cockpit-tabs" role="tablist">
                  <button
                    type="button"
                    className={`sppio-cockpit-tab ${cockpitTab === 'command' ? 'active' : ''}`}
                    onClick={() => setCockpitTab('command')}
                  >
                    <span>📊</span> Command Portal
                  </button>
                  <button
                    type="button"
                    className={`sppio-cockpit-tab ${cockpitTab === 'kiosk' ? 'active' : ''}`}
                    onClick={() => setCockpitTab('kiosk')}
                  >
                    <span>💻</span> Kiosk Sandbox
                  </button>
                  <button
                    type="button"
                    className={`sppio-cockpit-tab ${cockpitTab === 'forensics' ? 'active' : ''}`}
                    onClick={() => setCockpitTab('forensics')}
                  >
                    <span>🔬</span> Viva Forensics
                  </button>
                  <button
                    type="button"
                    className={`sppio-cockpit-tab ${cockpitTab === 'physical' ? 'active' : ''}`}
                    onClick={() => setCockpitTab('physical')}
                  >
                    <span>🛡️</span> Port Guard
                  </button>
                </div>

                {/* Cockpit Body Content */}
                <div className="sppio-cockpit-body">
                  {cockpitTab === 'command' && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                        <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                          SPPIO-Command™ Live Candidate Fleet
                        </span>
                        <span style={{ fontSize: '11px', color: '#4ADE80', fontWeight: 650 }}>● Sample station telemetry</span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {[
                          { station: 'Station #042', cand: 'Sarah Lin', role: 'Staff Frontend Architect', risk: '0.01 LOW', wpm: '74 WPM', face: 'Aligned' },
                          { station: 'Station #043', cand: 'Devon Miller', role: 'Staff Distributed Systems', risk: '0.02 LOW', wpm: '68 WPM', face: 'Aligned' },
                          { station: 'Station #044', cand: 'Aisha Patel', role: 'ML Platform Lead', risk: '0.01 LOW', wpm: '82 WPM', face: 'Aligned' },
                        ].map((row, i) => (
                          <div
                            key={i}
                            style={{
                              background: 'rgba(255, 255, 255, 0.04)',
                              border: '1px solid rgba(255, 255, 255, 0.08)',
                              borderRadius: '8px',
                              padding: '10px 14px',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              fontSize: '12px',
                            }}
                          >
                            <div>
                              <div style={{ fontWeight: 700, color: '#FFFFFF' }}>{row.cand} <span style={{ color: '#A69BA9', fontWeight: 400 }}>({row.station})</span></div>
                              <div style={{ color: '#FFAE99', fontSize: '11px' }}>{row.role}</div>
                            </div>
                            <div style={{ textAlign: 'right', display: 'flex', gap: '12px', alignItems: 'center' }}>
                              <span style={{ fontFamily: 'var(--sppio-font-mono)', color: '#C3B7C6', fontSize: '11px' }}>{row.wpm}</span>
                              <span style={{ background: 'rgba(74, 222, 128, 0.15)', color: '#4ADE80', padding: '2px 8px', borderRadius: '4px', fontSize: '10.5px', fontWeight: 700 }}>
                                {row.risk}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {cockpitTab === 'kiosk' && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                          SPPIO-Kiosk™ Single-Application IDE
                        </span>
                        <span style={{ background: 'rgba(181, 79, 52, 0.25)', color: '#FFAE99', padding: '2px 8px', borderRadius: '4px', fontSize: '10.5px', fontWeight: 700 }}>
                          🔒 Clipboard Host-Locked
                        </span>
                      </div>

                      <div style={{ background: 'rgba(0, 0, 0, 0.35)', borderRadius: '8px', padding: '12px 14px', fontFamily: 'var(--sppio-font-mono)', fontSize: '12px', lineHeight: 1.5, color: '#F6F2ED', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                        <div style={{ color: '#756F79' }}>// Contained in RAM • Zero host OS access • Anti-AI injection</div>
                        <div><span style={{ color: '#FFAE99' }}>def</span> <span style={{ color: '#4ADE80' }}>verify_transaction_ledger</span>(blocks):</div>
                        <div style={{ paddingLeft: '16px' }}><span style={{ color: '#FFAE99' }}>for</span> i <span style={{ color: '#FFAE99' }}>in</span> range(1, len(blocks)):</div>
                        <div style={{ paddingLeft: '32px' }}><span style={{ color: '#FFAE99' }}>if</span> blocks[i].prev != blocks[i-1].hash:</div>
                        <div style={{ paddingLeft: '48px' }}><span style={{ color: '#FFAE99' }}>return</span> <span style={{ color: '#F87171' }}>False</span></div>
                        <div style={{ paddingLeft: '16px', color: '#4ADE80' }}><span style={{ color: '#FFAE99' }}>return</span> True</div>
                      </div>

                      <div style={{ marginTop: '12px', display: 'flex', gap: '8px', fontSize: '11px', color: '#4ADE80', alignItems: 'center' }}>
                        <span>✓ Test 1: Memory Safety [OK]</span>
                        <span>•</span>
                        <span>✓ Test 2: Concurrency [OK]</span>
                        <span>•</span>
                        <span style={{ color: '#A69BA9' }}>0 Remote Tasks</span>
                      </div>
                    </div>
                  )}

                  {cockpitTab === 'forensics' && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                          SPPIO-Forensics™ Code Viva Defense
                        </span>
                        <span style={{ color: '#4ADE80', fontSize: '11px', fontWeight: 650 }}>● Keystrokes Chained</span>
                      </div>

                      <div style={{ background: 'rgba(255, 255, 255, 0.04)', borderRadius: '8px', padding: '12px', border: '1px solid rgba(255, 255, 255, 0.08)', marginBottom: '10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11.5px', color: '#C3B7C6', marginBottom: '6px' }}>
                          <span>Time-Lapse Code Construction Replay</span>
                          <span style={{ fontFamily: 'var(--sppio-font-mono)' }}>00:00 ━━━━●━━━━ 38:40</span>
                        </div>
                        <div style={{ height: '4px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ width: '68%', height: '100%', background: '#B54F34' }} />
                        </div>
                      </div>

                      <div style={{ background: 'rgba(181, 79, 52, 0.12)', border: '1px solid rgba(181, 79, 52, 0.3)', borderRadius: '8px', padding: '12px', fontSize: '12px' }}>
                        <div style={{ color: '#FFAE99', fontWeight: 700, marginBottom: '4px', fontSize: '11px', textTransform: 'uppercase' }}>
                          Targeted Viva Defense Prompt
                        </div>
                        <div style={{ color: '#FFFFFF', lineHeight: 1.45 }}>
                          &ldquo;Candidate typed lines 12-28 with natural cadence (72 WPM). Inquire about state cache eviction logic at timestamp 24:15.&rdquo;
                        </div>
                      </div>
                    </div>
                  )}

                  {cockpitTab === 'physical' && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <span style={{ fontSize: '11px', color: '#FFAE99', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                          SPPIO-PhysicalGuard™ Topology Shield
                        </span>
                        <span style={{ color: '#4ADE80', fontSize: '11px', fontWeight: 650 }}>● Illustrative control state</span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {[
                          { dev: 'Standard Input Keyboard', status: 'Whitelisted · VID:PID Bound', ok: true },
                          { dev: 'Optical Mouse', status: 'Whitelisted · HID Filter OK', ok: true },
                          { dev: 'External HDMI Display Splitter', status: 'BLOCKED · Port Output Suppressed', ok: false },
                          { dev: 'Keystroke Injector USB Dongle', status: 'BLOCKED · Kernel Endpoints Dropped', ok: false },
                        ].map((d, idx) => (
                          <div
                            key={idx}
                            style={{
                              background: 'rgba(255, 255, 255, 0.04)',
                              border: '1px solid rgba(255, 255, 255, 0.08)',
                              borderRadius: '8px',
                              padding: '8px 12px',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              fontSize: '11.5px',
                            }}
                          >
                            <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{d.dev}</span>
                            <span style={{ color: d.ok ? '#4ADE80' : '#F87171', fontWeight: 700, fontSize: '10.5px' }}>
                              {d.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Cockpit Window Footer */}
                <div className="sppio-frame-footer">
                  <span>Product preview — deployment behavior varies</span>
                  <button
                    type="button"
                    onClick={() => setShowSpecModal(true)}
                    style={{ background: 'none', border: 'none', color: '#FFAE99', cursor: 'pointer', fontWeight: 700, padding: 0 }}
                  >
                    View Architectural Specifications →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section aria-label="Choose your assessment use case" style={{ padding: '36px 0', background: '#FFFFFF' }}>
        <div className="sppio-container" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          {[
            { title: 'Institutional Exams', desc: 'Explore onboarding for institutions and exam programs.', href: '/register-institution', action: 'Start institutional onboarding' },
            { title: 'Enterprise Hiring', desc: 'Review hiring and assessment workflows for employers.', href: '/solutions#solutions-grid', action: 'Explore hiring solutions' },
            { title: 'Technical Evaluation', desc: 'Discuss technical assessment requirements and deployment scope.', href: '#contact', action: 'Request a technical briefing' },
          ].map((item) => (
            <article key={item.title} style={{ border: '1px solid #DCD5D2', borderRadius: '12px', padding: '20px', background: '#FBF9F7' }}>
              <h2 style={{ fontSize: '17px', margin: '0 0 8px', color: '#302337' }}>{item.title}</h2>
              <p style={{ fontSize: '13px', lineHeight: 1.5, color: '#756F79', margin: '0 0 14px' }}>{item.desc}</p>
              <Link to={item.href} style={{ color: '#A4442D', fontWeight: 700, fontSize: '13px' }}>{item.action} →</Link>
            </article>
          ))}
        </div>
      </section>

      {/* ----------------- Enterprise Trust & Scale Strip ----------------- */}
      <section className="sppio-trust-strip">
        <div className="sppio-container">
          <div className="sppio-trust-inner">
            <span className="sppio-trust-label">Illustrative assessment contexts — not customer endorsements:</span>
            <div className="sppio-trust-badges">
              <span className="sppio-trust-badge">
                <SppioSymbol size={14} accent="#B54F34" />
                <span>Enterprise Tech Recruitment</span>
              </span>
              <span className="sppio-trust-badge">
                <SppioSymbol size={14} accent="#B54F34" />
                <span>Campus Engineering Drives</span>
              </span>
              <span className="sppio-trust-badge">
                <SppioSymbol size={14} accent="#B54F34" />
                <span>National Assessment Authorities</span>
              </span>
              <span className="sppio-trust-badge">
                <SppioSymbol size={14} accent="#B54F34" />
                <span>State Licensure &amp; Universities</span>
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Metrics Strip ----------------- */}
      <section className="sppio-metrics-strip" aria-label="Illustrative design areas">
        <div className="sppio-container">
          <div className="sppio-metrics-grid">
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">Policy-led</span>
              <span className="sppio-metric-label">Hardware measurements where supported</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">Configured</span>
              <span className="sppio-metric-label">Station access restrictions</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">Reviewable</span>
              <span className="sppio-metric-label">Audit event handling and verification</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">Validated</span>
              <span className="sppio-metric-label">Performance for the selected deployment</span>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Capabilities (Numbered Editorial Layout) ----------------- */}
      <section id="capabilities" className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Enterprise Capabilities</span>
              <h2 className="sppio-section-title">Engineered for absolute integrity.</h2>
            </div>
            <p className="sppio-section-desc">
              Four verified architectural pillars ensuring that high-stakes examinations execute in strict hardware isolation with non-repudiable audit trails.
            </p>
          </div>

          <div className="sppio-capabilities-layout">
            {/* Left: Interactive Numbered Tab Selector */}
            <div className="sppio-cap-nav" role="tablist">
              {capabilities.map((cap, idx) => (
                <button
                  key={cap.number}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === idx}
                  className={`sppio-cap-tab ${activeTab === idx ? 'active' : ''}`}
                  onClick={() => setActiveTab(idx)}
                >
                  <span className="sppio-cap-number">{cap.number}</span>
                  <div className="sppio-cap-summary">
                    <h4>{cap.title}</h4>
                    <p>{cap.summary}</p>
                  </div>
                </button>
              ))}
            </div>

            {/* Right: Detailed Capability Display */}
            <div className="sppio-cap-display" role="tabpanel">
              <div className="sppio-display-tag">
                <SppioSymbol size={16} accent="#B54F34" />
                <span>{capabilities[activeTab].tag}</span>
              </div>
              <h3 className="sppio-display-headline">{capabilities[activeTab].title}</h3>
              <p className="sppio-display-body">{capabilities[activeTab].description}</p>

              <div className="sppio-specs-grid">
                {capabilities[activeTab].specs.map((spec, i) => (
                  <div key={i} className="sppio-spec-item">
                    <span className="sppio-spec-label">{spec.label}</span>
                    <span className="sppio-spec-value">{spec.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Technology Approach ----------------- */}
      <section id="technology" className="sppio-section sppio-tech-section">
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Architecture</span>
              <h2 className="sppio-section-title">Layered security controls.</h2>
            </div>
            <p className="sppio-section-desc">
              Security is not a reactive detection layer; it is an architectural property enforced from physical silicon up through the display compositor and cryptographic ledger.
            </p>
          </div>

          <div className="sppio-tech-layers">
            {techLayers.map((tl, idx) => (
              <div key={idx} className="sppio-tech-card">
                <span className="sppio-tech-layer-tag">{tl.layer}</span>
                <h4 className="sppio-tech-title">{tl.title}</h4>
                <p className="sppio-tech-desc">{tl.desc}</p>
                <span className="sppio-tech-badge">{tl.badge}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ----------------- Product Suite: Open Aperture Security & Recruitment ----------------- */}
      <section id="suite" className="sppio-section" style={{ background: '#FFFFFF' }}>
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Product Suite</span>
              <h2 className="sppio-section-title">The SPPIO Open Aperture Security Suite</h2>
              <p style={{ margin: '10px 0 0', color: '#756F79', fontSize: '13px', lineHeight: 1.5 }}>Product descriptions are informational previews, not independent test results or certification claims. Confirm availability and evidence for the selected release.</p>
            </div>
            <p className="sppio-section-desc">
              Modular, hardware-rooted technologies engineered to protect corporate technical recruitment pipelines, campus hiring drives, and national institutional examinations.
            </p>
          </div>

          {/* Category Filter Pills */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '32px' }}>
            {[
              { id: 'all', label: 'All 9 Products' },
              { id: 'endpoint', label: 'Endpoint & Silicon' },
              { id: 'intelligence', label: 'AI Proctoring & Forensics' },
              { id: 'cloud', label: 'Web Portal & Backend' },
            ].map((cat) => (
              <button
                key={cat.id}
                type="button"
                onClick={() => setSuiteCategory(cat.id)}
                style={{
                  padding: '8px 18px',
                  borderRadius: '999px',
                  fontSize: '13px',
                  fontWeight: 650,
                  cursor: 'pointer',
                  border: '1px solid',
                  borderColor: suiteCategory === cat.id ? '#B54F34' : '#DCD5D2',
                  backgroundColor: suiteCategory === cat.id ? '#B54F34' : '#FFFFFF',
                  color: suiteCategory === cat.id ? '#FFFFFF' : '#302337',
                  boxShadow: suiteCategory === cat.id ? '0 2px 8px rgba(181, 79, 52, 0.25)' : 'none',
                  transition: 'all 0.2s ease',
                }}
              >
                {cat.label}
              </button>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
            {productSuite
              .filter((p) => suiteCategory === 'all' || p.category === suiteCategory)
              .map((prod, idx) => (
              <div
                key={idx}
                style={{
                  background: '#F6F2ED',
                  border: '1px solid #DCD5D2',
                  borderRadius: '14px',
                  padding: '28px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  position: 'relative',
                  overflow: 'hidden',
                  transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                }}
              >
                <div style={{ position: 'absolute', top: 0, left: 0, width: '4px', height: '100%', background: '#B54F34' }} />
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="sppio-tag" style={{ background: 'rgba(181, 79, 52, 0.1)', color: '#B54F34', borderColor: 'rgba(181, 79, 52, 0.25)', fontSize: '11px' }}>
                      {prod.tag}
                    </span>
                    <SppioSymbol size={18} accent="#B54F34" />
                  </div>

                  <h3 style={{ fontSize: '19px', fontWeight: 800, color: '#302337', margin: '0 0 6px', letterSpacing: '-0.01em' }}>
                    {prod.name}
                  </h3>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#B54F34', marginBottom: '14px' }}>
                    {prod.tagline}
                  </div>
                  <p style={{ fontSize: '13.5px', color: '#756F79', lineHeight: 1.55, margin: '0 0 20px' }}>
                    {prod.desc}
                  </p>
                </div>

                <div style={{ background: 'rgba(48, 35, 55, 0.05)', borderRadius: '8px', padding: '12px 14px', border: '1px solid rgba(48, 35, 55, 0.08)' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#302337', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>🎯</span> Enterprise Recruitment Focus
                  </div>
                  <div style={{ fontSize: '12.5px', color: '#302337', lineHeight: 1.45, fontWeight: 550 }}>
                    {prod.hiringRole}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ----------------- Featured Work / Deployments ----------------- */}
      <section id="deployments" className="sppio-section">
        <div className="sppio-container">
          <p role="note" style={{ fontSize: '12px', color: '#756F79', margin: '0 0 16px' }}>Illustrative examples only; not customer case studies or independently verified outcomes.</p>
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Illustrative use cases</span>
              <h2 className="sppio-section-title">Example assessment workflows.</h2>
            </div>
            <p className="sppio-section-desc">
              These scenarios are examples, not customer case studies or verified performance results.
            </p>
          </div>

          <div className="sppio-deployments-list">
            {deployments.map((dep, idx) => (
              <div key={idx} className="sppio-deployment-card">
                <div className="sppio-deployment-sidebar">
                  <div>
                    <span className="sppio-deployment-scope">{dep.scope}</span>
                    <div className="sppio-deployment-metric-big">{dep.metric}</div>
                    <div className="sppio-deployment-metric-desc">{dep.metricDesc}</div>
                  </div>
                  <div style={{ marginTop: '24px' }}>
                    <SppioSymbol size={28} accent="#FFAE99" />
                  </div>
                </div>

                <div className="sppio-deployment-content">
                  <div>
                    <h3 className="sppio-deployment-title">{dep.title}</h3>
                    <p className="sppio-deployment-desc">{dep.desc}</p>
                  </div>
                  <div className="sppio-deployment-tags">
                    {dep.tags.map((t, i) => (
                      <span key={i} className="sppio-tag">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ----------------- Company & Philosophy ----------------- */}
      <section id="company" className="sppio-section sppio-company-section">
        <div className="sppio-container">
          <div className="sppio-company-grid">
            <div className="sppio-company-text">
              <span className="sppio-section-eyebrow" style={{ color: '#FFAE99' }}>Design Philosophy</span>
              <h2 className="sppio-section-title">A deliberate opening.</h2>
              <p className="sppio-company-lead">
                Two offset architectural elements form an open field. Opposing diagonal entries create a passage through a stable outer structure: controlled access without a literal shield, and connection without network-node imagery.
              </p>

              <div className="sppio-pillars">
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong>Expressive Restraint</strong>
                    <p>Clarity and confident simplicity over ornamental noise, decorative circuitry, and unnecessary gradients.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong>Hardware-Rooted Attestation</strong>
                    <p>Mathematical proof anchored in physical silicon, validating every workstation before execution begins.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong>Auditable Accountability</strong>
                    <p>Non-repudiable cryptographic audit logs with strict separation of duties and dual-custody governance.</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="sppio-geometry-study">
              <SppioLogo width={280} accent="#B54F34" ink="#FFFFFF" variant="stacked" />
              <p>
                The silhouette is intentionally asymmetric. Its 18-unit bands, 45-degree entrances, and unequal interior steps give the mark a repeatable construction logic.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Contact & Briefing Form ----------------- */}
      <section id="contact" className="sppio-section sppio-contact-section">
        <div className="sppio-container">
          <div className="sppio-contact-grid">
            {/* Left: Contact Info */}
            <div className="sppio-contact-info">
              <span className="sppio-section-eyebrow">Direct Engagement</span>
              <h3>Request an architecture briefing.</h3>
              <p>
                Discuss technical requirements, station attestation protocols, or schedule an executive walkthrough with our engineering leadership.
              </p>

              <div className="sppio-contact-details">
                <div className="sppio-contact-method">
                  <span className="sppio-method-label">Briefing contact</span>
                  <a className="sppio-method-val" href="mailto:briefings@sppio.io">briefings@sppio.io</a>
                </div>
              </div>
            </div>

            {/* Inquiry details are passed to the user's email app, not submitted to a backend. */}
            <div className="sppio-form-card">
                <form className="sppio-form" onSubmit={handleFormSubmit} noValidate>
                  <div className="sppio-form-row">
                    <div className="sppio-form-group">
                      <label htmlFor="contact-name">Full Name *</label>
                      <input
                        id="contact-name"
                        className="sppio-form-input"
                        aria-invalid={Boolean(contactErrors.name)}
                        aria-describedby={contactErrors.name ? 'contact-name-error' : undefined}
                        placeholder="Dr. Avery Rao"
                        value={formData.name}
                        onChange={(e) => { setFormData({ ...formData, name: e.target.value }); setContactErrors((prev) => ({ ...prev, name: '' })); setFormError(''); setFormNotice(''); }}
                        required
                      />
                      {contactErrors.name && <small id="contact-name-error" style={{ color: '#A93226' }}>{contactErrors.name}</small>}
                    </div>
                    <div className="sppio-form-group">
                      <label htmlFor="contact-email">Institutional Email *</label>
                      <input
                        id="contact-email"
                        type="email"
                        className="sppio-form-input"
                        aria-invalid={Boolean(contactErrors.email)}
                        aria-describedby={contactErrors.email ? 'contact-email-error' : undefined}
                        placeholder="a.rao@institution.edu"
                        value={formData.email}
                        onChange={(e) => { setFormData({ ...formData, email: e.target.value }); setContactErrors((prev) => ({ ...prev, email: '' })); setFormError(''); setFormNotice(''); }}
                        required
                      />
                      {contactErrors.email && <small id="contact-email-error" style={{ color: '#A93226' }}>{contactErrors.email}</small>}
                    </div>
                  </div>

                  <div className="sppio-form-row">
                    <div className="sppio-form-group">
                      <label htmlFor="contact-org">Organization / Agency *</label>
                      <input
                        id="contact-org"
                        className="sppio-form-input"
                        aria-invalid={Boolean(contactErrors.organization)}
                        aria-describedby={contactErrors.organization ? 'contact-organization-error' : undefined}
                        placeholder="State Testing Agency"
                        value={formData.organization}
                        onChange={(e) => { setFormData({ ...formData, organization: e.target.value }); setContactErrors((prev) => ({ ...prev, organization: '' })); setFormError(''); setFormNotice(''); }}
                        required
                      />
                      {contactErrors.organization && <small id="contact-organization-error" style={{ color: '#A93226' }}>{contactErrors.organization}</small>}
                    </div>
                    <div className="sppio-form-group">
                      <label htmlFor="contact-fleet">Testing Station Scale</label>
                      <select
                        id="contact-fleet"
                        className="sppio-form-select"
                        value={formData.fleetSize}
                        onChange={(e) => setFormData({ ...formData, fleetSize: e.target.value })}
                      >
                        <option value="50-500">50 – 500 Stations</option>
                        <option value="500-2500">500 – 2,500 Stations</option>
                        <option value="2500-10000">2,500 – 10,000 Stations</option>
                        <option value="10000+">10,000+ National Fleet</option>
                      </select>
                    </div>
                  </div>

                  <div className="sppio-form-group">
                    <label htmlFor="contact-msg">Technical Requirements / Scope</label>
                    <textarea
                      id="contact-msg"
                      className="sppio-form-textarea"
                      placeholder="Outline your examination requirements, target timeline, or attestation specifics..."
                      value={formData.message}
                      onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                    />
                  </div>

                  {formError && (
                    <div role="alert" style={{ color: '#C0392B', fontSize: '13px', fontWeight: 600 }}>
                      {formError}
                    </div>
                  )}
                  {formNotice && (
                    <div role="status" style={{ color: '#302337', fontSize: '13px', fontWeight: 600 }}>
                      {formNotice}
                    </div>
                  )}

                  <button
                    type="submit"
                    className="sppio-form-submit"
                  >
                    Open email draft
                  </button>
                </form>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Footer ----------------- */}
      <footer className="sppio-footer" role="contentinfo">
        <div className="sppio-container">
          <div className="sppio-footer-grid">
            <div className="sppio-footer-brand">
              <SppioLogo width={160} accent="#B54F34" ink="#FFFFFF" />
              <p>
                Open Aperture architecture. High-assurance infrastructure engineered for national, institutional, and corporate assessment integrity.
              </p>
              <p style={{ fontSize: '12px', lineHeight: 1.5 }}>Product descriptions are informational. Confirm current capabilities, deployment prerequisites, and assurance evidence before procurement.</p>
            </div>

            <div className="sppio-footer-col">
              <h5>Public Architecture</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/landing">Platform Overview</Link></li>
                <li><Link to="/architecture">Silicon Attestation</Link></li>
                <li><Link to="/solutions">Enterprise Solutions</Link></li>
                <li><a href="#capabilities">Enclave Capabilities</a></li>
              </ul>
            </div>

            <div className="sppio-footer-col">
              <h5>Governance</h5>
              <ul className="sppio-footer-links">
                <li><a href="#technology">Two-Person Authorization</a></li>
                <li><a href="#technology">Role-Based Access Control</a></li>
                <li><a href="#technology">Audit Event Handling</a></li>
                <li><a href="#deployments">Compliance &amp; Attestation</a></li>
              </ul>
            </div>

            <div className="sppio-footer-col">
              <h5>Console Access</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/login" style={{ color: '#FFAE99', fontWeight: 700 }}>Console Sign In →</Link></li>
                <li><Link to="/candidate-login">Candidate Station Login</Link></li>
                <li><Link to="/register-institution">Institution Onboarding</Link></li>
                <li><Link to="/register-institution?tab=track">Track Application</Link></li>
                <li><Link to="/recovery">Emergency TOTP Recovery</Link></li>
                <li><a href="#contact">Architecture Inquiry</a></li>
              </ul>
            </div>
          </div>

          <div className="sppio-footer-bottom">
            <div>
              © 2026 SPPIO Systems Enclave. All rights reserved. Open Aperture architecture.
            </div>
            <div className="sppio-legal-links">
              <a href="#top" onClick={(e) => { e.preventDefault(); document.getElementById('top')?.focus(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>
                Back to Top ↑
              </a>
            </div>
          </div>
        </div>
      </footer>

      {/* ----------------- Architecture Specs Modal ----------------- */}
      {showSpecModal && (
        <div className="polished-modal-backdrop" onClick={() => setShowSpecModal(false)}>
          <div className="polished-modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
            <div className="modal-header-row">
              <div>
                <h3 className="modal-title">Hardware Attestation &amp; Compositor Specifications</h3>
                <p className="modal-sub">SPPIO High-Assurance Enclave Architecture</p>
              </div>
              <button
                type="button"
                className="modal-close-icon"
                onClick={() => setShowSpecModal(false)}
                aria-label="Close specifications modal"
              >
                ×
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', fontSize: '13.5px', color: '#302337', lineHeight: 1.6 }}>
              <div>
                <strong style={{ display: 'block', color: '#B54F34', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.08em', marginBottom: '6px' }}>
                  1. Hardware Root of Trust Attestation
                </strong>
                <p style={{ margin: 0, color: '#756F79' }}>
                  Where supported, platform measurements may be checked against configured policies. Hardware compatibility, measurement coverage, failure handling, and release-manifest evidence must be verified for the target deployment.
                </p>
              </div>

              <div>
                <strong style={{ display: 'block', color: '#B54F34', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.08em', marginBottom: '6px' }}>
                  2. Isolated Station Environment
                </strong>
                <p style={{ margin: 0, color: '#756F79' }}>
                  The examination environment operates in strict single-application isolation without an accessible desktop interface, background process access, or host key shortcuts. Display cloning, unauthorized peripheral connections, and external media are suppressed at the operating system layer.
                </p>
              </div>

              <div>
                <strong style={{ display: 'block', color: '#B54F34', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.08em', marginBottom: '6px' }}>
                  3. Tamper-Evident Chained Audit Logging
                </strong>
                <p style={{ margin: 0, color: '#756F79' }}>
                  All supervisor interactions, candidate milestones, and workstation telemetry are cryptographically linked into an immutable event stream. Each record is verified against preceding milestones, ensuring complete historical non-repudiation and auditability for institutional compliance.
                </p>
              </div>

              <div style={{ paddingTop: '16px', borderTop: '1px solid #DCD5D2', display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  className="sppio-btn-primary"
                  onClick={() => setShowSpecModal(false)}
                >
                  Close Controls Overview
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
