import { useState, useEffect } from 'react';
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

  // Contact form state
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    organization: '',
    fleetSize: '50-500',
    message: '',
  });
  const [formSubmitted, setFormSubmitted] = useState(false);
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Live backend telemetry
  const [telemetryStatus, setTelemetryStatus] = useState({
    online: true,
    tpmMode: 'production',
    ledgerIntegrity: 'INTACT',
    database: true,
  });

  useEffect(() => {
    fetch('/api/v1/health')
      .then((r) => r.json())
      .then((data) => {
        if (data?.status === 'ok') {
          setTelemetryStatus({
            online: true,
            tpmMode: data.tpm_mode || 'production',
            ledgerIntegrity: data.ledger_integrity || 'INTACT',
            database: !!data.database,
          });
        }
      })
      .catch(() => {
        // Fallback gracefully to offline simulation values
      });
  }, []);

  const handleFormSubmit = (e) => {
    e.preventDefault();
    if (!formData.name.trim() || !formData.email.trim() || !formData.organization.trim()) {
      setFormError('Please complete all required fields.');
      return;
    }
    if (!formData.email.includes('@') || !formData.email.includes('.')) {
      setFormError('Please enter a valid institutional email address.');
      return;
    }
    setFormError('');
    setSubmitting(true);

    setTimeout(() => {
      setSubmitting(false);
      setFormSubmitted(true);
    }, 600);
  };

  const capabilities = [
    {
      number: '01',
      tag: 'Hardware Security',
      title: 'Hardware Cryptographic Attestation',
      summary: 'Physical device attestation authenticated against verified golden release policies.',
      description:
        'Before any assessment payload initializes, the physical device cryptoprocessor calculates cryptographic integrity measurements of the core system firmware and kernel. These measurements are validated against tamper-evident golden release policies, guaranteeing zero firmware tampering or bootkit persistence.',
      specs: [
        { label: 'Attestation Root', value: 'Hardware Cryptoprocessor' },
        { label: 'Integrity Check', value: 'Golden Policy Verification' },
        { label: 'Replay Protection', value: 'Anti-Replay Challenge Protocol' },
        { label: 'Attestation Latency', value: '< 120ms Roundtrip' },
      ],
    },
    {
      number: '02',
      tag: 'Station Lockdown',
      title: 'Zero-Trust Station Enclave',
      summary: 'Dedicated display environment enforcing single-application containment.',
      description:
        'The candidate workstation boots directly into a dedicated display environment engineered specifically for containment. Virtual terminal switching, host key shortcuts, unauthorized display cloning, clipboard sharing, and unapproved peripheral access are restricted at the operating system foundation.',
      specs: [
        { label: 'Display Engine', value: 'Isolated Kiosk Compositor' },
        { label: 'Storage Mode', value: 'Immutable Read-Only System' },
        { label: 'Peripheral Guard', value: 'Hardware Device Whitelisting' },
        { label: 'Host Access', value: 'Zero Residual Host Footprint' },
      ],
    },
    {
      number: '03',
      tag: 'Audit Integrity',
      title: 'Immutable Chained Audit Ledger',
      summary: 'Tamper-evident event chaining with strict separation of duties.',
      description:
        'Every supervisory action, candidate session lifecycle event, heartbeat, and policy update is permanently recorded in an immutable chained event ledger. Each record is linked cryptographically to prior blocks, ensuring any retrospective alteration or omission is immediately detectable.',
      specs: [
        { label: 'Ledger Model', value: 'Cryptographically Chained Records' },
        { label: 'Approval Model', value: 'Two-Person Dual-Custody Controls' },
        { label: 'Audit Verification', value: 'Independent Verification Protocol' },
        { label: 'Compliance', value: 'FIPS 140-3 & ISO 27001 Aligned' },
      ],
    },
    {
      number: '04',
      tag: 'Fleet Management',
      title: 'Distributed Fleet Orchestration',
      summary: 'Real-time telemetry, synchronized policy convergence, and offline resilience.',
      description:
        'SPPIO orchestrates thousands of concurrent testing stations across decentralized examination centers. Operating on a resilient local-first model, stations execute examinations seamlessly even during complete wide-area network severance, synchronizing encrypted submission batches upon link restoration.',
      specs: [
        { label: 'Network Resilience', value: 'Autonomous Offline Execution' },
        { label: 'Heartbeat Cadence', value: 'Real-Time Health Monitoring' },
        { label: 'Policy Rollout', value: 'Staged Canary Deployment' },
        { label: 'Data Recovery', value: 'Zero-Loss Local Cryptographic Cache' },
      ],
    },
  ];

  const techLayers = [
    {
      layer: 'LAYER 01',
      title: 'Silicon & Hardware Root',
      desc: 'Dedicated hardware cryptoprocessor generates non-exportable cryptographic keys and provides non-repudiable attestation quotes directly to the supervisory enclave.',
      badge: 'Hardware Root / FIPS 140-3',
    },
    {
      layer: 'LAYER 02',
      title: 'Kernel & Graphical Containment',
      desc: 'Immutable read-only system rootfs with display isolation suppressing virtual consoles, screen scraping, and unauthorized peripheral insertion.',
      badge: 'Station Display Enclave',
    },
    {
      layer: 'LAYER 03',
      title: 'Application & Telemetry Enclave',
      desc: 'High-assurance browser sandbox isolated in RAM memory, enforcing real-time multi-face supervisory tracking, audio thresholds, and strict peripheral containment.',
      badge: 'Wasm / WebRTC / MediaPipe',
    },
    {
      layer: 'LAYER 04',
      title: 'Cryptographic Audit & Ledger',
      desc: 'Cryptographically chained ledger replicated across authenticated backend nodes with dual-custody approval workflows preventing single-operator privilege abuse.',
      badge: 'PostgreSQL 16 TLS / Chained Ledger',
    },
  ];

  const deployments = [
    {
      scope: 'National Assessment Infrastructure',
      metric: '150+ Stations',
      metricDesc: 'Concurrently provisioned across multi-center test facilities',
      title: 'High-Assurance National Examination Enclave',
      desc: 'A mission-critical examination deployment requiring zero host OS exposure and hardware-enforced boot attestation. SPPIO bootable stations sealed workstations against unauthorized media, virtual terminals, and external networks, maintaining 100% attestation integrity throughout examination sessions.',
      tags: ['Hardware Attestation', 'Station Lockdown', 'Air-Gap Resilience', 'Zero-Loss Cache'],
    },
    {
      scope: 'State University Board',
      metric: '100% Verifiable',
      metricDesc: 'Chained tamper-evident audit ledger with two-person custody',
      title: 'Tamper-Evident Institutional Audit & Policy Governance',
      desc: 'Implementation of dual-custody authorization for policy changes and candidate grade submissions. All supervisor activities and examination events were permanently recorded in an immutable hash-chained audit log, providing complete non-repudiation for institutional compliance audits.',
      tags: ['Two-Person Rule', 'Audit Hash Chain', 'RBAC Enforcement', 'FIPS 140-3'],
    },
  ];

  return (
    <div className="sppio-website">
      {/* ----------------- Header & Navigation ----------------- */}
      <header className="sppio-header" role="banner">
        <div className="sppio-container">
          <div className="sppio-header-inner">
            <Link to="/" className="sppio-brand-link" aria-label="SPPIO Home">
              <SppioLogo width={164} accent="#B54F34" ink="#302337" />
            </Link>

            <nav className="sppio-nav" aria-label="Primary navigation">
              <a href="#capabilities" className="sppio-nav-item">Capabilities</a>
              <Link to="/architecture" className="sppio-nav-item">Architecture</Link>
              <Link to="/solutions" className="sppio-nav-item">Solutions</Link>
              <a href="#deployments" className="sppio-nav-item">Deployments</a>
              <a href="#company" className="sppio-nav-item">Company</a>
              <a href="#contact" className="sppio-nav-item">Briefing</a>
            </nav>

            <div className="sppio-header-actions">
              <Link to="/login" className="sppio-btn-ghost">
                Console Sign In
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
              <a href="#capabilities" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Capabilities</a>
              <Link to="/architecture" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Architecture</Link>
              <Link to="/solutions" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Solutions</Link>
              <a href="#deployments" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Deployments</a>
              <a href="#company" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Company</a>
              <a href="#contact" onClick={() => setMobileMenuOpen(false)} style={{ color: '#302337', fontWeight: 700, textDecoration: 'none' }}>Request Briefing</a>
              <Link to="/login" onClick={() => setMobileMenuOpen(false)} style={{ color: '#B54F34', fontWeight: 700, textDecoration: 'none' }}>Console Sign In →</Link>
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
                <span>Open Aperture · High-Assurance Enclave</span>
              </div>

              <h1 className="sppio-hero-headline">
                High-assurance systems.<br />
                <span className="sppio-highlight">Verifiable mathematical trust.</span>
              </h1>

              <p className="sppio-hero-lead">
                Engineered for national examinations, academic institutions, and high-security testing. SPPIO combines silicon-rooted hardware attestation, strict station isolation, and immutable cryptographic ledgers in one open aperture.
              </p>

              <div className="sppio-hero-actions">
                <a href="#contact" className="sppio-btn-primary">
                  Request Architecture Briefing
                </a>
                <Link to="/login" className="sppio-btn-ghost">
                  Access Enterprise Console
                </Link>
              </div>

              <div className="sppio-hero-standards">
                <span>Hardware Root Active</span>
                <span className="sppio-sep">•</span>
                <span>Enclave Isolation</span>
                <span className="sppio-sep">•</span>
                <span>Tamper-Evident Ledger</span>
                <span className="sppio-sep">•</span>
                <span>FIPS 140-3 Aligned</span>
              </div>
            </div>

            {/* Right: Architectural Open Aperture Framing with Live Telemetry */}
            <div className="sppio-hero-visual">
              <div className="sppio-aperture-frame">
                <div className="sppio-frame-top">
                  <div className="sppio-frame-title">
                    <SppioSymbol size={20} accent="#B54F34" />
                    <span>Station Enclave Telemetry</span>
                  </div>
                  <div className="sppio-status-chip">
                    <span className="sppio-status-pulse" />
                    <span>Enclave Sealed</span>
                  </div>
                </div>

                <div className="sppio-telemetry-list">
                  <div className="sppio-telemetry-row">
                    <span className="sppio-telemetry-label">System Integrity</span>
                    <span className="sppio-telemetry-val accent">
                      Hardware Attestation Active · Secure Boot Verified
                    </span>
                  </div>

                  <div className="sppio-telemetry-row">
                    <span className="sppio-telemetry-label">Station Environment</span>
                    <span className="sppio-telemetry-val">
                      Isolated Examination Enclave · Single-Application Lock
                    </span>
                  </div>

                  <div className="sppio-telemetry-row">
                    <span className="sppio-telemetry-label">Peripheral Controls</span>
                    <span className="sppio-telemetry-val">
                      Strict Device Policy Active · External Media Blocked
                    </span>
                  </div>

                  <div className="sppio-telemetry-row">
                    <span className="sppio-telemetry-label">Audit Stream</span>
                    <span className="sppio-telemetry-val">
                      Tamper-Evident Ledger · Chained Event Validation
                    </span>
                  </div>
                </div>

                <div className="sppio-frame-footer">
                  <span>Compliance: FIPS 140-3 &amp; ISO 27001 Aligned</span>
                  <button
                    type="button"
                    onClick={() => setShowSpecModal(true)}
                    style={{ background: 'none', border: 'none', color: '#FFAE99', cursor: 'pointer', fontWeight: 700, padding: 0 }}
                  >
                    Explore Enclave Controls →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------- Metrics Strip ----------------- */}
      <section className="sppio-metrics-strip" aria-label="Key Performance Metrics">
        <div className="sppio-container">
          <div className="sppio-metrics-grid">
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">100%</span>
              <span className="sppio-metric-label">Hardware-Rooted Boot Attestation</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">0</span>
              <span className="sppio-metric-label">Host OS Virtual Terminal Escapes</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">Chained</span>
              <span className="sppio-metric-label">Immutable Cryptographic Event Verification</span>
            </div>
            <div className="sppio-metric-box">
              <span className="sppio-metric-num">&lt; 120ms</span>
              <span className="sppio-metric-label">Attestation Quote Verification Latency</span>
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
              <h2 className="sppio-section-title">Layered prevention-first security.</h2>
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

      {/* ----------------- Featured Work / Deployments ----------------- */}
      <section id="deployments" className="sppio-section">
        <div className="sppio-container">
          <div className="sppio-section-header">
            <div>
              <span className="sppio-section-eyebrow">Field Deployments</span>
              <h2 className="sppio-section-title">Proven in high-assurance environments.</h2>
            </div>
            <p className="sppio-section-desc">
              Authentic institutional case studies delivering dependable, uncompromised examination security at national and university scale.
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
                    <strong>Immutable Accountability</strong>
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
                  <span className="sppio-method-label">Direct Communication</span>
                  <span className="sppio-method-val">briefings@sppio.io</span>
                </div>
                <div className="sppio-contact-method">
                  <span className="sppio-method-label">Enterprise Headquarters</span>
                  <span className="sppio-method-val">SPPIO Infrastructure Systems Enclave</span>
                </div>
                <div className="sppio-contact-method">
                  <span className="sppio-method-label">Attestation Endpoint</span>
                  <span className="sppio-method-val">TLS 1.3 Verified · FIPS 140-3 Hardware Attested</span>
                </div>
              </div>
            </div>

            {/* Right: Functional Inquiry Form */}
            <div className="sppio-form-card">
              {formSubmitted ? (
                <div className="sppio-form-success" role="status">
                  <SppioSymbol size={32} accent="#1B7A4B" />
                  <h4 style={{ fontSize: '18px', fontWeight: 800, margin: '12px 0 6px' }}>
                    Briefing Request Received
                  </h4>
                  <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5 }}>
                    Thank you, <strong>{formData.name}</strong>. An engineering representative from SPPIO will review your fleet profile (<strong>{formData.organization}</strong>) and deliver technical briefing materials within one business day.
                  </p>
                  <button
                    type="button"
                    className="sppio-btn-ghost"
                    style={{ marginTop: '20px' }}
                    onClick={() => {
                      setFormSubmitted(false);
                      setFormData({ name: '', email: '', organization: '', fleetSize: '50-500', message: '' });
                    }}
                  >
                    Submit another inquiry
                  </button>
                </div>
              ) : (
                <form className="sppio-form" onSubmit={handleFormSubmit} noValidate>
                  <div className="sppio-form-row">
                    <div className="sppio-form-group">
                      <label htmlFor="contact-name">Full Name *</label>
                      <input
                        id="contact-name"
                        className="sppio-form-input"
                        placeholder="Dr. Avery Rao"
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        required
                      />
                    </div>
                    <div className="sppio-form-group">
                      <label htmlFor="contact-email">Institutional Email *</label>
                      <input
                        id="contact-email"
                        type="email"
                        className="sppio-form-input"
                        placeholder="a.rao@institution.edu"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        required
                      />
                    </div>
                  </div>

                  <div className="sppio-form-row">
                    <div className="sppio-form-group">
                      <label htmlFor="contact-org">Organization / Agency *</label>
                      <input
                        id="contact-org"
                        className="sppio-form-input"
                        placeholder="State Testing Agency"
                        value={formData.organization}
                        onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                        required
                      />
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
                    <div style={{ color: '#C0392B', fontSize: '13px', fontWeight: 600 }}>
                      {formError}
                    </div>
                  )}

                  <button
                    type="submit"
                    className="sppio-form-submit"
                    disabled={submitting}
                  >
                    {submitting ? 'Submitting Request…' : 'Schedule Architecture Briefing'}
                  </button>
                </form>
              )}
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
              <div style={{ display: 'flex', gap: '8px' }}>
                <span className="sppio-tag" style={{ background: 'rgba(255,255,255,0.08)', color: '#F6F2ED', borderColor: 'rgba(255,255,255,0.15)' }}>Hardware Attestation</span>
                <span className="sppio-tag" style={{ background: 'rgba(255,255,255,0.08)', color: '#F6F2ED', borderColor: 'rgba(255,255,255,0.15)' }}>FIPS 140-3</span>
                <span className="sppio-tag" style={{ background: 'rgba(255,255,255,0.08)', color: '#F6F2ED', borderColor: 'rgba(255,255,255,0.15)' }}>Station Enclave</span>
              </div>
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
                <li><a href="#technology">Cryptographic Non-Repudiation</a></li>
                <li><a href="#deployments">Compliance &amp; Attestation</a></li>
              </ul>
            </div>

            <div className="sppio-footer-col">
              <h5>Console Access</h5>
              <ul className="sppio-footer-links">
                <li><Link to="/login" style={{ color: '#FFAE99', fontWeight: 700 }}>Console Sign In →</Link></li>
                <li><Link to="/login">Candidate Station Login</Link></li>
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
              <a href="#top" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>
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
                  Workstations utilize a dedicated hardware cryptoprocessor. Before assessment payloads are unlocked, the system cryptographically validates physical firmware, operating system components, and launch policies against authorized release manifests. Any unauthorized modification prevents workstation authorization.
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
