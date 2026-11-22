import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import SppioLogo, { SppioSymbol } from './SppioLogo';
import PublicHeader from './PublicHeader';
import PublicFooter from './PublicFooter';
import SppioShowcase from './SppioShowcase';
import usePageMeta from './usePageMeta';

export default function LandingPage() {
  usePageMeta({
    title: 'SPPIO | High-Assurance Assessment & Enterprise Recruitment Platform',
    description:
      'SPPIO Open Aperture platform: hardware-rooted assessment stations, reviewable audit evidence, and institutional onboarding for high-stakes exams and technical hiring.',
    path: '/',
  });

  const [activeTab, setActiveTab] = useState(0);
  const [showSpecModal, setShowSpecModal] = useState(false);
  const [suiteCategory, setSuiteCategory] = useState('all'); // 'all' | 'endpoint' | 'intelligence' | 'cloud'

  useEffect(() => {
    if (!showSpecModal) return undefined;
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') setShowSpecModal(false);
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [showSpecModal]);

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
      <PublicHeader />

      <main id="main-content">

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

            <div className="sppio-hero-visual">
              <SppioShowcase onSpecs={() => setShowSpecModal(true)} />
            </div>
          </div>
        </div>
      </section>

      <section aria-labelledby="use-case-heading" style={{ padding: '40px 0', background: '#FFFFFF', borderBottom: '1px solid #DCD5D2' }}>
        <div className="sppio-container">
          <div className="sppio-use-case-head">
            <div>
              <span className="sppio-section-eyebrow">Where teams start</span>
              <h2 id="use-case-heading" className="sppio-use-case-title">Choose the path closest to your programme</h2>
            </div>
            <p className="sppio-use-case-desc">
              Each path leads to a short outline of the workflow, the controls involved, and what to confirm before a pilot.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            {[
              { title: 'Institutional Exams', desc: 'Explore onboarding for institutions and exam programs.', href: '/register-institution', action: 'Start institutional onboarding' },
              { title: 'Enterprise Hiring', desc: 'Review hiring and assessment workflows for employers.', href: '/solutions#solutions-grid', action: 'Explore hiring solutions' },
              { title: 'Technical Evaluation', desc: 'Discuss technical assessment requirements and deployment scope.', href: '#contact', action: 'Request a technical briefing' },
            ].map((item) => (
              <article key={item.title} className="sppio-use-case-card" style={{ border: '1px solid #DCD5D2', borderRadius: '12px', padding: '20px', background: '#FBF9F7' }}>
                <h3 style={{ fontSize: '17px', margin: '0 0 8px', color: '#302337' }}>{item.title}</h3>
                <p style={{ fontSize: '13px', lineHeight: 1.5, color: '#756F79', margin: '0 0 14px' }}>{item.desc}</p>
                <Link to={item.href} className="sppio-use-case-link">{item.action} →</Link>
              </article>
            ))}
          </div>
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
              <h2 className="sppio-section-title">Engineered for reviewable integrity.</h2>
            </div>
            <p className="sppio-section-desc">
              Four architectural pillars describing how high-stakes assessments are intended to run in an isolated station with reviewable audit evidence.
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
              Security is treated as an architectural property rather than a single detection layer: station policies, boot measurements, display handling, and audit chaining are separate control areas, each dependent on the hardware and configuration of the deployment.
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
                className="sppio-product-card"
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
                    <p>Boot measurements anchored in supported hardware, where the platform and firmware configuration allow them to be collected and verified.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong>Auditable Accountability</strong>
                    <p>Hash-linked audit records intended to make certain changes detectable, alongside separation of duties and dual-custody options for policy changes.</p>
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

              <p className="sppio-contact-note">
                Prefer the detail first?{' '}
                <Link to="/architecture">Review the control boundaries and deployment prerequisites</Link> before the call.
              </p>
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

      </main>

      <PublicFooter />

      {/* ----------------- Architecture Specs Modal ----------------- */}
      {showSpecModal && (
        <div className="polished-modal-backdrop" onClick={() => setShowSpecModal(false)}>
          <div
            className="polished-modal-dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Architecture specifications"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '640px' }}
          >
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
                  The examination environment is intended to run as a single-application session without an accessible desktop interface, background process access, or host key shortcuts. Display cloning, unauthorized peripheral connections, and external media are restricted by the configured station profile; verify coverage for the target hardware.
                </p>
              </div>

              <div>
                <strong style={{ display: 'block', color: '#B54F34', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.08em', marginBottom: '6px' }}>
                  3. Tamper-Evident Chained Audit Logging
                </strong>
                <p style={{ margin: 0, color: '#756F79' }}>
                  Supervisor interactions, candidate milestones, and workstation telemetry can be hash-linked into a tamper-evident event stream. Detectability depends on protected signing keys, independent checkpoints, and the verification evidence available for the deployment.
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
