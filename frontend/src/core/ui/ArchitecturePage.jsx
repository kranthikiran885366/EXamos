import { useState } from 'react';
import { SppioSymbol } from './SppioLogo';
import PublicHeader from './PublicHeader';
import PublicFooter from './PublicFooter';
import SppioShowcase from './SppioShowcase';
import usePageMeta from './usePageMeta';

export default function ArchitecturePage() {
  usePageMeta({
    title: 'Architecture | SPPIO Open Aperture Control Boundaries',
    description:
      'How SPPIO assessment stations are intended to attest, isolate, and record activity, with the deployment boundaries, prerequisites, and limits of each control area.',
    path: '/architecture',
  });

  const [activeStep, setActiveStep] = useState(0);

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
      <PublicHeader active="architecture" />

      <main id="main-content">

      {/* ---------------- Hero Section ---------------- */}
      <section className="sppio-hero-section" style={{ padding: '72px 0 80px' }}>
        <div className="sppio-container">
          <div className="sppio-hero-split">
            <div>
              <div className="sppio-kicker-badge">
                <span className="sppio-kicker-dot" />
                <span>Open Aperture &middot; Architecture &amp; control boundaries</span>
              </div>

              <h1 className="sppio-hero-headline" style={{ maxWidth: '720px' }}>
                Zero-trust execution.<br />
                <span className="sppio-highlight">Silicon-rooted recruitment &amp; assessment integrity.</span>
              </h1>

              <p className="sppio-hero-lead" style={{ maxWidth: '640px' }}>
                An overview of the intended system boundaries and controls for assessment workstations.
                Actual protections depend on supported hardware, deployment configuration, and the policies
                enabled for each institution.
              </p>

              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '24px' }}>
                <a href="#attestation" className="sppio-btn-primary">
                  Inspect attestation sequence
                  <span aria-hidden="true">&darr;</span>
                </a>
                <a href="#threat-model" className="sppio-btn-ghost">
                  Review threat model
                </a>
              </div>
            </div>

            <SppioShowcase compact caption="Control boundaries, expressed as one layered station architecture." />
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
              A supported station can measure selected boot components before an assessment session. Coverage, enforcement, and verification evidence depend on the hardware, firmware configuration, and policy of the deployment.
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
                className="sppio-threat-row"
                style={{
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
                <div className="sppio-threat-status" style={{ textAlign: 'right' }}>
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
                    <p style={{ color: '#756F79' }}>An offline verification tool is intended to check chain integrity without network connectivity. Confirm availability, versioning, and operator procedure for the deployment.</p>
                  </div>
                </div>
                <div className="sppio-pillar-item">
                  <span className="sppio-pillar-mark" />
                  <div>
                    <strong style={{ color: '#302337' }}>Two-Person Dual-Custody</strong>
                    <p style={{ color: '#756F79' }}>Separation of duties can require dual administrative sign-off for policy changes. Confirm the configured approval model.</p>
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

      </main>

      <PublicFooter />
    </div>
  );
}
