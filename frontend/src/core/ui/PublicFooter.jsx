import { Link } from 'react-router-dom';
import SppioLogo from './SppioLogo';

const backToTop = (event) => {
  event.preventDefault();
  document.getElementById('top')?.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
};

export default function PublicFooter() {
  return (
    <footer className="sppio-footer" role="contentinfo">
      <div className="sppio-container">
        <div className="sppio-footer-grid">
          <div className="sppio-footer-brand">
            <SppioLogo width={160} accent="#B54F34" ink="#FFFFFF" />
            <p>
              Open Aperture architecture. High-assurance infrastructure engineered for national,
              institutional, and corporate assessment integrity.
            </p>
            <p className="sppio-footer-note">
              Public product information. Confirm current capabilities, deployment prerequisites,
              and assurance evidence before procurement.
            </p>
          </div>

          <div className="sppio-footer-col">
            <h5>Platform</h5>
            <ul className="sppio-footer-links">
              <li><Link to="/landing">Platform overview</Link></li>
              <li><Link to="/architecture">Architecture</Link></li>
              <li><Link to="/solutions">Solutions</Link></li>
              <li><Link to="/landing#capabilities">Capabilities</Link></li>
              <li><Link to="/landing#deployments">Deployments</Link></li>
            </ul>
          </div>

          <div className="sppio-footer-col">
            <h5>Governance</h5>
            <ul className="sppio-footer-links">
              <li><Link to="/architecture#threat-model">Threat model</Link></li>
              <li><Link to="/architecture#ledger">Audit chaining</Link></li>
              <li><Link to="/architecture#deployment">Deployment boundaries</Link></li>
              <li><a href="mailto:security@sppio.io">Responsible disclosure</a></li>
            </ul>
          </div>

          <div className="sppio-footer-col">
            <h5>Console access</h5>
            <ul className="sppio-footer-links">
              <li><Link to="/login" className="sppio-footer-cta">Console sign in →</Link></li>
              <li><Link to="/candidate-login">Candidate station login</Link></li>
              <li><Link to="/register-institution">Institution onboarding</Link></li>
              <li><Link to="/register-institution?tab=track">Track application</Link></li>
              <li><a href="mailto:briefings@sppio.io">Briefings contact</a></li>
            </ul>
          </div>
        </div>

        <div className="sppio-footer-bottom">
          <div>© 2026 SPPIO Systems Enclave. All rights reserved. Open Aperture architecture.</div>
          <div className="sppio-legal-links">
            <Link to="/landing">Platform home</Link>
            <a href="#top" onClick={backToTop}>Back to top ↑</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
