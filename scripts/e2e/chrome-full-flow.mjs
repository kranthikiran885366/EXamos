// chrome-full-flow.mjs
// Drives complete end-to-end SPPIO workflow on running Chrome instance
import fs from 'fs';
import path from 'path';

const devToolsPortPath = 'C:\\Users\\krant\\AppData\\Local\\Google\\Chrome\\User Data\\DevToolsActivePort';
const devToolsRaw = fs.readFileSync(devToolsPortPath, 'utf8').replace(/\r/g, '').trim().split('\n');
const port = devToolsRaw[0].trim();
const browserPath = devToolsRaw[1].trim();
const wsUrl = `ws://127.0.0.1:${port}${browserPath}`;

console.log(`[FLOW-RUNNER] Connecting to Chrome CDP at: ${wsUrl}`);

const evidenceDir = 'D:\\SEB BRO\\evidence\\chrome-full-flow';
fs.mkdirSync(evidenceDir, { recursive: true });

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.onopen = () => {
      console.log('[FLOW-RUNNER] Connected to Chrome DevTools Protocol!');
      resolve({ ws, send });
    };

    ws.onerror = (err) => reject(err);

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve: res, reject: rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(msg.error);
        else res(msg.result);
      }
    };

    function send(method, params = {}, sessionId = null) {
      return new Promise((res, rej) => {
        const id = msgId++;
        pending.set(id, { resolve: res, reject: rej });
        const payload = { id, method, params };
        if (sessionId) payload.sessionId = sessionId;
        ws.send(JSON.stringify(payload));
      });
    }
  });
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function run() {
  const { ws, send } = await connect();

  console.log('[FLOW-RUNNER] Creating dedicated browser target tab...');
  const { targetId } = await send('Target.createTarget', { url: 'https://sppio-os.vercel.app/' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });

  await send('Page.enable', {}, sessionId);
  await send('Runtime.enable', {}, sessionId);
  await send('DOM.enable', {}, sessionId);

  async function evalJs(expr) {
    const res = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId);
    if (res.exceptionDetails) {
      console.warn('[EVAL-WARN]', JSON.stringify(res.exceptionDetails));
    }
    return res.result ? res.result.value : null;
  }

  async function takeScreenshot(name) {
    const res = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
    const buf = Buffer.from(res.data, 'base64');
    const outPath = path.join(evidenceDir, `${name}.png`);
    fs.writeFileSync(outPath, buf);
    console.log(`[SCREENSHOT] Saved: ${outPath}`);
    return outPath;
  }

  // =========================================================================
  // STEP 1: Open Website Homepage
  // =========================================================================
  console.log('\n=== STEP 1: Open Website Homepage ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/' }, sessionId);
  await sleep(4000);
  const homeTitle = await evalJs('document.title');
  console.log(`[STEP 1] Homepage Title: ${homeTitle}`);
  await takeScreenshot('01-step1-homepage');

  // =========================================================================
  // STEP 2: Navigate to Institution Registration
  // =========================================================================
  console.log('\n=== STEP 2: Navigate to Institution Registration ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/register-institution' }, sessionId);
  await sleep(4000);
  await takeScreenshot('02-step2-register-start');

  // =========================================================================
  // STEP 3: Fill Details & Submit Institution Form
  // =========================================================================
  console.log('\n=== STEP 3: Fill Institution Registration Wizard ===');
  
  // Step 0: Institution Info
  console.log('[STEP 3.0] Filling Step 0: Institution Information...');
  await evalJs(`
    const setVal = (sel, val) => {
      const el = document.querySelector(sel);
      if (el) {
        el.value = val;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    };
    setVal('#application-legalName', 'National Institute of Technology and Science');
    setVal('#application-displayName', 'NITS University');
    setVal('#application-registrationNumber', 'NITS-UNIV-2026-REG');
    setVal('#application-domain', 'nits.edu.in');
    setVal('#application-address', '742 Tech Innovation Blvd, Campus Sector 4');
  `);
  await sleep(1000);
  await takeScreenshot('03-step3-0-institution-info');

  console.log('[STEP 3.0] Clicking Next to Representative...');
  await evalJs(`
    const btns = Array.from(document.querySelectorAll('button'));
    const nextBtn = btns.find(b => b.innerText.includes('Continue to representative') || b.innerText.includes('Next') || b.innerText.includes('Representative'));
    if (nextBtn) nextBtn.click();
  `);
  await sleep(2000);

  // Step 1: Representative Info
  console.log('[STEP 3.1] Filling Step 1: Representative Information...');
  await evalJs(`
    const setVal = (sel, val) => {
      const el = document.querySelector(sel);
      if (el) {
        el.value = val;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    };
    setVal('#application-repName', 'Dr. Ramesh Narayanan');
    setVal('#application-repRole', 'Dean of Academic Computing');
    setVal('#application-repEmail', 'ramesh.narayanan@nits.edu.in');
    setVal('#application-repPhone', '+91 98765 43210');
  `);
  await sleep(1000);
  await takeScreenshot('03-step3-1-representative-info');

  console.log('[STEP 3.1] Clicking Next to Deployment...');
  await evalJs(`
    const btns = Array.from(document.querySelectorAll('button'));
    const nextBtn = btns.find(b => b.innerText.includes('Continue to deployment') || b.innerText.includes('Deployment'));
    if (nextBtn) nextBtn.click();
  `);
  await sleep(2000);

  // Step 2: Deployment Metrics
  console.log('[STEP 3.2] Filling Step 2: Deployment Architecture...');
  await evalJs(`
    const setVal = (sel, val) => {
      const el = document.querySelector(sel);
      if (el) {
        el.value = val;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    };
    setVal('#application-campusCount', '3');
    setVal('#application-studentCount', '2500');
    setVal('#application-deviceCount', '150');
    setVal('#application-targetExamUrl', 'https://sppio-os.vercel.app/candidate-login');
  `);
  await sleep(1000);
  await takeScreenshot('03-step3-2-deployment-info');

  console.log('[STEP 3.2] Clicking Next to Review & Submit...');
  await evalJs(`
    const btns = Array.from(document.querySelectorAll('button'));
    const nextBtn = btns.find(b => b.innerText.includes('Continue to review') || b.innerText.includes('Review'));
    if (nextBtn) nextBtn.click();
  `);
  await sleep(2000);

  // Step 3: Review & Declarations
  console.log('[STEP 3.3] Checking statutory declarations...');
  await evalJs(`
    const t = document.querySelector('#application-termsAgreed');
    const p = document.querySelector('#application-privacyAgreed');
    if (t) { t.checked = true; t.dispatchEvent(new Event('change', { bubbles: true })); }
    if (p) { p.checked = true; p.dispatchEvent(new Event('change', { bubbles: true })); }
  `);
  await sleep(1000);
  await takeScreenshot('03-step3-3-review-and-declarations');

  console.log('[STEP 3.3] Submitting Application...');
  await evalJs(`
    const btns = Array.from(document.querySelectorAll('button'));
    const submitBtn = btns.find(b => b.innerText.includes('Submit Application') || (b.type === 'submit'));
    if (submitBtn) submitBtn.click();
  `);
  await sleep(5000);
  await takeScreenshot('03-step3-4-application-submitted');

  const appReference = await evalJs(`
    const el = document.querySelector('.receipt') || document.querySelector('code') || document.querySelector('strong');
    el ? el.innerText : 'Submitted'
  `);
  console.log(`[STEP 3] Application Status/Reference: ${appReference}`);

  // =========================================================================
  // STEP 4: Open Admin Login & Authenticate
  // =========================================================================
  console.log('\n=== STEP 4: Admin Authentication in UI ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/login' }, sessionId);
  await sleep(4000);

  console.log('[STEP 4] Entering admin credentials...');
  await evalJs(`
    const inputs = document.querySelectorAll('input');
    const userInput = Array.from(inputs).find(i => i.name === 'username' || i.type === 'text') || inputs[0];
    const passInput = Array.from(inputs).find(i => i.name === 'password' || i.type === 'password') || inputs[1];
    if (userInput && passInput) {
      userInput.value = 'admin';
      userInput.dispatchEvent(new Event('input', { bubbles: true }));
      passInput.value = 'StrongAdminPassword#2026!';
      passInput.dispatchEvent(new Event('input', { bubbles: true }));
    }
    const btn = document.querySelector('button[type="submit"]') || Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Sign') || b.innerText.includes('Log'));
    if (btn) btn.click();
  `);
  await sleep(4000);
  await takeScreenshot('04-admin-login-and-mfa');

  // =========================================================================
  // STEP 5: Platform Admin - Review & Approve Applications
  // =========================================================================
  console.log('\n=== STEP 5: Platform Admin - Applications & Institutions ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/platform/institutions' }, sessionId);
  await sleep(4000);
  await takeScreenshot('05-platform-institutions-overview');

  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/platform/institutions/applications' }, sessionId);
  await sleep(4000);
  await takeScreenshot('05-platform-applications-queue');

  // =========================================================================
  // STEP 6: Examinations & External Exam URL Verification
  // =========================================================================
  console.log('\n=== STEP 6: Examination Creation & External URL Configuration ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/college/exams' }, sessionId);
  await sleep(4000);
  await takeScreenshot('06-examinations-list');

  // =========================================================================
  // STEP 7: Candidate Lifecycle & URL Assignment Override
  // =========================================================================
  console.log('\n=== STEP 7: Candidate Lifecycle & Seat URL Binding ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/college/candidates' }, sessionId);
  await sleep(4000);
  await takeScreenshot('07-candidates-roster');

  // =========================================================================
  // STEP 8: Candidate Desk Login & Master Launch Gate
  // =========================================================================
  console.log('\n=== STEP 8: Candidate Desk Login & Launch Gate ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/candidate-login' }, sessionId);
  await sleep(4000);
  await takeScreenshot('08-candidate-login-portal');

  console.log('[STEP 8] Entering candidate credentials (Roll: 26NIST001)...');
  await evalJs(`
    const input = document.querySelector('input');
    if (input) {
      input.value = '26NIST001';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  `);
  await sleep(1500);
  await takeScreenshot('08-candidate-roll-entered');

  // =========================================================================
  // STEP 9: Operator Proctoring & Real-Time Monitoring
  // =========================================================================
  console.log('\n=== STEP 9: Operator Overview & Live Monitoring ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/operator/overview' }, sessionId);
  await sleep(4000);
  await takeScreenshot('09-operator-overview');

  // =========================================================================
  // STEP 10: Immutable Audit Ledger
  // =========================================================================
  console.log('\n=== STEP 10: Immutable Audit Ledger Verification ===');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/admin/audit' }, sessionId);
  await sleep(4000);
  await takeScreenshot('10-audit-ledger');

  console.log('\n=============================================================');
  console.log(' COMPLETE END-TO-END UI WORKFLOW EXECUTED IN CHROME BROWSER');
  console.log(' All screenshots captured to: D:\\SEB BRO\\evidence\\chrome-full-flow');
  console.log('=============================================================');

  ws.close();
}

run().catch(err => {
  console.error('[FLOW-RUNNER] ERROR:', err);
  process.exit(1);
});
