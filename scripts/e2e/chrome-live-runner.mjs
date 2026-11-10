// chrome-live-runner.mjs
// Connects to running Chrome instance via DevToolsActivePort, drives UI, and captures screenshots
import fs from 'fs';
import path from 'path';

const devToolsPortPath = 'C:\\Users\\krant\\AppData\\Local\\Google\\Chrome\\User Data\\DevToolsActivePort';
const devToolsRaw = fs.readFileSync(devToolsPortPath, 'utf8').replace(/\r/g, '').trim().split('\n');
const port = devToolsRaw[0].trim();
const browserPath = devToolsRaw[1].trim();
const wsUrl = `ws://127.0.0.1:${port}${browserPath}`;

console.log(`[CHROME-RUNNER] Connecting to Chrome at: ${wsUrl}`);

const evidenceDir = 'D:\\SEB BRO\\evidence\\chrome-live-ui';
fs.mkdirSync(evidenceDir, { recursive: true });

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const pending = new Map();

    ws.onopen = () => {
      console.log('[CHROME-RUNNER] Connected to Chrome DevTools Protocol!');
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

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function run() {
  const { ws, send } = await connect();

  // 1. Create a new target page
  console.log('[CHROME-RUNNER] Creating new browser page for SPPIO...');
  const { targetId } = await send('Target.createTarget', { url: 'https://sppio-os.vercel.app/login' });
  console.log(`[CHROME-RUNNER] Created Target: ${targetId}`);

  // 2. Attach to target
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  console.log(`[CHROME-RUNNER] Attached with Session: ${sessionId}`);

  // Enable domains
  await send('Page.enable', {}, sessionId);
  await send('Runtime.enable', {}, sessionId);
  await send('DOM.enable', {}, sessionId);

  async function evalJs(expr) {
    const res = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId);
    if (res.exceptionDetails) {
      throw new Error(JSON.stringify(res.exceptionDetails));
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

  // Wait for login page load
  console.log('[CHROME-RUNNER] Waiting for React application hydration...');
  await sleep(4000);

  const initialUrl = await evalJs('window.location.href');
  console.log(`[CHROME-RUNNER] Initial URL: ${initialUrl}`);
  await takeScreenshot('01-login-screen');

  // Fill in credentials
  console.log('[CHROME-RUNNER] Entering credentials (admin / StrongAdminPassword#2026!)...');
  await evalJs(`
    const userInput = document.querySelector('input[type="text"]') || document.querySelector('input[name="username"]') || document.querySelectorAll('input')[0];
    const passInput = document.querySelector('input[type="password"]') || document.querySelectorAll('input')[1];
    if (userInput && passInput) {
      userInput.value = 'admin';
      userInput.dispatchEvent(new Event('input', { bubbles: true }));
      passInput.value = 'StrongAdminPassword#2026!';
      passInput.dispatchEvent(new Event('input', { bubbles: true }));
    }
  `);

  await sleep(1000);
  await takeScreenshot('02-credentials-entered');

  // Submit form
  console.log('[CHROME-RUNNER] Submitting login form...');
  await evalJs(`
    const submitBtn = document.querySelector('button[type="submit"]') || document.querySelector('.polished-submit-btn') || Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Sign') || b.innerText.includes('Log'));
    if (submitBtn) submitBtn.click();
  `);

  await sleep(3500);
  const afterLoginUrl = await evalJs('window.location.href');
  console.log(`[CHROME-RUNNER] Post-login URL: ${afterLoginUrl}`);
  await takeScreenshot('03-post-submit-screen');

  // Check if MFA is shown
  const isMfa = await evalJs(`document.body.innerText.includes('Verification') || document.body.innerText.includes('MFA') || document.body.innerText.includes('code') || !!document.querySelector('input[autocomplete="one-time-code"]')`);
  console.log(`[CHROME-RUNNER] MFA Screen Detected: ${isMfa}`);

  // Test Navigation to Platform Institutions
  console.log('[CHROME-RUNNER] Testing Navigation to /platform/institutions...');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/platform/institutions' }, sessionId);
  await sleep(3000);
  await takeScreenshot('04-platform-institutions');

  // Test Navigation to Registration
  console.log('[CHROME-RUNNER] Testing Navigation to /register-institution...');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/register-institution' }, sessionId);
  await sleep(3000);
  await takeScreenshot('05-register-institution');

  // Test Navigation to Candidate Login
  console.log('[CHROME-RUNNER] Testing Navigation to /candidate-login...');
  await send('Page.navigate', { url: 'https://sppio-os.vercel.app/candidate-login' }, sessionId);
  await sleep(3000);
  await takeScreenshot('06-candidate-login');

  console.log('[CHROME-RUNNER] Browser UI testing completed successfully!');
  ws.close();
}

run().catch(err => {
  console.error('[CHROME-RUNNER] ERROR:', err);
  process.exit(1);
});
