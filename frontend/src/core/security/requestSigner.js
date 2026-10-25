// ExamOS Console — ECDSA request signing (advanced security).
//
// Signs outgoing API requests so the C backend can verify the console's
// identity and request integrity. Uses Web Crypto (SubtleCrypto) with
// ECDSA over P-256 (SHA-256). The key is generated per workspace and the
// public half is persisted in IndexedDB for backend registration.

import { get, put } from '../db/db';

const KEY_ID = 'examos_console_signing_key';
const ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
const KEY_USAGES = ['sign'];

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(input)));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Canonicalizes a request into a deterministic string to sign.
async function canonicalRequest(method, url, body, headers) {
  const headersToSign = ['content-type', 'x-examos-console', 'x-examos-console-version', 'x-examos-request-id', 'x-examos-timestamp'];
  const h = {};
  for (const k of headersToSign) {
    const v = headers[k];
    if (v !== undefined && v !== null) h[k.toLowerCase()] = String(v).trim();
  }
  const headerList = Object.keys(h).sort().map((k) => `${k}:${h[k]}`).join('\n');
  const bodyHash = await sha256Hex(body || '');
  return [String(method).toUpperCase(), url, headerList, bodyHash].join('\n');
}

let signingKeyCache = null;
let keyPromise = null;

async function ensureSigningKey() {
  if (signingKeyCache) return signingKeyCache;
  if (keyPromise) return keyPromise;
  keyPromise = (async () => {
    let storedJwk = null;
    try {
      const stored = await get('keys', KEY_ID);
      if (stored?.privateJwk) storedJwk = stored.privateJwk;
    } catch { /* IndexedDB may be unavailable */ }

    let key;
    if (storedJwk) {
      key = await crypto.subtle.importKey('jwk', storedJwk, ALGO, true, KEY_USAGES);
    } else {
      const pair = await crypto.subtle.generateKey(ALGO, true, KEY_USAGES);
      key = pair.privateKey;
      try {
        const [privateJwk, publicJwk] = await Promise.all([
          crypto.subtle.exportKey('jwk', pair.privateKey),
          crypto.subtle.exportKey('jwk', pair.publicKey),
        ]);
        await put('keys', { id: KEY_ID, privateJwk, jwk: publicJwk, created_at: Date.now() });
      } catch { /* persistence optional */ }
    }
    signingKeyCache = key;
    return key;
  })();
  return keyPromise;
}

export async function getPublicKeyJwk() {
  await ensureSigningKey();
  const stored = await get('keys', KEY_ID);
  return stored?.jwk || null;
}

export async function signRequest(method, url, body = '', extraHeaders = {}) {
  const key = await ensureSigningKey();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const requestId = crypto.randomUUID?.() || `${timestamp}-${Math.random().toString(36).slice(2)}`;

  const headers = {
    'content-type': extraHeaders['content-type'] || 'application/json',
    'x-examos-console': '1',
    'x-examos-console-version': '2.18.4',
    'x-examos-request-id': requestId,
    'x-examos-timestamp': timestamp,
    ...extraHeaders,
  };

  const toSign = await canonicalRequest(method, url, body, headers);
  const sig = await crypto.subtle.sign(ALGO, key, new TextEncoder().encode(toSign));
  const signature = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');

  return {
    ...headers,
    'x-examos-signature': signature,
    'x-examos-signature-alg': 'ECDSA-P256-SHA256',
    'x-examos-signature-key-id': KEY_ID,
  };
}

export function verificationPayload(method, url, body, headers) {
  return canonicalRequest(method, url, body, headers);
}
