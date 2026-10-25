const enc = new TextEncoder();
export const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
export const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
export async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 210000 }, k, 256));
}
export const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};
export const randomId = (n = 6) => hex(crypto.getRandomValues(new Uint8Array(n)));
export const corrId = () => 'cor_' + randomId(4) + '..' + randomId(2);
export const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((c) => { s += String.fromCharCode(c); }); return btoa(s); };
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sortKeys = (o) => (Array.isArray(o) ? o.map(sortKeys) : o && typeof o === 'object' ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])])) : o);
export const canon = (o) => JSON.stringify(sortKeys(o));
// ECDSA P-256: private keys are non-extractable CryptoKeys persisted in IndexedDB.
export const genKeyPair = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
export const sign = async (priv, data) => b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode(data)));
export async function verify(jwk, data, sig) {
  try {
    const k = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, unb64(sig), enc.encode(data));
  } catch { return false; }
}
