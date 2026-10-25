import { safeEqual } from './crypto';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const decode = (s) => {
  let bits = '';
  for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
};
// RFC 6238 TOTP (HMAC-SHA1, 30s, 6 digits) via WebCrypto.
export async function totp(secret, t = Date.now()) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(Math.floor(t / 30000)));
  const key = await crypto.subtle.importKey('raw', decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const o = h[19] & 15;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return String(n).padStart(6, '0');
}
export async function verifyTotp(secret, code) {
  let ok = false;
  for (const d of [-1, 0, 1]) if (safeEqual(await totp(secret, Date.now() + d * 30000), code)) ok = true;
  return ok;
}
export const newSecret = () => {
  const b = crypto.getRandomValues(new Uint8Array(20)); let bits = '', s = '';
  b.forEach((x) => { bits += x.toString(2).padStart(8, '0'); });
  for (let i = 0; i < bits.length; i += 5) s += B32[parseInt(bits.slice(i, i + 5), 2)];
  return s;
};
