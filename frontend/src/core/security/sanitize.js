// Strip control chars and angle brackets, trim, cap length. React escapes output; this is input hygiene.
export const clean = (s, max = 200) => String(s ?? '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, max);
export function safeHttpsUrl(u, allowHosts = []) {
  try {
    const x = new URL(u);
    if (x.protocol !== 'https:' || x.username || x.password) return null;
    if (allowHosts.length && !allowHosts.includes(x.hostname)) return null;
    return x.href;
  } catch { return null; }
}
// Open-redirect guard: only same-app absolute paths.
export const safeRedirect = (p) => (typeof p === 'string' && /^\/[a-z0-9\-/]*$/i.test(p) && !p.startsWith('//') ? p : '/');
// CSV formula-injection guard.
export const csvCell = (v) => {
  let s = String(v).replace(/"/g, '""');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s}"`;
};
