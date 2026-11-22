export const normalizeTimeMs = (t) => {
  if (!t || t === 0 || t === '0') return null;
  const n = typeof t === 'string' ? Number(t) : t;
  if (typeof n !== 'number' || isNaN(n) || n <= 0) return null;
  // If in seconds (e.g. < 1e11), convert to milliseconds
  return n < 1e11 ? n * 1000 : n;
};

export const fmt = (t) => {
  const ms = normalizeTimeMs(t);
  return ms ? new Date(ms).toLocaleString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
};

export const ist = (t = Date.now()) => {
  const ms = normalizeTimeMs(t) || Date.now();
  return new Date(ms).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
};

export const ago = (t) => {
  const ms = normalizeTimeMs(t);
  if (!ms) return 'never';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
};

export const hms = (ms) => {
  const validMs = normalizeTimeMs(ms) ?? (typeof ms === 'number' && ms > 0 ? ms : 0);
  const s = Math.max(0, Math.floor(validMs / 1000));
  return [Math.floor(s / 3600), Math.floor(s / 60) % 60, s % 60].map((n) => String(n).padStart(2, '0')).join(':');
};
