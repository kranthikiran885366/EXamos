import { useEffect, useRef, useState } from 'react';

// Locks the console after `idleMs` of no input and hard-logs-out after `maxMs`.
// Also exposes a warning window so the shell can show a session-expiry banner.
export function useSessionGuard({ idleMs, maxMs, onIdle, onExpire, active, warnMs = 45000 }) {
  const t = useRef(Date.now());
  const [warning, setWarning] = useState(0);
  useEffect(() => {
    if (!active) { setWarning(0); return; }
    const start = Date.now();
    t.current = start;
    const bump = () => { t.current = Date.now(); setWarning(0); };
    const ev = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'];
    ev.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    const id = setInterval(() => {
      const idle = Date.now() - t.current;
      const left = idleMs - idle;
      if (Date.now() - start > maxMs) onExpire();
      else if (left <= 0) onIdle();
      else if (left <= warnMs) setWarning(left);
      else setWarning(0);
    }, 1000);
    return () => { ev.forEach((e) => window.removeEventListener(e, bump)); clearInterval(id); };
  }, [active, idleMs, maxMs, onIdle, onExpire, warnMs]);
  return warning;
}
