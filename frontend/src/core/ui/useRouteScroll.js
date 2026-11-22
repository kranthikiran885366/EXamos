import { useEffect } from 'react';
import { useLocation, useNavigationType } from 'react-router-dom';

function hashTarget(hash) {
  const raw = hash.slice(1);
  if (!raw) return null;
  try {
    return document.getElementById(decodeURIComponent(raw));
  } catch {
    return document.getElementById(raw);
  }
}

/**
 * SPA navigation does not reset scroll position or honour in-page hashes the
 * way a full page load does. This keeps the public navigation predictable:
 * pushed routes start at the top, and hash links land on their section once it
 * has rendered (with a short retry for lazily rendered routes).
 */
export default function useRouteScroll() {
  const { pathname, hash } = useLocation();
  const navigationType = useNavigationType();

  useEffect(() => {
    if (navigationType !== 'PUSH' || hash) return;
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [pathname, hash, navigationType]);

  useEffect(() => {
    if (!hash) return undefined;

    let frame = 0;
    let attempts = 0;

    const scrollToHash = () => {
      const target = hashTarget(hash);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }
      if (attempts < 20) {
        attempts += 1;
        frame = requestAnimationFrame(scrollToHash);
      }
    };

    frame = requestAnimationFrame(scrollToHash);
    return () => cancelAnimationFrame(frame);
  }, [pathname, hash]);
}
