import { useEffect, useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { can } from '../security/rbac';

/** Small async loader with an explicit reload trigger. */
export function useLoad(fn, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [n, setN] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve().then(fn)
      .then((data) => live && setState({ data, error: null, loading: false }))
      .catch((error) => live && setState({ data: null, error, loading: false }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n]);
  return { ...state, reload: () => setN((x) => x + 1) };
}

/** Permission helper bound to the signed-in user. */
export function usePerm() {
  const { user } = useAuth();
  return (p) => !p || can(user?.role, p);
}

export const when = (ok, node) => (ok ? node : null);
export const pctOf = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
