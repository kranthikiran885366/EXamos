import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { all, onChange } from './db';
import { useAuth } from '../auth/AuthContext';
import { isGlobal } from '../security/rbac';

const T = createContext({ tenantId: null, tenant: null, tenants: [], setTenantId() {} });
export const useTenant = () => useContext(T);

export function TenantProvider({ children }) {
  const { user } = useAuth();
  const [tenants, setTenants] = useState([]);
  const [tenantId, setTenantId] = useState(null);

  const allowed = useMemo(() => {
    if (!user) return [];
    if (isGlobal(user.role)) return tenants;
    return tenants.filter((t) => t.id === user.tenantId);
  }, [tenants, user]);

  useEffect(() => {
    const load = async () => {
      const t = await all('tenants'); setTenants(t);
    };
    load(); return onChange((c) => c === 'tenants' && load());
  }, []);

  useEffect(() => {
    if (!user) return;
    setTenantId((cur) => {
      if (cur && allowed.some((x) => x.id === cur)) return cur;
      if (user.tenantId && allowed.some((x) => x.id === user.tenantId)) return user.tenantId;
      return (allowed.find((x) => x.status === 'active') || allowed[0])?.id || null;
    });
  }, [allowed, user]);

  const tenant = tenants.find((t) => t.id === tenantId) || null;
  return <T.Provider value={{ tenantId, tenant, tenants: allowed, allTenants: tenants, setTenantId }}>{children}</T.Provider>;
}

// Live collection hook: re-reads when any tab/service writes the collection. Tenant-scoped by default.
export function useCol(name, scoped = true) {
  const { tenantId } = useTenant();
  const [rows, setRows] = useState([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let live = true;
    const load = async () => { const r = await all(name); if (live) { setRows(r); setLoaded(true); } };
    load(); const off = onChange((c) => c === name && load());
    return () => { live = false; off(); };
  }, [name]);
  const data = useMemo(() => (scoped ? rows.filter((r) => r.tenantId === tenantId) : rows), [rows, scoped, tenantId]);
  return data;
}

export function useColLoaded(name, scoped = true) {
  const { tenantId } = useTenant();
  const [state, setState] = useState({ rows: [], loaded: false });
  useEffect(() => {
    let live = true;
    const load = async () => { const r = await all(name); if (live) setState({ rows: r, loaded: true }); };
    load(); const off = onChange((c) => c === name && load());
    return () => { live = false; off(); };
  }, [name]);
  const rows = useMemo(() => (scoped ? state.rows.filter((r) => r.tenantId === tenantId) : state.rows), [state.rows, scoped, tenantId]);
  return { rows, loaded: state.loaded };
}

export function useAsync(fn, deps = [], initial = null) {
  const [state, setState] = useState({ data: initial, loading: true, error: null });
  useEffect(() => {
    let live = true; setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve().then(fn).then((data) => live && setState({ data, loading: false, error: null })).catch((e) => live && setState({ data: initial, loading: false, error: e }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}

export function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}
