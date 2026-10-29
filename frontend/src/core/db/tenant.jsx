import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { all, onChange } from './db';
import { useAuth } from '../auth/AuthContext';
import { isGlobal } from '../security/rbac';

const TENANT_STORAGE_KEY = 'examos_selected_tenant_id';

const T = createContext({ tenantId: null, tenant: null, tenants: [], setTenantId() {} });
export const useTenant = () => useContext(T);

export function TenantProvider({ children }) {
  const { user } = useAuth();
  const [tenants, setTenants] = useState([]);
  const [tenantId, setTenantIdState] = useState(() => {
    try {
      return localStorage.getItem(TENANT_STORAGE_KEY) || null;
    } catch {
      return null;
    }
  });

  const setTenantId = (newId) => {
    setTenantIdState(newId);
    try {
      if (newId) {
        localStorage.setItem(TENANT_STORAGE_KEY, newId);
      } else {
        localStorage.removeItem(TENANT_STORAGE_KEY);
      }
    } catch {}
  };

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

  // Synchronize across browser tabs when user changes institution in another tab
  useEffect(() => {
    const onStorage = (e) => {
      if (e.key === TENANT_STORAGE_KEY && e.newValue) {
        setTenantIdState(e.newValue);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  useEffect(() => {
    if (!user || allowed.length === 0) return;
    setTenantIdState((cur) => {
      // 1. If currently selected institution is valid in allowed list, keep it!
      if (cur && allowed.some((x) => x.id === cur)) {
        try { localStorage.setItem(TENANT_STORAGE_KEY, cur); } catch {}
        return cur;
      }
      // 2. Check if localStorage has a valid stored institution
      try {
        const saved = localStorage.getItem(TENANT_STORAGE_KEY);
        if (saved && allowed.some((x) => x.id === saved)) {
          return saved;
        }
      } catch {}
      // 3. Fallback to user's assigned tenant if applicable
      if (user.tenantId && allowed.some((x) => x.id === user.tenantId)) {
        try { localStorage.setItem(TENANT_STORAGE_KEY, user.tenantId); } catch {}
        return user.tenantId;
      }
      // 4. Fallback to first active or available tenant
      const fallback = (allowed.find((x) => x.status === 'active') || allowed[0])?.id || null;
      if (fallback) {
        try { localStorage.setItem(TENANT_STORAGE_KEY, fallback); } catch {}
      }
      return fallback;
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
