import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { all, del, putMany, onChange, watchCollection } from './db';
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

  // Purge legacy mock/seed institution T1 on startup
  useEffect(() => {
    del('tenants', 'T1').catch(() => {});
    try {
      if (localStorage.getItem(TENANT_STORAGE_KEY) === 'T1') {
        localStorage.removeItem(TENANT_STORAGE_KEY);
        setTenantIdState(null);
      }
    } catch {}
  }, []);

  const allowed = useMemo(() => {
    if (!user) return [];
    // Strict zero-fabrication: Never include fake seed institution T1
    const realTenants = tenants.filter((t) => t.id !== 'T1');
    if (isGlobal(user.role)) return realTenants;
    return realTenants.filter((t) => t.id === user.tenantId);
  }, [tenants, user]);

  useEffect(() => {
    if (!user) {
      setTenants([]);
      return undefined;
    }
    let active = true;
    const load = async () => {
      try {
        const t = await all('tenants');
        const clean = (t || []).filter((x) => x.id !== 'T1');
        if (active) setTenants(clean);
        // Synchronize genuine provisioned institutions from backend
        import('../api/services').then(({ listInstitutions }) => {
          listInstitutions()
            .then(async (remote) => {
              if (Array.isArray(remote) && remote.length > 0) {
                const genuine = remote.filter((r) => r.id !== 'T1');
                await putMany('tenants', genuine);
                if (active) setTenants(genuine);
              }
            })
            .catch(() => {});
        }).catch(() => {});
      } catch (error) {
        console.error('Failed to load institutions from the backend.', error);
      }
    };
    load();
    const off = onChange((c) => c === 'tenants' && load());
    const unwatch = watchCollection('tenants', (rows, error) => {
      if (error) console.error('Failed to refresh institutions from the backend.', error);
      else if (active) setTenants(rows);
    });
    return () => { active = false; off(); unwatch(); };
  }, [user]);

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
    const load = async () => {
      try {
        const r = await all(name);
        if (live) { setRows(r); setLoaded(true); }
      } catch (error) {
        if (live) {
          setRows([]);
          setLoaded(true);
          console.error(`Failed to load ${name} from the backend.`, error);
        }
      }
    };
    load();
    const off = onChange((c) => c === name && load());
    const unwatch = watchCollection(name, (records, error) => {
      if (error) {
        if (live) { setRows([]); console.error(`Failed to refresh ${name} from the backend.`, error); }
      } else if (live) setRows(records);
    });
    return () => { live = false; off(); unwatch(); };
  }, [name]);
  const data = useMemo(() => (scoped ? rows.filter((r) => r.tenantId === tenantId) : rows), [rows, scoped, tenantId]);
  return data;
}

export function useColLoaded(name, scoped = true) {
  const { tenantId } = useTenant();
  const [state, setState] = useState({ rows: [], loaded: false });
  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const r = await all(name);
        if (live) setState({ rows: r, loaded: true, error: null });
      } catch (error) {
        if (live) setState({ rows: [], loaded: true, error });
      }
    };
    load();
    const off = onChange((c) => c === name && load());
    const unwatch = watchCollection(name, (records, error) => {
      if (live) setState({ rows: error ? [] : records, loaded: true, error: error || null });
    });
    return () => { live = false; off(); unwatch(); };
  }, [name]);
  const rows = useMemo(() => (scoped ? state.rows.filter((r) => r.tenantId === tenantId) : state.rows), [state.rows, scoped, tenantId]);
  return { rows, loaded: state.loaded, error: state.error };
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
