import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { all, onChange, watchCollection } from './db';
import { useAuth } from '../auth/AuthContext';
import { isGlobal } from '../security/rbac';
import { getInstitution, listInstitutions } from '../api/services';
import { canonicalPlan } from '../ui/normalizers';

const TENANT_STORAGE_KEY = 'examos_selected_tenant_id';

const T = createContext({ tenantId: null, tenant: null, tenants: [], loading: false, error: '', setTenantId() {} });
export const useTenant = () => useContext(T);

export function TenantProvider({ children }) {
  const { user } = useAuth();
  const [tenants, setTenants] = useState([]);
  const [loading, setLoading] = useState(false);
  const [tenantsLoaded, setTenantsLoaded] = useState(false);
  const [error, setError] = useState('');
  const [tenantId, setTenantIdState] = useState(() => {
    try {
      return localStorage.getItem(TENANT_STORAGE_KEY) || null;
    } catch {
      return null;
    }
  });

  const setTenantId = (newId) => {
    // Normalise: find the canonical `id` in the allowed list so the stored
    // key always matches what the backend returns as the primary identifier.
    const canonical = newId
      ? (allowed.find((x) => x.id === newId || x.institution_id === newId)?.id || newId)
      : null;
    setTenantIdState(canonical);
    try {
      if (canonical) {
        localStorage.setItem(TENANT_STORAGE_KEY, canonical);
      } else {
        localStorage.removeItem(TENANT_STORAGE_KEY);
      }
    } catch {}
  };

  const refreshTenants = useCallback(async () => {
    if (!user) {
      setTenants([]);
      setLoading(false);
      setTenantsLoaded(true);
      setError('');
      return;
    }
    setLoading(true);
    setTenantsLoaded(false);
    setError('');
    try {
      let rows;
      if (user.role === 'superadmin') {
        const response = await listInstitutions();
        rows = response?.institutions || response;
        if (!Array.isArray(rows)) throw new Error('The institution endpoint returned an unexpected response.');
      } else if (user.tenantId) {
        const response = await getInstitution(user.tenantId);
        const institution = response?.institution || response;
        if (!institution || (institution.id || institution.institution_id) !== user.tenantId) {
          throw new Error("The backend did not return the signed-in user's institution.");
        }
        rows = [institution];
      } else {
        rows = [];
      }
      const records = rows.map((row) => ({
        ...row,
        id: row.id || row.institution_id,
        tenantId: row.id || row.institution_id,
        entityType: row.entityType || row.entity_type || '',
        maxCenters: row.maxCenters ?? row.max_centers ?? null,
        maxCandidates: row.maxCandidates ?? row.max_candidates ?? null,
        contactEmail: row.contactEmail || row.contact_email || '',
        contactPhone: row.contactPhone || row.contact_phone || '',
        createdAt: row.createdAt || row.created_at || null,
        planId: canonicalPlan(row),
        plan: canonicalPlan(row),
      })).filter((row) => row.id);
      setTenants(records);
    } catch (loadError) {
      setTenants([]);
      setError(loadError.message || 'Failed to load institutions from the backend.');
      throw loadError;
    } finally {
      setLoading(false);
      setTenantsLoaded(true);
    }
  }, [user]);

  const allowed = useMemo(() => {
    if (!user) return [];
    if (isGlobal(user.role)) return tenants;
    return tenants.filter((t) => t.id === user.tenantId);
  }, [tenants, user]);

  useEffect(() => {
    if (!user) {
      setTenants([]);
      setLoading(false);
      setError('');
      return undefined;
    }
    refreshTenants().catch((loadError) => {
      console.error('Failed to load institutions from the backend.', loadError);
    });
    return undefined;
  }, [user, refreshTenants]);

  useEffect(() => {
    const refresh = () => {
      refreshTenants().catch((loadError) => {
        console.error('Failed to refresh institutions from the backend.', loadError);
      });
    };
    window.addEventListener('examos:institution-change', refresh);
    return () => window.removeEventListener('examos:institution-change', refresh);
  }, [refreshTenants]);

  // Synchronize across browser tabs when user changes institution in another tab
  useEffect(() => {
    const onStorage = (e) => {
      if (e.key === TENANT_STORAGE_KEY && e.newValue) {
        // Validate the incoming value is still in the allowed list before applying.
        const incoming = e.newValue;
        setTenantIdState((cur) => {
          const valid = allowed.some((x) => x.id === incoming || x.institution_id === incoming);
          if (!valid) return cur;
          const canonical = allowed.find((x) => x.id === incoming || x.institution_id === incoming)?.id || incoming;
          return canonical;
        });
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [allowed]);

  useEffect(() => {
    if (!user || loading || !tenantsLoaded || error) return;
    if (allowed.length === 0) {
      setTenantIdState(null);
      try { localStorage.removeItem(TENANT_STORAGE_KEY); } catch {}
      return;
    }
    // Normalise: backend may return institution_id or id; both are valid keys.
    const inAllowed = (id) => id && allowed.some((x) => x.id === id || x.institution_id === id);
    const canonicalId = (id) => {
      if (!id) return null;
      const match = allowed.find((x) => x.id === id || x.institution_id === id);
      return match ? match.id : null;
    };

    // 1. Read the persisted selection directly — do NOT rely on the stale
    //    `cur` closure value inside a setter, which races with re-renders.
    let saved = null;
    try { saved = localStorage.getItem(TENANT_STORAGE_KEY); } catch {}

    if (inAllowed(saved)) {
      // Persisted selection is still valid — keep it, no state change needed.
      const canonical = canonicalId(saved);
      setTenantIdState((cur) => {
        if (cur === canonical) return cur;
        return canonical;
      });
      return;
    }

    // 2. Fallback to user's assigned tenant.
    if (inAllowed(user.tenantId)) {
      const canonical = canonicalId(user.tenantId);
      try { localStorage.setItem(TENANT_STORAGE_KEY, canonical); } catch {}
      setTenantIdState(canonical);
      return;
    }

    // 3. Last resort: first active tenant (only when nothing else matches).
    const fallback = (allowed.find((x) => x.status === 'active') || allowed[0])?.id || null;
    if (fallback) {
      try { localStorage.setItem(TENANT_STORAGE_KEY, fallback); } catch {}
    }
    setTenantIdState(fallback);
  }, [allowed, user, loading, tenantsLoaded, error]);

  const tenant = allowed.find((t) => t.id === tenantId) || null;
  return <T.Provider value={{ tenantId, tenant, tenants: allowed, allTenants: tenants, loading, error, setTenantId, refreshTenants }}>{children}</T.Provider>;
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
