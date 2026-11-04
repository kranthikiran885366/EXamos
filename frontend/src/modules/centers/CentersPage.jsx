import { useEffect, useRef, useState } from 'react';
import Crud from '../../core/ui/Crud';
import { useTenant } from '../../core/db/tenant';
import { createCenter, listCenters, setCenterStatus } from './service';

export default function CentersPage() {
  const { tenantId } = useTenant();
  const [centers, setCenters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const loadVersion = useRef(0);

  useEffect(() => {
    let active = true;
    const version = ++loadVersion.current;
    setLoading(true);
    setError('');
    listCenters(tenantId)
      .then((rows) => { if (active && version === loadVersion.current) setCenters(rows); })
      .catch((err) => {
        if (active && version === loadVersion.current) {
          setCenters([]);
          setError(err.message || 'Failed to load centers.');
        }
      })
      .finally(() => { if (active && version === loadVersion.current) setLoading(false); });
    return () => {
      active = false;
      if (version === loadVersion.current) loadVersion.current++;
    };
  }, [tenantId]);

  const refresh = async () => {
    const version = ++loadVersion.current;
    setLoading(true);
    setError('');
    try {
      const rows = await listCenters(tenantId);
      if (version === loadVersion.current) setCenters(rows);
      return true;
    } catch (err) {
      if (version === loadVersion.current) setError(err.message || 'Failed to refresh centers.');
      return false;
    } finally {
      if (version === loadVersion.current) setLoading(false);
    }
  };
  const create = tenantId ? {
    label: 'Add center',
    perm: 'center.manage',
    fields: [
      { name: 'code', label: 'Center code *', placeholder: 'BLR-87', help: 'Three letters, a hyphen, then one to three digits.' },
      { name: 'name', label: 'Center name *' },
      { name: 'city', label: 'City' },
      { name: 'labs', label: 'Labs *', type: 'number', min: 1, max: 12, help: 'Enter 1–12 labs.' },
      { name: 'seatsPerLab', label: 'Seats per lab *', type: 'number', min: 8, max: 96, help: 'Enter 8–96 seats per lab; total capacity cannot exceed 416.' },
    ],
    submit: async (values) => {
      const message = await createCenter({ tenantId, ...values });
      const refreshed = await refresh();
      return refreshed ? message : `${message} The grid could not refresh; use Refresh to retry.`;
    },
  } : undefined;

  return (
    <Crud
      title="Centers"
      desc="Exam centers and seat capacity, loaded from the institution backend."
      rows={centers}
      search={(center) => `${center.code || ''} ${center.name || ''} ${center.city || ''}`.toLowerCase()}
      columns={[
        { label: 'Code', key: 'code' },
        { label: 'Name', key: 'name' },
        { label: 'City', key: 'city' },
        { label: 'Labs', key: 'labs' },
        { label: 'Seats per lab', key: 'seatsPerLab' },
        { label: 'Capacity', key: 'capacity' },
        { label: 'Status', key: 'status', badge: true },
      ]}
      create={create}
      head={<button className="btn" type="button" onClick={refresh} disabled={loading}>{loading ? 'Loading…' : 'Refresh'}</button>}
      top={
        <>
          {error && <div className="err" role="alert">{error}</div>}
          {!tenantId && <div className="muted" role="status">Showing centers available to this account. Select an institution to create a center.</div>}
          {loading && <div className="muted" role="status">Loading centers from the backend…</div>}
        </>
      }
      actions={[
        {
          label: 'Deactivate',
          perm: 'center.manage',
          danger: true,
          reason: true,
          show: (center) => center.status === 'active',
          run: async (center, reason) => {
            const result = await setCenterStatus(center, 'inactive', reason);
            await refresh();
            return result;
          },
        },
        {
          label: 'Activate',
          perm: 'center.manage',
          reason: true,
          show: (center) => center.status !== 'active',
          run: async (center, reason) => {
            const result = await setCenterStatus(center, 'active', reason);
            await refresh();
            return result;
          },
        },
      ]}
    />
  );
}
