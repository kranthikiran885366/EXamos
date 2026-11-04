import { useEffect, useState } from 'react';
import Crud from '../../core/ui/Crud';
import { useTenant } from '../../core/db/tenant';
import { createCenter, listCenters, setCenterStatus } from './service';

export default function CentersPage() {
  const { tenantId } = useTenant();
  const [centers, setCenters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    listCenters(tenantId)
      .then((rows) => { if (active) setCenters(rows); })
      .catch((err) => { if (active) { setCenters([]); setError(err.message || 'Failed to load centers.'); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [tenantId, reloadKey]);

  const refresh = () => setReloadKey((key) => key + 1);
  const create = tenantId ? {
    label: 'Add center',
    perm: 'center.manage',
    fields: [
      { name: 'code', label: 'Code', placeholder: 'BLR-87' },
      { name: 'name', label: 'Name' },
      { name: 'city', label: 'City' },
      { name: 'labs', label: 'Labs', type: 'number', min: 1, max: 12 },
      { name: 'seatsPerLab', label: 'Seats per lab', type: 'number', min: 8, max: 96 },
    ],
    submit: async (values) => {
      const message = await createCenter({ tenantId, ...values });
      refresh();
      return message;
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
            refresh();
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
            refresh();
            return result;
          },
        },
      ]}
    />
  );
}
