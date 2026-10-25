import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { createCenter, setCenterStatus } from './service';

export default function CentersPage() {
  const { user } = useAuth(); const { tenantId } = useTenant();
  const centers = useCol('centers'), cands = useCol('candidates'), devices = useCol('devices');
  return (
    <Crud title="Centers" desc="Exam centers, seat capacity and utilisation computed from candidates and enrolled devices." rows={centers} search={(c) => `${c.code} ${c.name} ${c.city}`}
      columns={[{ label: 'Code', key: 'code' }, { label: 'Name', key: 'name' }, { label: 'City', key: 'city' }, { label: 'Labs', key: 'labs' }, { label: 'Capacity', key: 'capacity' },
        { label: 'Seated', render: (c) => { const n = cands.filter((x) => x.centerId === c.id).length; return `${n} (${Math.round((n / c.capacity) * 100)}%)`; } },
        { label: 'Devices', render: (c) => devices.filter((d) => d.centerId === c.id).length }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'Add center', perm: 'center.manage', fields: [{ name: 'code', label: 'Code', placeholder: 'BLR-87' }, { name: 'name', label: 'Name' }, { name: 'city', label: 'City' }, { name: 'labs', label: 'Labs', type: 'number', default: 2 }, { name: 'seatsPerLab', label: 'Seats per lab', type: 'number', default: 32 }], submit: (v) => createCenter(user, { tenantId, ...v }) }}
      actions={[{ label: 'Deactivate', perm: 'center.manage', danger: true, reason: true, show: (c) => c.status === 'active', run: (c, r) => setCenterStatus(user, c, 'inactive', r) },
        { label: 'Activate', perm: 'center.manage', reason: true, show: (c) => c.status !== 'active', run: (c, r) => setCenterStatus(user, c, 'active', r) }]} />
  );
}
