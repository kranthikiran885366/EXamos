import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { createTenant, setTenantStatus, resetWorkspace } from './service';

export default function AdminPage() {
  const { user } = useAuth();
  const tenants = useCol('tenants', false), centers = useCol('centers', false), devices = useCol('devices', false), cands = useCol('candidates', false), exams = useCol('exams', false);
  const n = (arr, t) => arr.filter((x) => x.tenantId === t.id).length;
  return (
    <Crud title="Admin" desc="Tenants, plan limits and platform-wide controls. Usage is computed from live data." rows={tenants} search={(t) => `${t.name} ${t.region} ${t.plan}`}
      columns={[{ label: 'Tenant', key: 'name' }, { label: 'Region', key: 'region' }, { label: 'Plan', key: 'plan' },
        { label: 'Centers', render: (t) => `${n(centers, t)} / ${t.maxCenters}` }, { label: 'Devices', render: (t) => n(devices, t) }, { label: 'Candidates', render: (t) => n(cands, t) },
        { label: 'Live exams', render: (t) => exams.filter((e) => e.tenantId === t.id && e.status === 'live').length }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New tenant', perm: 'tenant.manage', fields: [{ name: 'name', label: 'Name' }, { name: 'region', label: 'Region', default: 'ap-south-1' }, { name: 'plan', label: 'Plan', type: 'select', options: ['pilot', 'standard', 'enterprise'], default: 'pilot' }, { name: 'maxCenters', label: 'Max centers', type: 'number', default: 5 }], submit: (v) => createTenant(user, v) }}
      actions={[{ label: 'Suspend', perm: 'tenant.manage', danger: true, reason: true, show: (t) => t.status === 'active', run: (t, r) => setTenantStatus(user, t, 'suspended', r) },
        { label: 'Activate', perm: 'tenant.manage', reason: true, show: (t) => t.status !== 'active', run: (t, r) => setTenantStatus(user, t, 'active', r) }]}
      top={user.role === 'superadmin' && <div className="card pad2"><b>Danger zone</b><p className="muted sm">Deletes the local IndexedDB (all tenants, keys, audit log) and re-seeds on reload.</p><DangerReset user={user} /></div>} />
  );
}
import ReauthModal from '../../core/ui/ReauthModal';
import { useState } from 'react';
function DangerReset({ user }) {
  const [o, setO] = useState(false);
  return <><button className="btn danger" onClick={() => setO(true)}>Reset workspace</button>{o && <ReauthModal title="Reset workspace" text="This cannot be undone." confirmLabel="Wipe and reseed" onClose={() => setO(false)} onConfirm={() => resetWorkspace(user)} />}</>;
}
