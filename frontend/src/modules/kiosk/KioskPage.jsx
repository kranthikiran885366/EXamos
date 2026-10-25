import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { createProfile, promote, retire, assignToCenter } from './service';

export default function KioskPage() {
  const { user } = useAuth(); const { tenantId } = useTenant();
  const kiosks = useCol('kiosks'), rels = useCol('releases', false), devices = useCol('devices'), centers = useCol('centers');
  return (
    <Crud title="Kiosk" desc="Lockdown profiles bound to signed releases. Promotion requires a verified, non-revoked release." rows={kiosks} search={(k) => `${k.name} ${k.status}`}
      columns={[{ label: 'Profile', key: 'name' }, { label: 'Release', render: (k) => rels.find((r) => r.id === k.releaseId)?.version || '—' }, { label: 'Lockdown', key: 'lockdown' }, { label: 'Clipboard', render: (k) => (k.blockClipboard ? 'blocked' : 'allowed') }, { label: 'Screen capture', render: (k) => (k.blockCapture ? 'blocked' : 'allowed') },
        { label: 'Devices', render: (k) => devices.filter((d) => d.kioskId === k.id).length }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New profile', perm: 'kiosk.manage', fields: [{ name: 'name', label: 'Name' }, { name: 'releaseId', label: 'Release', type: 'select', options: rels.filter((r) => ['approved', 'rolling', 'stable'].includes(r.status)).map((r) => ({ v: r.id, l: `${r.version} (${r.status})` })) }, { name: 'lockdown', label: 'Lockdown', type: 'select', options: ['full', 'relaxed'], default: 'full' }, { name: 'blockClipboard', label: 'Block clipboard', type: 'checkbox', default: true }, { name: 'blockCapture', label: 'Block screen capture', type: 'checkbox', default: true }], submit: (v) => createProfile(user, { tenantId, ...v }) }}
      actions={[{ label: 'Promote', perm: 'kiosk.manage', show: (k) => k.status === 'canary', run: (k) => promote(user, k) },
        { label: 'Assign to center', perm: 'kiosk.manage', show: (k) => k.status !== 'retired', field: { label: 'Center', options: centers.map((c) => ({ v: c.id, l: c.code })) }, reason: false, run: (k, _r, v) => assignToCenter(user, k, v) },
        { label: 'Retire', perm: 'kiosk.manage', danger: true, reason: true, show: (k) => k.status !== 'retired', run: (k, r) => retire(user, k, r) }]} />
  );
}
