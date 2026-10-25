import Crud from '../../core/ui/Crud';
import Badge from '../../core/ui/Badge';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { ago } from '../../core/ui/format';
import { FLOW, move, addNote, assign, falsePositive, promote } from './service';

export default function IncidentsPage() {
  const { user } = useAuth(); const incs = useCol('incidents'); const devices = useCol('devices', false);
  const sev = { critical: 0, high: 1, medium: 2, low: 3 };
  const rows = [...incs].sort((a, b) => (['closed', 'false_positive'].includes(a.status) ? 1 : 0) - (['closed', 'false_positive'].includes(b.status) ? 1 : 0) || sev[a.severity] - sev[b.severity] || b.createdAt - a.createdAt);
  return (
    <Crud title="Incidents" desc="Automated alerts become findings only after human review. Resolving needs an investigation note." rows={rows} search={(i) => `INC-${i.no} ${i.title} ${i.status} ${i.owner}`}
      columns={[{ label: 'ID', render: (i) => `INC-${i.no}` }, { label: 'Title', key: 'title' }, { label: 'Severity', render: (i) => <Badge>{i.severity}</Badge> }, { label: 'Kind', key: 'kind' }, { label: 'Device', render: (i) => devices.find((d) => d.id === i.deviceId)?.hostname || '—' },
        { label: 'Owner', render: (i) => i.owner || 'unassigned' }, { label: 'Notes', render: (i) => <span title={i.notes.map((n) => n.text).join('\n')}>{i.notes.length}</span> }, { label: 'Opened', render: (i) => ago(i.createdAt) }, { label: 'Status', key: 'status', badge: true }]}
      actions={(i) => [...(FLOW[i.status] || []).map((to) => ({ label: to === 'investigating' && i.status === 'resolved' ? 'Reopen' : to[0].toUpperCase() + to.slice(1), perm: 'incident.manage', run: (r) => move(user, r, to) })),
        { label: 'Add note', perm: 'incident.manage', field: { label: 'Note' }, reason: false, show: (r) => !['closed', 'false_positive'].includes(r.status), run: (r, _x, v) => addNote(user, r, v) },
        { label: 'Take', perm: 'incident.manage', show: (r) => r.owner !== user.id && !['closed', 'false_positive'].includes(r.status), run: (r) => assign(user, r, user.id) },
        { label: 'Promote', perm: 'incident.manage', show: (r) => r.kind === 'alert', run: (r) => promote(user, r) },
        { label: 'False positive', perm: 'incident.manage', danger: true, field: { label: 'Justification' }, show: (r) => ['open', 'investigating', 'contained'].includes(r.status), run: (r, _x, v) => falsePositive(user, r, v) }]} />
  );
}
