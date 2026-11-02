import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { ROLES } from '../../core/security/rbac';
import { fmt } from '../../core/ui/format';
import { createUser, setUserStatus, setUserRole, resetPassword } from './service';

export default function IamPage() {
  const { user } = useAuth(); const allUsers = useCol('users', false);
  const users = user?.role === 'superadmin' ? allUsers : allUsers.filter((u) => u.tenantId === user?.tenantId);
  const roleOpts = Object.entries(ROLES).map(([v, r]) => ({ v, l: r.label }));
  return (
    <Crud title="IAM" desc="Users, roles and MFA. Passwords are PBKDF2-hashed; authenticator keys are shown once at creation." rows={users} search={(u) => `${u.id} ${u.name} ${u.role}`}
      columns={[{ label: 'User', key: 'id' }, { label: 'Name', key: 'name' }, { label: 'Role', render: (u) => ROLES[u.role]?.label }, { label: 'MFA', render: () => 'TOTP' }, { label: 'Last sign-in', render: (u) => fmt(u.lastLogin) }, { label: 'Status', key: 'status', badge: true }]}
      create={{ label: 'New user', perm: 'user.manage', fields: [{ name: 'username', label: 'Username' }, { name: 'name', label: 'Full name' }, { name: 'role', label: 'Role', type: 'select', options: roleOpts }, { name: 'password', label: 'Initial password', type: 'password', help: '12+ characters with upper, lower, digit and symbol.' }], submit: (v) => createUser(user, v) }}
      actions={[{ label: 'Suspend', perm: 'user.manage', danger: true, reason: true, show: (u) => u.status === 'active', run: (u, r) => setUserStatus(user, u, 'suspended', r) },
        { label: 'Reactivate', perm: 'user.manage', reason: true, show: (u) => u.status !== 'active', run: (u, r) => setUserStatus(user, u, 'active', r) },
        { label: 'Change role', perm: 'user.manage', reason: true, stepUp: true, field: { label: 'New role', options: roleOpts }, run: (u, r, v) => setUserRole(user, u, v, r) },
        { label: 'Reset password', perm: 'user.manage', stepUp: true, field: { label: 'New password', type: 'password' }, run: (u, _r, v) => resetPassword(user, u, v) }]} />
  );
}
