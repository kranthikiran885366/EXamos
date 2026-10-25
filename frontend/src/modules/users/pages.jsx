import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Modal, ActionDialog,
  Field, Input, Select, Textarea, Alert, KeyValue, Tabs, useFlash, Flash, CopyField, Loading,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { ROLES, HUMAN_ROLES, roleLabel, roleInfo, permissionsOf, PERMISSION_GROUPS, isGlobal } from '../../core/security/rbac';
import { usePerm } from '../../core/ui/hooks';
import {
  createUser, setUserStatus, unlockUser, setUserRole, resetPassword,
  invite, resendInvitation, expireInvitation, effectivePermissions,
  createRole, updateRole, deleteRole,
} from './service';
import { KINDS as APPROVAL_KINDS, decide as decideApproval, cancel as cancelApproval } from '../../core/services/approvals';

const ROLE_OPTIONS = (actor) => Object.keys(ROLES)
  .filter((r) => r !== 'system')
  .filter((r) => actor?.role === 'superadmin' || (roleInfo(r)?.rank || 0) < (roleInfo(actor?.role)?.rank || 0))
  .map((r) => ({ v: r, l: roleLabel(r) }));

const norm = (s) => String(s ?? '').toLowerCase();

/* ------------------------------------------------------------------ create user */
function CreateUserModal({ onClose, onDone }) {
  const { user } = useAuth();
  const { tenantId, allTenants } = useTenant();
  const [v, setV] = useState({ username: '', name: '', email: '', role: '', password: '', tenantId: user.role === 'superadmin' ? (tenantId || '') : '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false); const [result, setResult] = useState(null);
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      const r = await createUser(user, {
        ...v,
        tenantId: user.role === 'superadmin' ? (v.tenantId || null) : tenantId,
      });
      setResult(r); onDone?.();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  if (result) {
    return (
      <Modal title="Account created" desc="Share the one-time credentials through a secure channel." onClose={onClose}
        footer={<button className="btn primary" onClick={onClose}>Done</button>}>
        <Alert tone="success" title="Save these now">The TOTP secret and recovery codes are shown only once.</Alert>
        <CopyField label="Authenticator secret (TOTP)" value={result.totp} />
        <Card title="Recovery codes" desc="Each code works once. Store them offline." pad>
          <div className="codegrid">{result.recovery.map((c) => <code key={c}>{c}</code>)}</div>
        </Card>
      </Modal>
    );
  }
  return (
    <Modal title="Add user" desc="Creates an account with a temporary password and MFA secret." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="create-user" disabled={busy}>{busy ? 'Creating…' : 'Create account'}</button></>}>
      <form id="create-user" onSubmit={submit} className="formgrid">
        <Field label="Username" required help="3–32 characters, starts with a letter.">
          <Input value={v.username} onChange={(e) => set('username', e.target.value)} autoComplete="off" maxLength={32} autoFocus />
        </Field>
        <Field label="Full name" required><Input value={v.name} onChange={(e) => set('name', e.target.value)} maxLength={60} /></Field>
        <Field label="Email"><Input type="email" value={v.email} onChange={(e) => set('email', e.target.value)} maxLength={120} /></Field>
        <Field label="Role" required><Select value={v.role} onChange={(e) => set('role', e.target.value)} options={ROLE_OPTIONS(user)} /></Field>
        {user.role === 'superadmin' && (
          <Field label="Institution" help="Leave blank for a platform-level identity.">
            <Select value={v.tenantId} onChange={(e) => set('tenantId', e.target.value)} options={allTenants.map((t) => ({ v: t.id, l: t.name }))} placeholder="Platform (global)" />
          </Field>
        )}
        <Field label="Temporary password" required help="12+ characters with upper, lower, digit and symbol.">
          <Input type="password" value={v.password} onChange={(e) => set('password', e.target.value)} autoComplete="new-password" maxLength={128} />
        </Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ invite user */
function InviteModal({ onClose, onDone }) {
  const { user } = useAuth();
  const { tenantId, allTenants } = useTenant();
  const [v, setV] = useState({ name: '', email: '', role: '', tenantId: user.role === 'superadmin' ? (tenantId || '') : '' });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false); const [result, setResult] = useState(null);
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      const r = await invite(user, { ...v, tenantId: user.role === 'superadmin' ? (v.tenantId || null) : tenantId });
      setResult(r); onDone?.();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  if (result) {
    return (
      <Modal title="Invitation sent" onClose={onClose} footer={<button className="btn primary" onClick={onClose}>Done</button>}>
        <Alert tone="success" title="Invitation created">Send this single-use link to the invitee. It expires in 7 days.</Alert>
        <CopyField label="Invitation link" value={result.link} />
      </Modal>
    );
  }
  return (
    <Modal title="Invite user" desc="The invitee chooses their own username and password." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="invite-user" disabled={busy}>{busy ? 'Sending…' : 'Send invitation'}</button></>}>
      <form id="invite-user" onSubmit={submit} className="formgrid">
        <Field label="Full name" required><Input value={v.name} onChange={(e) => set('name', e.target.value)} maxLength={60} autoFocus /></Field>
        <Field label="Email" required><Input type="email" value={v.email} onChange={(e) => set('email', e.target.value)} maxLength={120} /></Field>
        <Field label="Role" required><Select value={v.role} onChange={(e) => set('role', e.target.value)} options={ROLE_OPTIONS(user)} /></Field>
        {user.role === 'superadmin' && (
          <Field label="Institution" required>
            <Select value={v.tenantId} onChange={(e) => set('tenantId', e.target.value)} options={allTenants.map((t) => ({ v: t.id, l: t.name }))} />
          </Field>
        )}
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ users list */
export function UsersPage() {
  const { user } = useAuth();
  const { tenantId, allTenants } = useTenant();
  const perms = usePerm();
  const allUsers = useCol('users', false);
  const allInvites = useCol('invitations', false);
  const [creating, setCreating] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [act, setAct] = useState(null);
  const [tab, setTab] = useState('accounts');
  const flash = useFlash();

  const global = isGlobal(user.role);
  const users = useMemo(() => (global ? allUsers : allUsers.filter((u) => u.tenantId === user.tenantId)), [allUsers, global, user.tenantId]);
  const invites = useMemo(() => (global ? allInvites : allInvites.filter((i) => i.tenantId === user.tenantId)), [allInvites, global, user.tenantId]);
  const tenantName = (id) => (id ? (allTenants.find((t) => t.id === id)?.name || id) : 'Platform');
  const pending = invites.filter((i) => i.status === 'pending');

  const run = (fn, ok) => flash.run(fn, ok);
  const closeAct = () => setAct(null);

  return (
    <Page title="Users" desc="Accounts, roles, two-factor status and invitations."
      actions={<>
        {perms('user.manage') && <button className="btn" onClick={() => setInviting(true)}><Icon name="mail" size={15} /> Invite user</button>}
        {perms('user.manage') && <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> Add user</button>}
      </>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Accounts" value={users.length} icon="users" />
        <Stat label="Active" value={users.filter((u) => u.status === 'active').length} icon="check" />
        <Stat label="Suspended / locked" value={users.filter((u) => ['suspended', 'locked', 'deactivated'].includes(u.status)).length} icon="warn" tone="amber" />
        <Stat label="Pending invites" value={pending.length} icon="mail" tone="violet" />
      </StatGrid>

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'accounts', label: 'Accounts', count: users.length },
        { key: 'invitations', label: 'Invitations', count: pending.length },
      ]} />

      {tab === 'accounts' && (
        <DataTable
          title="User accounts" desc="Reset passwords, suspend accounts or change roles."
          rows={users}
          search={(u) => `${u.name} ${u.username} ${u.email} ${u.role} ${u.tenantId || 'global'}`}
          filters={[
            { key: 'status', label: 'Status', options: ['active', 'suspended', 'locked', 'deactivated'].map((s) => ({ v: s, l: s })) },
            { key: 'role', label: 'Role', options: HUMAN_ROLES.map((r) => ({ v: r, l: roleLabel(r) })) },
            ...(global ? [{ key: 'tenantId', label: 'Institution', get: (u) => u.tenantId || '', options: allTenants.map((t) => ({ v: t.id, l: t.name })) }] : []),
          ]}
          defaultSort={{ key: 'name', dir: 'asc' }}
          columns={[
            { key: 'name', label: 'Name', sortable: true, render: (u) => <Link className="strong-link" to={`/admin/users/${u.id}`}>{u.name}</Link> },
            { key: 'username', label: 'Username', sortable: true, mono: true },
            { key: 'email', label: 'Email', render: (u) => u.email || '—' },
            { key: 'role', label: 'Role', sortable: true, render: (u) => <Badge value={roleLabel(u.role)} /> },
            ...(global ? [{ key: 'tenantId', label: 'Institution', render: (u) => tenantName(u.tenantId) }] : []),
            { key: 'mfaEnabled', label: 'MFA', render: (u) => <Badge value={u.mfaEnabled === false ? 'off' : 'on'} /> },
            { key: 'status', label: 'Status', sortable: true, render: (u) => <Badge value={u.status} /> },
            { key: 'lastLogin', label: 'Last login', sortable: true, render: (u) => (u.lastLogin ? <span title={fmt(u.lastLogin)}>{ago(u.lastLogin)}</span> : 'Never') },
          ]}
          actions={(u) => {
            if (u.id === user.id) return [{ label: 'This is you', disabled: true, onClick: () => {} }];
            const list = [];
            if (u.status === 'locked') list.push({ label: 'Unlock', onClick: () => setAct({ type: 'unlock', row: u }) });
            if (u.status === 'active') list.push({ label: 'Suspend', danger: true, onClick: () => setAct({ type: 'status', row: u, next: 'suspended' }) });
            else list.push({ label: 'Activate', onClick: () => setAct({ type: 'status', row: u, next: 'active' }) });
            list.push({ label: 'Reset password', onClick: () => setAct({ type: 'reset', row: u }) });
            list.push({ label: 'Change role', onClick: () => setAct({ type: 'role', row: u }) });
            return list;
          }}
        />
      )}

      {tab === 'invitations' && (
        <DataTable
          title="Invitations" desc="Single-use links that let staff set their own credentials."
          rows={invites}
          search={(i) => `${i.name} ${i.email} ${i.role} ${i.status}`}
          filters={[{ key: 'status', label: 'Status', options: ['pending', 'accepted', 'expired'].map((s) => ({ v: s, l: s })) }]}
          defaultSort={{ key: 'createdAt', dir: 'desc' }}
          columns={[
            { key: 'name', label: 'Name' },
            { key: 'email', label: 'Email' },
            { key: 'role', label: 'Role', render: (i) => <Badge value={roleLabel(i.role)} /> },
            ...(global ? [{ key: 'tenantId', label: 'Institution', render: (i) => tenantName(i.tenantId) }] : []),
            { key: 'createdAt', label: 'Invited', sortable: true, render: (i) => fmt(i.createdAt) },
            { key: 'expiresAt', label: 'Expires', sortable: true, render: (i) => <span className={i.status === 'pending' && i.expiresAt < Date.now() ? 'text-danger' : ''}>{fmt(i.expiresAt)}</span> },
            { key: 'status', label: 'Status', render: (i) => <Badge value={i.status} /> },
          ]}
          actions={(i) => (i.status === 'pending' ? [
            { label: 'Resend', onClick: () => run(async () => { const r = await resendInvitation(user, i); return `Invitation resent · ${r.link}`; }) },
            { label: 'Expire', danger: true, onClick: () => setAct({ type: 'expire-invite', row: i }) },
          ] : [])}
        />
      )}

      {creating && <CreateUserModal onClose={() => setCreating(false)} onDone={() => flash.setMsg({ ok: true, text: 'Account created.' })} />}
      {inviting && <InviteModal onClose={() => setInviting(false)} onDone={() => flash.setMsg({ ok: true, text: 'Invitation created.' })} />}

      {act?.type === 'status' && (
        <ActionDialog title={act.next === 'suspended' ? 'Suspend account' : 'Activate account'}
          desc={`${act.row.name} (${act.row.username})`} danger={act.next === 'suspended'}
          confirmLabel={act.next === 'suspended' ? 'Suspend' : 'Activate'}
          onClose={closeAct}
          onConfirm={(reason) => run(() => setUserStatus(user, act.row, act.next, reason))} />
      )}
      {act?.type === 'unlock' && (
        <ActionDialog title="Unlock account" desc={`${act.row.name} will be able to sign in again.`} confirmLabel="Unlock"
          onClose={closeAct} onConfirm={(reason) => run(() => unlockUser(user, act.row, reason))} />
      )}
      {act?.type === 'reset' && (
        <ActionDialog title="Reset password" desc={`Set a new temporary password for ${act.row.name}.`} confirmLabel="Reset password"
          field={{ label: 'New password', type: 'password', help: '12+ characters with upper, lower, digit and symbol.' }}
          onClose={closeAct} onConfirm={(reason, val) => run(() => resetPassword(user, act.row, val, reason))} />
      )}
      {act?.type === 'role' && (
        <ActionDialog title="Change role" desc={`${act.row.name} is currently ${roleLabel(act.row.role)}.`} confirmLabel="Request change"
          field={{ label: 'New role', options: ROLE_OPTIONS(user) }} password
          onClose={closeAct} onConfirm={(reason, val) => run(() => setUserRole(user, act.row, val, reason))} />
      )}
      {act?.type === 'expire-invite' && (
        <ActionDialog title="Expire invitation" desc={act.row.email} danger confirmLabel="Expire"
          onClose={closeAct} onConfirm={(reason) => run(() => expireInvitation(user, act.row, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ user detail */
export function UserDetailPage() {
  const { id } = useParams(); const { user } = useAuth();
  const { allTenants } = useTenant();
  const users = useCol('users', false);
  const sessions = useCol('authSessions', false);
  const u = users.find((x) => x.id === id);
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  if (!u) return <Page title="User not found"><Empty icon="user" title="No such user" action={<Link className="btn" to="/admin/users">Back to users</Link>} /></Page>;
  const eff = effectivePermissions(u);
  const tenant = u.tenantId ? (allTenants.find((t) => t.id === u.tenantId)?.name || u.tenantId) : 'Platform (global)';
  const mine = sessions.filter((s) => s.userId === u.id && s.status === 'active');

  return (
    <Page title={u.name} desc={`${u.username} · ${roleLabel(u.role)}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/admin/users">Users</Link><Icon name="arrow" size={12} /><span>{u.name}</span></div>}
      actions={u.id !== user.id && perms('user.manage') ? <>
        <button className="btn" onClick={() => setAct({ type: 'reset' })}>Reset password</button>
        {u.status === 'active'
          ? <button className="btn danger" onClick={() => setAct({ type: 'status', next: 'suspended' })}>Suspend</button>
          : <button className="btn" onClick={() => setAct({ type: 'status', next: 'active' })}>Activate</button>}
        <button className="btn primary" onClick={() => setAct({ type: 'role' })}>Change role</button>
      </> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Role" value={roleLabel(u.role)} icon="badge" sub={roleInfo(u.role)?.scope || 'custom'} />
        <Stat label="Status" value={u.status} icon={u.status === 'active' ? 'check' : 'warn'} tone={u.status === 'active' ? 'green' : 'amber'} />
        <Stat label="MFA" value={u.mfaEnabled === false ? 'Off' : 'On'} icon="shield" />
        <Stat label="Permissions" value={eff.perms.includes('*') ? 'All' : eff.perms.length} icon="key" />
      </StatGrid>
      <div className="two">
        <Card title="Profile">
          <KeyValue cols={2} items={[
            ['Username', <code>{u.username}</code>],
            ['Email', u.email || '—'],
            ['Institution', tenant],
            ['Created', fmt(u.createdAt)],
            ['Last login', u.lastLogin ? fmt(u.lastLogin) : 'Never'],
            ['Password changed', fmt(u.passwordChangedAt)],
            ['Recovery codes', `${(u.recoveryCodes || []).length} configured`],
            ['Active sessions', mine.length],
          ]} />
        </Card>
        <Card title="Role summary">
          <p className="muted">{roleInfo(u.role)?.desc || 'Custom role defined for this workspace.'}</p>
          <KeyValue cols={2} items={[
            ['Scope', roleInfo(u.role)?.scope || 'custom'],
            ['Rank', roleInfo(u.role)?.rank ?? '—'],
            ['Custom', roleInfo(u.role)?.custom ? 'Yes' : 'No'],
            ['Role changed', u.roleChangedAt ? fmt(u.roleChangedAt) : '—'],
          ]} />
        </Card>
      </div>
      <Card title="Effective permissions" desc="Union of the role's granted permissions.">
        {eff.perms.includes('*')
          ? <Alert tone="warn" title="Unrestricted role">This account has every permission on the platform.</Alert>
          : <div className="chips">{eff.perms.map((p) => <span key={p} className="chip">{p}</span>)}</div>}
      </Card>
      <Card title="Active sessions" desc="Sessions are revoked automatically on password or role changes.">
        {mine.length ? (
          <DataTable rows={mine} dense columns={[
            { key: 'id', label: 'Session', mono: true },
            { key: 'createdAt', label: 'Started', render: (s) => fmt(s.createdAt) },
            { key: 'lastSeenAt', label: 'Last seen', render: (s) => (s.lastSeenAt ? ago(s.lastSeenAt) : '—') },
            { key: 'current', label: 'Current', render: (s) => (s.current ? <Badge value="current" /> : '—') },
          ]} />
        ) : <Empty icon="lock" title="No active sessions" />}
      </Card>

      {act?.type === 'status' && (
        <ActionDialog title={act.next === 'suspended' ? 'Suspend account' : 'Activate account'} danger={act.next === 'suspended'}
          confirmLabel={act.next === 'suspended' ? 'Suspend' : 'Activate'} onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(() => setUserStatus(user, u, act.next, reason))} />
      )}
      {act?.type === 'reset' && (
        <ActionDialog title="Reset password" confirmLabel="Reset password"
          field={{ label: 'New password', type: 'password', help: '12+ characters with upper, lower, digit and symbol.' }}
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(() => resetPassword(user, u, val, reason))} />
      )}
      {act?.type === 'role' && (
        <ActionDialog title="Change role" confirmLabel="Request change" field={{ label: 'New role', options: ROLE_OPTIONS(user) }} password
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(() => setUserRole(user, u, val, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ roles */
function PermissionPicker({ value, onChange, disabled = false }) {
  const has = (p) => value.includes(p);
  const toggle = (p) => onChange(has(p) ? value.filter((x) => x !== p) : [...value, p]);
  return (
    <div className="perm-picker">
      {PERMISSION_GROUPS.map((g) => (
        <fieldset key={g.group} disabled={disabled}>
          <legend>{g.group}</legend>
          {g.perms.map((p) => (
            <label key={p} className="check">
              <input type="checkbox" checked={has(p)} onChange={() => toggle(p)} disabled={disabled} />
              <span>{p}</span>
            </label>
          ))}
        </fieldset>
      ))}
    </div>
  );
}

function RoleModal({ role, onClose, onSaved }) {
  const { user } = useAuth();
  const editing = !!role;
  const [v, setV] = useState({
    id: role?.id || '', label: role?.label || '', desc: role?.desc || '',
    perms: role?.perms?.includes('*') ? [] : [...(role?.perms || [])],
  });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      if (editing) await updateRole(user, role, { label: v.label, desc: v.desc, perms: v.perms });
      else await createRole(user, { id: v.id, label: v.label, desc: v.desc, perms: v.perms });
      onSaved?.(editing ? 'Role updated.' : 'Role created.');
      onClose();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal wide title={editing ? `Edit ${role.label}` : 'Create custom role'}
      desc={editing ? 'Changes apply the next time affected users make a request.' : 'Grant only the permissions this role needs.'}
      onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="role-form" disabled={busy}>{busy ? 'Saving…' : editing ? 'Save role' : 'Create role'}</button></>}>
      <form id="role-form" onSubmit={submit}>
        <div className="formgrid">
          <Field label="Role key" required help="Lowercase letters, digits and dashes. Cannot be changed later.">
            <Input value={v.id} onChange={(e) => set('id', e.target.value)} disabled={editing} placeholder="dept-exam-officer" maxLength={40} />
          </Field>
          <Field label="Role name" required><Input value={v.label} onChange={(e) => set('label', e.target.value)} maxLength={60} /></Field>
          <Field label="Description" className="span2"><Textarea rows={2} value={v.desc} onChange={(e) => set('desc', e.target.value)} maxLength={200} /></Field>
        </div>
        <Field label={`Permissions (${v.perms.length} selected)`} required>
          <PermissionPicker value={v.perms} onChange={(p) => set('perms', p)} />
        </Field>
        {err && <Alert tone="danger">{err}</Alert>}
      </form>
    </Modal>
  );
}

export function RolesPage() {
  const { user } = useAuth();
  const customRoles = useCol('roles', false);
  const [modal, setModal] = useState(null); // { role } | 'new'
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => {
    const builtIn = Object.keys(ROLES).map((r) => ({
      id: r, label: ROLES[r].label, desc: ROLES[r].desc, perms: ROLES[r].perms,
      scope: ROLES[r].scope, rank: ROLES[r].rank, custom: false,
    }));
    const custom = customRoles.filter((r) => !r.deleted).map((r) => ({ ...r, custom: true }));
    return [...builtIn, ...custom];
  }, [customRoles]);

  return (
    <Page title="Roles & permissions" desc="Built-in and custom roles with their effective permissions."
      actions={perms('role.manage') ? <button className="btn primary" onClick={() => setModal('new')}><Icon name="plus" size={15} /> Create role</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={3}>
        <Stat label="Built-in roles" value={rows.filter((r) => !r.custom).length} icon="shield" />
        <Stat label="Custom roles" value={rows.filter((r) => r.custom).length} icon="key" tone="violet" />
        <Stat label="Assignable" value={rows.filter((r) => r.id !== 'system').length} icon="users" tone="green" />
      </StatGrid>
      <DataTable
        title="Roles" desc="Predefined roles are immutable; clone one as a custom role if you need changes."
        rows={rows} search={(r) => `${r.id} ${r.label} ${r.desc || ''} ${(r.perms || []).join(' ')}`}
        filters={[{ key: 'custom', label: 'Type', get: (r) => (r.custom ? 'custom' : 'built-in'), options: [{ v: 'built-in', l: 'Built-in' }, { v: 'custom', l: 'Custom' }] }]}
        defaultSort={{ key: 'label', dir: 'asc' }}
        columns={[
          { key: 'label', label: 'Role', sortable: true, render: (r) => <><b>{r.label}</b><div className="muted sm mono">{r.id}</div></> },
          { key: 'desc', label: 'Description', render: (r) => <span className="muted sm">{r.desc || '—'}</span> },
          { key: 'scope', label: 'Scope', render: (r) => <Badge value={r.scope || 'custom'} /> },
          { key: 'rank', label: 'Rank', sortable: true, render: (r) => r.rank ?? '—' },
          { key: 'custom', label: 'Type', render: (r) => <Badge value={r.custom ? 'custom' : 'built-in'} /> },
          { key: 'perms', label: 'Permissions', render: (r) => <span className="muted sm">{r.perms?.includes('*') ? 'All permissions' : `${r.perms?.length || 0} granted`}</span> },
        ]}
        actions={(r) => [
          { label: 'View', onClick: () => setView(r) },
          ...(r.custom && perms('role.manage') ? [
            { label: 'Edit', onClick: () => setModal(r) },
            { label: 'Delete', danger: true, onClick: () => setAct(r) },
          ] : []),
        ]}
      />
      {modal && <RoleModal role={modal === 'new' ? null : modal} onClose={() => setModal(null)} onSaved={(m) => flash.setMsg({ ok: true, text: m })} />}
      {view && (
        <Modal wide title={view.label} desc={view.desc} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={3} items={[['Key', <code>{view.id}</code>], ['Scope', view.scope || 'custom'], ['Type', view.custom ? 'Custom' : 'Built-in']]} />
          {view.perms?.includes('*')
            ? <Alert tone="warn" title="Unrestricted">This role has every permission.</Alert>
            : <div className="chips">{(view.perms || []).map((p) => <span key={p} className="chip">{p}</span>)}</div>}
        </Modal>
      )}
      {act && (
        <ActionDialog title="Delete role" desc={`Delete ${act.label}? This cannot be undone.`} danger confirmLabel="Delete role"
          onClose={() => setAct(null)}
          onConfirm={(reason) => flash.run(async () => { await deleteRole(user, act); return `Role ${act.label} deleted. ${reason ? '' : ''}`; })} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ approvals */
export function ApprovalsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const approvals = useCol('approvals', false);
  const [act, setAct] = useState(null);
  const [tab, setTab] = useState('pending');
  const flash = useFlash();
  const perms = usePerm();

  const scoped = useMemo(() => approvals.filter((a) => !a.tenantId || a.tenantId === tenantId || user.role === 'superadmin'), [approvals, tenantId, user.role]);
  const pending = scoped.filter((a) => a.status === 'pending');
  const decided = scoped.filter((a) => a.status !== 'pending').sort((a, b) => (b.decidedAt || 0) - (a.decidedAt || 0));
  const mine = (a) => a.requestedBy === user.id;

  return (
    <Page title="Approvals" desc="Two-person approval requests. You cannot decide your own request.">
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Pending" value={pending.length} icon="clock" tone="amber" />
        <Stat label="Approved" value={decided.filter((a) => a.status === 'approved').length} icon="check" tone="green" />
        <Stat label="Rejected" value={decided.filter((a) => a.status === 'rejected').length} icon="warn" tone="red" />
        <Stat label="Total" value={scoped.length} icon="chart" />
      </StatGrid>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'pending', label: 'Pending', count: pending.length },
        { key: 'history', label: 'Decision history', count: decided.length },
      ]} />
      {tab === 'pending' && (
        <DataTable
          title="Pending approvals" desc="Requests awaiting a second privileged user."
          rows={pending} search={(a) => `${a.kind} ${a.label} ${a.requestedBy} ${a.reason}`}
          filters={[{ key: 'kind', label: 'Type', options: Object.entries(APPROVAL_KINDS).map(([v, l]) => ({ v, l })) }]}
          defaultSort={{ key: 'createdAt', dir: 'asc' }}
          columns={[
            { key: 'kind', label: 'Type', render: (a) => <Badge value={APPROVAL_KINDS[a.kind] || a.kind} /> },
            { key: 'label', label: 'Subject', render: (a) => <><b>{a.label}</b>{a.targetId && <div className="muted sm mono">{a.targetId}</div>}</> },
            { key: 'requestedBy', label: 'Requested by' },
            { key: 'reason', label: 'Reason', render: (a) => <span className="muted sm">{a.reason}</span> },
            { key: 'createdAt', label: 'Age', sortable: true, render: (a) => ago(a.createdAt) },
          ]}
          actions={(a) => {
            if (mine(a)) return [{ label: 'Withdraw', danger: true, onClick: () => setAct({ type: 'cancel', row: a }) }];
            if (!perms('approval.decide')) return [];
            return [
              { label: 'Approve', onClick: () => setAct({ type: 'approve', row: a }) },
              { label: 'Reject', danger: true, onClick: () => setAct({ type: 'reject', row: a }) },
            ];
          }}
        />
      )}
      {tab === 'history' && (
        <DataTable
          title="Decision history" desc="Previously decided requests, newest first."
          rows={decided} search={(a) => `${a.kind} ${a.label} ${a.decidedBy} ${a.note}`}
          filters={[{ key: 'status', label: 'Decision', options: ['approved', 'rejected', 'withdrawn', 'failed'].map((s) => ({ v: s, l: s })) }]}
          defaultSort={{ key: 'decidedAt', dir: 'desc' }}
          columns={[
            { key: 'kind', label: 'Type', render: (a) => APPROVAL_KINDS[a.kind] || a.kind },
            { key: 'label', label: 'Subject' },
            { key: 'status', label: 'Decision', render: (a) => <Badge value={a.status} /> },
            { key: 'decidedBy', label: 'Decided by', render: (a) => a.decidedBy || '—' },
            { key: 'note', label: 'Note', render: (a) => <span className="muted sm">{a.note || '—'}</span> },
            { key: 'decidedAt', label: 'Time', sortable: true, render: (a) => fmt(a.decidedAt) },
          ]}
        />
      )}

      {(act?.type === 'approve' || act?.type === 'reject') && (
        <ActionDialog
          title={act.type === 'approve' ? 'Approve request' : 'Reject request'}
          desc={`${APPROVAL_KINDS[act.row.kind] || act.row.kind}: ${act.row.label}`}
          danger={act.type === 'reject'}
          confirmLabel={act.type === 'approve' ? 'Approve & apply' : 'Reject'}
          reasonLabel={act.type === 'approve' ? 'Approval note' : 'Rejection reason'}
          onClose={() => setAct(null)}
          onConfirm={(note) => flash.run(async () => {
            const r = await decideApproval(user, act.row, act.type === 'approve', note);
            return r.status === 'approved' ? `Approved. ${r.result || ''}` : 'Request rejected.';
          })}
        />
      )}
      {act?.type === 'cancel' && (
        <ActionDialog title="Withdraw request" desc={act.row.label} danger confirmLabel="Withdraw"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => cancelApproval(user, act.row, reason))} />
      )}
    </Page>
  );
}
