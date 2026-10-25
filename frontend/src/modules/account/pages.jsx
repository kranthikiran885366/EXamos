import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Field, Input, useFlash, Flash, CopyField, Tabs,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { roleLabel, permissionsOf, roleInfo } from '../../core/security/rbac';

/* ------------------------------------------------------------------ profile */
export function AccountPage() {
  const { user } = useAuth();
  const { allTenants } = useTenant();
  const sessions = useCol('authSessions', false);
  const tenant = user.tenantId ? (allTenants.find((t) => t.id === user.tenantId)?.name || user.tenantId) : 'Platform (global)';
  const mine = sessions.filter((s) => s.userId === user.id && s.status === 'active');
  const perms = permissionsOf(user.role);

  return (
    <Page title="Account" desc="Your profile, role and security at a glance."
      actions={<><Link className="btn" to="/account/security">Security</Link><Link className="btn" to="/account/sessions">Sessions</Link></>}>
      <StatGrid cols={4}>
        <Stat label="Role" value={roleLabel(user.role)} icon="badge" sub={roleInfo(user.role)?.scope || 'custom'} />
        <Stat label="MFA" value={user.mfaEnabled === false ? 'Off' : 'On'} icon="shield" tone={user.mfaEnabled === false ? 'amber' : 'green'} />
        <Stat label="Active sessions" value={mine.length} icon="lock" to="/account/sessions" />
        <Stat label="Last login" value={user.lastLogin ? ago(user.lastLogin) : '—'} icon="clock" sub={user.lastLogin ? fmt(user.lastLogin) : ''} />
      </StatGrid>
      <div className="two">
        <Card title="Profile">
          <KeyValue cols={2} items={[
            ['Username', <code key="u">{user.id}</code>],
            ['Name', user.name],
            ['Email', user.email || '—'],
            ['Role', roleLabel(user.role)],
            ['Institution', tenant],
            ['Candidate record', user.candidateId || '—'],
          ]} />
        </Card>
        <Card title="Role capabilities" desc={roleInfo(user.role)?.desc || 'Custom role'}>
          {perms.includes('*')
            ? <Alert tone="warn" title="Unrestricted role">This account has every platform permission.</Alert>
            : <div className="chips">{perms.map((p) => <span key={p} className="chip">{p}</span>)}</div>}
        </Card>
      </div>
      <Card title="Quick links">
        <div className="row wrap">
          <Link className="btn" to="/account/security">Change password & MFA</Link>
          <Link className="btn" to="/account/sessions">Review sessions</Link>
          <Link className="btn" to="/notifications">Inbox</Link>
          {user.role === 'student' && <Link className="btn" to="/student/home">My exams</Link>}
        </div>
      </Card>
    </Page>
  );
}

/* ------------------------------------------------------------------ security */
export function AccountSecurityPage() {
  const { user, changePassword, regenerateRecovery, rotateMfa } = useAuth();
  const events = useCol('securityEvents', false);
  const [v, setV] = useState({ current: '', next: '', confirm: '' });
  const [busy, setBusy] = useState(false);
  const [codes, setCodes] = useState(null);
  const [mfa, setMfa] = useState(null);
  const [act, setAct] = useState(null);
  const flash = useFlash();
  const mine = events.filter((e) => e.actor === user.id).sort((a, b) => b.at - a.at).slice(0, 10);

  const savePassword = async (e) => {
    e.preventDefault();
    if (v.next !== v.confirm) return flash.setMsg({ ok: false, text: 'The new passwords do not match.' });
    setBusy(true);
    const r = await changePassword(v.current, v.next);
    setBusy(false);
    if (r.error) flash.setMsg({ ok: false, text: r.error });
    else { setV({ current: '', next: '', confirm: '' }); flash.setMsg({ ok: true, text: 'Password changed.' }); }
  };

  return (
    <Page title="Security" desc="Change your password, rotate MFA and manage recovery codes."
      breadcrumb={<div className="crumbs-inline"><Link to="/account">Account</Link><Icon name="arrow" size={12} /><span>Security</span></div>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <div className="two">
        <Card title="Change password" desc="You will stay signed in on this session.">
          <form onSubmit={savePassword} className="formgrid">
            <Field label="Current password" required className="span2"><Input type="password" value={v.current} onChange={(e) => setV({ ...v, current: e.target.value })} autoComplete="current-password" maxLength={128} /></Field>
            <Field label="New password" required help="12+ characters with upper, lower, digit and symbol."><Input type="password" value={v.next} onChange={(e) => setV({ ...v, next: e.target.value })} autoComplete="new-password" maxLength={128} /></Field>
            <Field label="Confirm new password" required><Input type="password" value={v.confirm} onChange={(e) => setV({ ...v, confirm: e.target.value })} autoComplete="new-password" maxLength={128} /></Field>
            <div className="span2"><button className="btn primary" disabled={busy || !v.current || !v.next}>{busy ? 'Saving…' : 'Change password'}</button></div>
          </form>
        </Card>
        <Card title="Two-factor authentication" desc="A TOTP code is required at sign-in.">
          <KeyValue cols={2} items={[
            ['Status', <Badge key="s" value={user.mfaEnabled === false ? 'off' : 'on'} />],
            ['Recovery codes', '8 single-use codes'],
            ['Method', 'TOTP (30-second period)'],
            ['Algorithm', 'SHA-1 · 6 digits'],
          ]} />
          <div className="row wrap">
            <button className="btn" onClick={() => setAct({ type: 'mfa' })}>Rotate MFA secret</button>
            <button className="btn" onClick={() => setAct({ type: 'recovery' })}>Regenerate recovery codes</button>
          </div>
          <Alert tone="info" title="After rotation">Add the new secret to your authenticator before signing out. Old codes stop working immediately.</Alert>
        </Card>
      </div>
      <Card title="Recent account security events" desc="From the security event log.">
        <DataTable rows={mine} dense columns={[
          { key: 'at', label: 'Time', render: (e) => fmt(e.at) },
          { key: 'type', label: 'Type', render: (e) => <Badge value={e.type} /> },
          { key: 'severity', label: 'Severity', render: (e) => <Badge value={e.severity} /> },
          { key: 'title', label: 'Title' },
          { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
        ]} empty={<Empty icon="shield" title="No security events" />} />
      </Card>

      {act?.type === 'mfa' && (
        <ActionDialog title="Rotate MFA secret" desc="Your current authenticator entry will stop working." danger confirmLabel="Rotate secret" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={async () => { const r = await rotateMfa(); if (r.error) throw new Error(r.error); setMfa(r); }} />
      )}
      {act?.type === 'recovery' && (
        <ActionDialog title="Regenerate recovery codes" desc="All existing recovery codes are invalidated." danger confirmLabel="Regenerate" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={async () => { const r = await regenerateRecovery(); if (r.error) throw new Error(r.error); setCodes(r.codes); }} />
      )}
      {mfa && (
        <Modal title="New MFA secret" desc="Add this secret to your authenticator app now." onClose={() => setMfa(null)}
          footer={<button className="btn primary" onClick={() => setMfa(null)}>I have saved it</button>}>
          <Alert tone="warn" title="Shown once">If you lose this secret before adding it, you will need a recovery code.</Alert>
          <CopyField label="Authenticator secret" value={mfa.secret} />
          <CopyField label="otpauth URI" value={mfa.uri} />
        </Modal>
      )}
      {codes && (
        <Modal title="New recovery codes" desc="Each code works once. Store them offline." onClose={() => setCodes(null)}
          footer={<button className="btn primary" onClick={() => setCodes(null)}>I have saved them</button>}>
          <Alert tone="warn" title="Shown once">Old recovery codes no longer work.</Alert>
          <div className="codegrid">{codes.map((c) => <code key={c}>{c}</code>)}</div>
        </Modal>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ sessions */
export function AccountSessionsPage() {
  const { user, revokeSession, revokeOthers } = useAuth();
  const sessions = useCol('authSessions', false);
  const [act, setAct] = useState(null);
  const [tab, setTab] = useState('active');
  const flash = useFlash();

  const rows = sessions.filter((s) => s.userId === user.id).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
  const active = rows.filter((s) => s.status === 'active');
  const ended = rows.filter((s) => s.status !== 'active');
  const shown = tab === 'active' ? active : ended;

  return (
    <Page title="Sessions" desc="Active sessions and devices signed into your account."
      breadcrumb={<div className="crumbs-inline"><Link to="/account">Account</Link><Icon name="arrow" size={12} /><span>Sessions</span></div>}
      actions={active.length > 1 ? <button className="btn danger" onClick={() => setAct({ type: 'others' })}>Sign out other sessions</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={3}>
        <Stat label="Active" value={active.length} icon="lock" tone="green" />
        <Stat label="Ended / revoked" value={ended.length} icon="history" />
        <Stat label="This session" value={active.find((s) => s.current) ? 'Current' : '—'} icon="check" />
      </StatGrid>
      <Tabs value={tab} onChange={setTab} tabs={[{ key: 'active', label: 'Active', count: active.length }, { key: 'ended', label: 'History', count: ended.length }]} />
      <DataTable
        title="Sessions" desc="Sessions are revoked automatically when your password or role changes."
        rows={shown}
        columns={[
          { key: 'id', label: 'Session', render: (s) => <span className="mono sm">{s.id}</span> },
          { key: 'userAgent', label: 'Device', render: (s) => <span className="muted sm">{s.userAgent || 'Unknown'}</span> },
          { key: 'ip', label: 'IP', render: (s) => s.ip || '—' },
          { key: 'createdAt', label: 'Started', sortable: true, render: (s) => fmt(s.createdAt) },
          { key: 'lastSeen', label: 'Last used', sortable: true, render: (s) => (s.lastSeen ? ago(s.lastSeen) : '—') },
          { key: 'current', label: 'Current', render: (s) => (s.current && s.status === 'active' ? <Badge value="current" /> : '—') },
          { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} /> },
          { key: 'reason', label: 'Ended because', render: (s) => s.reason || (s.endedAt ? fmt(s.endedAt) : '—') },
        ]}
        actions={(s) => (s.status === 'active' && !s.current ? [
          { label: 'Revoke', danger: true, onClick: () => setAct({ type: 'one', row: s }) },
        ] : [])}
        empty={<Empty icon="lock" title={tab === 'active' ? 'No active sessions' : 'No session history'} />}
      />
      {act?.type === 'one' && (
        <ActionDialog title="Revoke session" desc="That device will need to sign in again." danger confirmLabel="Revoke" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={() => flash.run(async () => { const r = await revokeSession(act.row.id); if (r.error) throw new Error(r.error); return 'Session revoked.'; })} />
      )}
      {act?.type === 'others' && (
        <ActionDialog title="Sign out other sessions" desc="Every other active session is revoked. This session stays signed in." danger confirmLabel="Sign out others" requireReason={false}
          onClose={() => setAct(null)}
          onConfirm={() => flash.run(async () => { const r = await revokeOthers(); if (r.error) throw new Error(r.error); return `${r.count} session(s) revoked.`; })} />
      )}
    </Page>
  );
}
