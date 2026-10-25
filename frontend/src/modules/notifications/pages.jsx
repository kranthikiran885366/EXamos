import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, Field, Input, Select, Textarea, useFlash, Flash, Tabs, CopyButton,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { usePerm } from '../../core/ui/hooks';
import { HUMAN_ROLES, roleLabel } from '../../core/security/rbac';
import {
  sendNotification, markRead, markAllRead, archive, unarchive, remove,
  visibleTo, unreadFor, notifStats, CHANNELS, TONES, AUDIENCES, TEMPLATES,
} from './service';

/* ------------------------------------------------------------------ admin */
function BroadcastModal({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const [v, setV] = useState({
    template: '', title: '', body: '', tone: 'info', channel: 'in-app',
    audience: 'all', role: '', link: '', scheduledAt: '',
  });
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const pickTemplate = (key) => {
    const t = TEMPLATES.find((x) => x.key === key);
    setV((s) => ({ ...s, template: key, ...(t ? { title: t.title, body: t.body } : {}) }));
  };
  const submit = async (e) => {
    e.preventDefault(); if (busy) return; setBusy(true); setErr('');
    try {
      const m = await sendNotification(user, { tenantId, ...v, audience: v.audience, role: v.audience === 'role' ? v.role : null });
      onDone?.(m); onClose();
    } catch (x) { setErr(x.message || String(x)); }
    setBusy(false);
  };
  return (
    <Modal wide title="Send notification" desc="Targeted in-app or email delivery. Scheduled messages appear later." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" type="submit" form="broadcast-form" disabled={busy}>{busy ? 'Sending…' : v.scheduledAt ? 'Schedule' : 'Send now'}</button></>}>
      <form id="broadcast-form" onSubmit={submit} className="formgrid">
        <Field label="Template" className="span2" help="Pick a template to prefill the title and body.">
          <Select value={v.template} onChange={(e) => pickTemplate(e.target.value)} options={TEMPLATES.map((t) => ({ v: t.key, l: t.label }))} placeholder="No template" />
        </Field>
        <Field label="Title" required className="span2"><Input value={v.title} onChange={(e) => set('title', e.target.value)} maxLength={140} autoFocus /></Field>
        <Field label="Body" className="span2"><Textarea rows={4} value={v.body} onChange={(e) => set('body', e.target.value)} maxLength={600} /></Field>
        <Field label="Audience" required>
          <Select value={v.audience} onChange={(e) => set('audience', e.target.value)} options={AUDIENCES} placeholder={false} />
        </Field>
        {v.audience === 'role' && (
          <Field label="Role" required>
            <Select value={v.role} onChange={(e) => set('role', e.target.value)} options={HUMAN_ROLES.map((r) => ({ v: r, l: roleLabel(r) }))} />
          </Field>
        )}
        <Field label="Tone"><Select value={v.tone} onChange={(e) => set('tone', e.target.value)} options={TONES} placeholder={false} /></Field>
        <Field label="Channel"><Select value={v.channel} onChange={(e) => set('channel', e.target.value)} options={CHANNELS} placeholder={false} /></Field>
        <Field label="Link" help="In-app path, e.g. /college/exams."><Input value={v.link} onChange={(e) => set('link', e.target.value)} maxLength={300} /></Field>
        <Field label="Schedule for" help="Leave blank to send immediately."><Input type="datetime-local" value={v.scheduledAt} onChange={(e) => set('scheduledAt', e.target.value)} /></Field>
        {err && <div className="span2"><Alert tone="danger">{err}</Alert></div>}
      </form>
    </Modal>
  );
}

export function AdminNotificationsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const notifications = useCol('notifications', false);
  const [sending, setSending] = useState(false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const flash = useFlash();
  const perms = usePerm();

  const rows = useMemo(() => notifications
    .filter((n) => !n.deleted && (!n.tenantId || n.tenantId === tenantId))
    .sort((a, b) => b.createdAt - a.createdAt), [notifications, tenantId]);
  const stats = notifStats(rows, null);

  return (
    <Page title="Notifications" desc="Institutional notifications and delivery log."
      actions={perms('notify.manage') ? <button className="btn primary" onClick={() => setSending(true)}><Icon name="mail" size={15} /> Send notification</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Messages" value={rows.length} icon="mail" />
        <Stat label="Scheduled" value={rows.filter((n) => n.status === 'scheduled').length} icon="clock" tone="amber" />
        <Stat label="Critical" value={rows.filter((n) => n.tone === 'danger').length} icon="warn" tone="red" />
        <Stat label="Read receipts" value={rows.reduce((s, n) => s + (n.readBy || []).length, 0)} icon="check" tone="green" />
      </StatGrid>
      <DataTable
        title="Delivery log" desc="Newest first. Scheduled messages are hidden from recipients until their send time."
        rows={rows} search={(n) => `${n.title} ${n.body} ${n.kind} ${n.tone} ${n.channel}`}
        filters={[
          { key: 'tone', label: 'Tone', options: TONES },
          { key: 'channel', label: 'Channel', options: CHANNELS },
          { key: 'status', label: 'Status', get: (n) => n.status || 'sent', options: [{ v: 'sent', l: 'Sent' }, { v: 'scheduled', l: 'Scheduled' }] },
        ]}
        columns={[
          { key: 'title', label: 'Title', render: (n) => <><b>{n.title}</b><div className="muted sm">{n.body}</div></> },
          { key: 'tone', label: 'Tone', render: (n) => <Badge value={n.tone} /> },
          { key: 'channel', label: 'Channel', render: (n) => n.channel || 'in-app' },
          { key: 'audience', label: 'Audience', render: (n) => (n.role ? roleLabel(n.role) : n.userId ? n.userId : 'Everyone') },
          { key: 'status', label: 'Status', render: (n) => <Badge value={n.status || 'sent'} /> },
          { key: 'readBy', label: 'Read', render: (n) => (n.readBy || []).length },
          { key: 'createdAt', label: 'Created', sortable: true, render: (n) => fmt(n.createdAt) },
        ]}
        actions={(n) => [
          { label: 'View', onClick: () => setView(n) },
          ...(perms('notify.manage') ? [{ label: 'Delete', danger: true, onClick: () => setAct(n) }] : []),
        ]}
      />
      {sending && <BroadcastModal tenantId={tenantId} onClose={() => setSending(false)} onDone={(m) => flash.setMsg({ ok: true, text: m })} />}
      {act && (
        <ActionDialog title="Delete notification" desc={act.title} danger confirmLabel="Delete" requireReason={false}
          onClose={() => setAct(null)} onConfirm={() => flash.run(() => remove(user, act))} />
      )}
      {view && (
        <Modal title={view.title} desc={`${view.tone} · ${view.channel || 'in-app'}`} onClose={() => setView(null)} footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <p className="preserve">{view.body}</p>
          <Field label="Audience">{view.role ? roleLabel(view.role) : view.userId || 'Everyone'}</Field>
          <Field label="Link">{view.link || '—'}</Field>
          <Field label="Read by">{(view.readBy || []).length ? (view.readBy || []).join(', ') : 'Nobody yet'}</Field>
          <Field label="Created">{fmt(view.createdAt)}</Field>
        </Modal>
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ inbox */
export function NotificationsPage() {
  const { user } = useAuth();
  const notifications = useCol('notifications', false);
  const [tab, setTab] = useState('unread');
  const [view, setView] = useState(null);
  const flash = useFlash();
  const navigate = useNavigate();

  const visible = useMemo(() => visibleTo(user, notifications).sort((a, b) => b.createdAt - a.createdAt), [notifications, user]);
  const archived = useMemo(() => notifications
    .filter((n) => !n.deleted && (n.archivedBy || []).includes(user.id))
    .filter((n) => !n.tenantId || !user.tenantId || n.tenantId === user.tenantId)
    .sort((a, b) => b.createdAt - a.createdAt), [notifications, user]);
  const unread = visible.filter((n) => !(n.readBy || []).includes(user.id));
  const rows = tab === 'unread' ? unread : tab === 'archived' ? archived : visible;

  const open = async (n) => {
    await flash.run(async () => {
      if (!(n.readBy || []).includes(user.id)) await markRead(user.id, n);
      setView(n);
      return 'Notification opened.';
    });
  };

  return (
    <Page title="Inbox" desc="Your notifications and announcements."
      actions={unread.length ? <button className="btn" onClick={() => flash.run(async () => { await markAllRead(user.id, unread); return `${unread.length} notification(s) marked read.`; })}><Icon name="check" size={15} /> Mark all read</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Unread" value={unread.length} icon="bell" tone="amber" />
        <Stat label="Inbox" value={visible.length} icon="mail" />
        <Stat label="Archived" value={archived.length} icon="package" />
        <Stat label="Critical" value={visible.filter((n) => n.tone === 'danger').length} icon="warn" tone="red" />
      </StatGrid>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'unread', label: 'Unread', count: unread.length },
        { key: 'all', label: 'All', count: visible.length },
        { key: 'archived', label: 'Archived', count: archived.length },
      ]} />
      <DataTable
        title="Notifications" desc="Open a notification to mark it read."
        rows={rows} search={(n) => `${n.title} ${n.body}`}
        columns={[
          { key: 'title', label: 'Title', render: (n) => <><b>{n.title}</b>{!(n.readBy || []).includes(user.id) && <span className="unread-dot" />}<div className="muted sm">{n.body}</div></> },
          { key: 'tone', label: 'Tone', render: (n) => <Badge value={n.tone} /> },
          { key: 'createdAt', label: 'Received', sortable: true, render: (n) => ago(n.createdAt) },
          { key: 'readBy', label: 'Read', render: (n) => ((n.readBy || []).includes(user.id) ? <Badge value="read" /> : <Badge value="unread" />) },
        ]}
        actions={(n) => [
          { label: 'Open', onClick: () => open(n) },
          ...(tab === 'archived'
            ? [{ label: 'Restore', onClick: () => flash.run(async () => { await unarchive(user.id, n); return 'Restored to inbox.'; }) }]
            : [{ label: 'Archive', onClick: () => flash.run(async () => { await archive(user.id, n); return 'Archived.'; }) }]),
        ]}
        empty={<Empty icon="bell" title={tab === 'unread' ? 'No unread notifications' : 'Nothing here yet'} />}
      />
      {view && (
        <Modal title={view.title} desc={`${view.tone} · ${fmt(view.createdAt)}`} onClose={() => setView(null)}
          footer={<>
            {view.link && <button className="btn primary" onClick={() => { setView(null); navigate(view.link); }}>Open link</button>}
            <button className="btn" onClick={() => setView(null)}>Close</button>
          </>}>
          <p className="preserve">{view.body}</p>
        </Modal>
      )}
    </Page>
  );
}
