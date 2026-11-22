import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert, ActionDialog,
  Modal, KeyValue, Timeline, Field, Input, Select, Textarea, useFlash, Flash, Tabs, Progress,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { formatExamSchedule } from '../../core/ui/normalizers';
import { useLoad, usePerm } from '../../core/ui/hooks';
import * as Api from '../../core/api/services';
import {
  assignedExams, liveBoard, boardStats, checkIn, startCandidate, terminateSession, extendTime,
  submissionFeed, submissionStats, deskLookup,
} from './service';
import { raise, move, addNote, assign, falsePositive, promote, FLOW } from '../incidents/service';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const NEXT_LABEL = { investigating: 'Start investigating', contained: 'Contain', resolved: 'Resolve', closed: 'Close', open: 'Reopen' };

/* ------------------------------------------------------------------ overview */
export function OperatorOverviewPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const exams = useCol('exams', false);
  const sessions = useCol('sessions', false);
  const incidents = useCol('incidents', false);
  const candidates = useCol('candidates', false);
  const devices = useCol('devices', false);
  const [roll, setRoll] = useState('');
  const [lookup, setLookup] = useState(null);
  const flash = useFlash();

  const targetTenantId = tenantId || user?.tenantId;
  const mine = useMemo(() => exams.filter((e) => !targetTenantId || e.tenantId === targetTenantId), [exams, targetTenantId]);
  const live = mine.filter((e) => e.status === 'live');
  const openIncidents = incidents.filter((i) => (!targetTenantId || i.tenantId === targetTenantId) && ['open', 'investigating', 'contained'].includes(i.status));
  const activeSessions = sessions.filter((s) => (!targetTenantId || s.tenantId === targetTenantId) && s.status === 'in_progress');
  const submitted = sessions.filter((s) => (!targetTenantId || s.tenantId === targetTenantId) && s.status === 'submitted');

  const doLookup = (e) => {
    e.preventDefault();
    flash.run(async () => {
      const c = await deskLookup(roll, targetTenantId);
      setLookup(c);
      return `${c.name} · ${c.rollNo}`;
    });
  };

  return (
    <Page title="Operations overview" desc="Live sessions, incidents and desk check-in for your institution."
      actions={<Link className="btn" to="/operator/exams">Assigned exams <Icon name="arrow" size={14} /></Link>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Live exams" value={live.length} icon="exam" tone="green" to="/operator/exams" />
        <Stat label="Active sessions" value={activeSessions.length} icon="pulse" tone="amber" />
        <Stat label="Open incidents" value={openIncidents.length} icon="alert" tone="red" to="/operator/incidents" />
        <Stat label="Submitted" value={submitted.length} icon="check" />
      </StatGrid>

      <div className="two">
        <Card title="Desk check-in" desc="Look up a candidate by roll number, then verify their photo ID.">
          <form className="inline-form" onSubmit={doLookup}>
            <Field label="Roll number"><Input value={roll} onChange={(e) => setRoll(e.target.value)} placeholder="e.g. EXM-2026-0001" maxLength={40} /></Field>
            <button className="btn primary" disabled={flash.busy || !roll.trim()}>{flash.busy ? 'Looking up…' : 'Look up'}</button>
          </form>
          {lookup && (
            <div className="lookup-result">
              <KeyValue cols={2} items={[
                ['Candidate', lookup.name], ['Roll number', lookup.rollNo],
                ['Exam', lookup.examId || '—'], ['Centre', lookup.center?.name || '—'],
                ['Seat', lookup.seat || '—'], ['Identity', <Badge key="id" value={lookup.identity} />],
                ['Device', lookup.device ? lookup.device.hostname : 'Not assigned'],
              ]} />
              {lookup.identity !== 'verified' && (
                <button className="btn primary" onClick={() => flash.run(async () => { await checkIn(user, lookup); setLookup({ ...lookup, identity: 'verified' }); return `${lookup.rollNo} checked in.`; })}>Verify identity</button>
              )}
            </div>
          )}
        </Card>
        <Card title="Live exams" desc="Open the live board to monitor seats and intervene.">
          {live.length ? (
            <ul className="list">
              {live.map((e) => (
                <li key={e.id}>
                  <div><b>{e.code}</b><div className="muted sm">{e.title}</div></div>
                  <span className="grow" />
                  <Link className="mini" to={`/operator/exams/${e.id}/live`}>Open board</Link>
                </li>
              ))}
            </ul>
          ) : <Empty icon="exam" title="No live exams" >Exams appear here once they are published and started.</Empty>}
        </Card>
      </div>

      <DataTable
        title="Recent incidents" desc="Newest first. Open the queue to triage."
        rows={[...openIncidents].sort((a, b) => b.createdAt - a.createdAt).slice(0, 8)}
        columns={[
          { key: 'no', label: 'Ref', render: (i) => `INC-${i.no}` },
          { key: 'title', label: 'Title' },
          { key: 'severity', label: 'Severity', render: (i) => <Badge value={i.severity} /> },
          { key: 'status', label: 'Status', render: (i) => <Badge value={i.status} /> },
          { key: 'createdAt', label: 'Raised', render: (i) => ago(i.createdAt) },
        ]}
        empty={<Empty icon="check" title="No open incidents" />}
      />
    </Page>
  );
}

/* ------------------------------------------------------------------ exams */
export function OperatorExamsPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const { data: rows, loading, error } = useLoad(() => assignedExams(user), [user.id]);

  return (
    <Page title="Assigned exams" desc="Exams assigned to you for invigilation, ordered by status and start time.">
      {error && <Alert tone="danger" title="Could not load exams">{error.message}</Alert>}
      {loading ? <Loading /> : (
        <DataTable
          title="Exam assignments" desc="Open a live exam to monitor seats and candidates."
          rows={rows || []}
          search={(e) => `${e.code} ${e.title} ${e.status}`}
          filters={[
            { key: 'status', label: 'Status', options: ['draft', 'review', 'approved', 'published', 'live', 'closed', 'cancelled'].map((s) => ({ v: s, l: s })) },
          ]}
          defaultSort={{ key: 'startAt', dir: 'asc' }}
          columns={[
            { key: 'code', label: 'Code', sortable: true, mono: true },
            { key: 'title', label: 'Title', sortable: true },
            { key: 'status', label: 'Status', render: (e) => <Badge value={e.status} /> },
            { key: 'startAt', label: 'Starts', sortable: true, render: (e) => formatExamSchedule(e) },
            { key: 'durationMin', label: 'Duration', render: (e) => {
              const dur = e.durationMin || e.duration_minutes || e.durationMin;
              return dur ? `${dur} min` : <span className="muted">Duration unavailable</span>;
            } },
            { key: 'assigned', label: 'Candidates', render: (e) => e.assigned },
            { key: 'inProgress', label: 'In progress', render: (e) => <Badge value={String(e.inProgress)} /> },
            { key: 'submitted', label: 'Submitted', render: (e) => e.submitted },
            { key: 'centers', label: 'Centres', render: (e) => (e.centers || []).length },
          ]}
          actions={(e) => [
            { label: 'Live board', onClick: () => nav(`/operator/exams/${e.id}/live`) },
            { label: 'Incidents', onClick: () => nav(`/operator/exams/${e.id}/incidents`) },
            { label: 'Submissions', onClick: () => nav(`/operator/exams/${e.id}/submissions`) },
          ]}
        />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ live board */
export function LiveExamPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const exams = useCol('exams', false);
  const cachedExam = exams.find((x) => x.id === id);
  const detail = useLoad(async () => {
    if (!id) return null;
    const res = await Api.getExamination(id);
    return res?.examination || res;
  }, [id]);
  const sessions = useCol('sessions', false);
  const candidates = useCol('candidates', false);
  const devices = useCol('devices', false);
  const incidents = useCol('incidents', false);
  const attestations = useCol('attestations', false);
  const centers = useCol('centers', false);
  const [act, setAct] = useState(null);
  const [tab, setTab] = useState('seats');
  const flash = useFlash();
  const perms = usePerm();

  const exam = detail.data || cachedExam;
  const board = useLoad(
    () => (exam ? liveBoard(exam, { candidates, sessions, devices, centers, incidents, attestations }) : Promise.resolve({ rows: [], byCenter: [], incidents: [] })),
    [id, exam, sessions, candidates, devices, incidents, attestations, centers, exams],
  );

  if (!exam && detail.loading) return <Page title="Loading exam"><Loading /></Page>;
  if (!exam && detail.error) return <Page title="Exam unavailable"><Alert tone="danger" title="Could not load examination">{detail.error.message}</Alert><Link className="btn" to="/operator/exams">Back to exams</Link></Page>;
  if (!exam) return <Page title="Exam not found"><Empty icon="exam" title="No such exam" action={<Link className="btn" to="/operator/exams">Back to exams</Link>} /></Page>;

  const rawReason = exam.cancelReason || exam.cancel_reason || (exam.history || []).slice().reverse().find((h) => h?.to === 'cancelled' || h?.to_status === 'cancelled' || h?.action === 'EXAM_CANCELLED')?.reason;
  const reason = rawReason ? String(rawReason).trim().replace(/\.+$/, '') : '';
  const isCancelled = exam.status === 'cancelled';
  const isClosed = exam.status === 'closed';
  const pageTitle = isCancelled ? `Cancelled (Historical): ${exam.code}` : isClosed ? `Closed: ${exam.code}` : `Live: ${exam.code}`;

  if (board.loading) return <Page title={pageTitle}><Loading /></Page>;
  const b = board.data || { rows: [], byCenter: [] };
  const stats = boardStats(b);
  const rows = b.rows || [];

  return (
    <Page title={pageTitle} desc={exam.title}
      breadcrumb={<div className="crumbs-inline"><Link to="/operator/exams">Assigned exams</Link><Icon name="arrow" size={12} /><span>{exam.code}</span></div>}
      actions={<>
        <Link className="btn" to={`/operator/exams/${exam.id}/incidents`}>Incidents <Badge value={String(b.incidents?.length || 0)} /></Link>
        <Link className="btn" to={`/operator/exams/${exam.id}/submissions`}>Submissions</Link>
      </>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      {isCancelled && (
        <Alert tone="warn" title="This examination was cancelled — Read-only historical board">
          {reason ? `Cancellation reason: ${reason}. ` : ''}Live interventions, candidate check-ins, and session actions are disabled for cancelled examinations.
        </Alert>
      )}
      {isClosed && (
        <Alert tone="info" title="This examination is closed — Read-only historical board">
          Examination has concluded. Live interventions are disabled.
        </Alert>
      )}
      <StatGrid cols={5}>
        <Stat label="Assigned" value={stats.assigned} icon="users" />
        <Stat label="Verified" value={stats.verified} icon="check" tone="green" />
        <Stat label="Started" value={stats.started} icon="pulse" tone="amber" />
        <Stat label="Submitted" value={stats.submitted} icon="check" />
        <Stat label="Device issues" value={stats.issues} icon="warn" tone="red" />
      </StatGrid>
      <Card title="Attendance" desc={`${stats.started} of ${stats.assigned} candidates have started.`} pad>
        <Progress value={stats.started} max={Math.max(1, stats.assigned)} label="Started" />
      </Card>
      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'seats', label: 'Seats', count: rows.length },
        { key: 'centers', label: 'Centres', count: (b.byCenter || []).length },
      ]} />
      {tab === 'seats' && (
        <DataTable
          title="Seat board" desc={isCancelled ? 'Historical seating record. Candidate check-in and session interventions are disabled.' : isClosed ? 'Concluded examination seating record. Live interventions are disabled.' : 'Check in candidates, start sessions and handle interventions.'}
          rows={rows} search={(r) => `${r.name} ${r.rollNo} ${r.state} ${r.deviceState}`}
          filters={[
            { key: 'state', label: 'State', options: ['waiting-identity', 'ready', 'in_progress', 'submitted', 'terminated'].map((s) => ({ v: s, l: s })) },
            { key: 'deviceState', label: 'Device', options: ['attested', 'healthy', 'offline', 'isolated', 'failed', 'none'].map((s) => ({ v: s, l: s })) },
          ]}
          columns={[
            { key: 'name', label: 'Candidate', sortable: true, render: (r) => <><b>{r.name}</b><div className="muted sm mono">{r.rollNo}</div></> },
            { key: 'seat', label: 'Seat', mono: true },
            { key: 'center', label: 'Centre', render: (r) => r.center?.name || '—' },
            { key: 'identity', label: 'Identity', render: (r) => <Badge value={r.identity} /> },
            { key: 'state', label: 'State', render: (r) => <Badge value={r.state} /> },
            { key: 'deviceState', label: 'Device', render: (r) => <Badge value={r.deviceState} /> },
            { key: 'session', label: 'Session', render: (r) => (r.session ? <span className="mono sm">{r.session.status}</span> : '—') },
            { key: 'remaining', label: 'Remaining', render: (r) => (r.session?.status === 'in_progress' ? `${Math.ceil(r.remaining / 60000)} min` : '—') },
          ]}
          actions={(r) => {
            if (isCancelled || isClosed) return [];
            const out = [];
            if (perms('exam.operate') && r.identity !== 'verified') out.push({ label: 'Check in', onClick: () => flash.run(async () => { await checkIn(user, r); return `${r.rollNo} checked in.`; }) });
            if (perms('exam.operate') && r.identity === 'verified' && !r.session) out.push({ label: 'Start', onClick: () => flash.run(async () => { await startCandidate(user, r); return `Session started for ${r.rollNo}.`; }) });
            if (r.session?.status === 'in_progress') {
              out.push({ label: 'Extend', onClick: () => setAct({ type: 'extend', row: r }) });
              if (perms('session.terminate')) out.push({ label: 'Terminate', danger: true, onClick: () => setAct({ type: 'terminate', row: r }) });
            }
            return out;
          }}
        />
      )}
      {tab === 'centers' && (
        <DataTable
          title="Centres" desc="Attendance and device issues by centre."
          rows={b.byCenter || []}
          columns={[
            { key: 'center', label: 'Centre', render: (c) => <><b>{c.center?.name}</b><div className="muted sm">{c.center?.city || ''}</div></> },
            { key: 'seats', label: 'Seats', render: (c) => c.seats.length },
            { key: 'started', label: 'Started', render: (c) => <Badge value={String(c.started)} /> },
            { key: 'submitted', label: 'Submitted', render: (c) => c.submitted },
            { key: 'issues', label: 'Issues', render: (c) => <Badge value={String(c.issues)} /> },
          ]}
        />
      )}
      {act?.type === 'extend' && (
        <ActionDialog title="Extend session" desc={`${act.row.name} · ${act.row.rollNo}`} confirmLabel="Extend"
          field={{ label: 'Minutes (1–60)', type: 'number', default: '10' }}
          onClose={() => setAct(null)} onConfirm={(reason, val) => flash.run(() => extendTime(user, act.row.session, val, reason))} />
      )}
      {act?.type === 'terminate' && (
        <ActionDialog title="Terminate session" desc={`${act.row.name} · ${act.row.rollNo}`} danger confirmLabel="Terminate"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => terminateSession(user, act.row.session, reason))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ incidents */
export function OperatorIncidentsPage() {
  const { id: examId } = useParams();
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const incidents = useCol('incidents', false);
  const exams = useCol('exams', false);
  const users = useCol('users', false);
  const [act, setAct] = useState(null);
  const [view, setView] = useState(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: '', severity: 'medium', description: '' });
  const flash = useFlash();
  const perms = usePerm();

  const exam = examId ? exams.find((e) => e.id === examId) : null;
  const rows = useMemo(() => incidents
    .filter((i) => i.tenantId === tenantId)
    .filter((i) => !examId || i.examId === examId)
    .sort((a, b) => b.createdAt - a.createdAt), [incidents, tenantId, examId]);

  const create = async (e) => {
    e.preventDefault();
    await flash.run(async () => {
      const inc = await raise({ tenantId, key: `op:${Date.now()}`, title: form.title, severity: form.severity, source: 'operator-console', examId });
      if (form.description.trim()) await addNote(user, inc, form.description);
      setCreating(false);
      setForm({ title: '', severity: 'medium', description: '' });
      return `INC-${inc.no} raised.`;
    });
  };

  return (
    <Page title={exam ? `Incidents · ${exam.code}` : 'Incident queue'} desc="Report, triage and resolve exam incidents."
      actions={perms('incident.manage') ? <button className="btn primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New incident</button> : null}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Open" value={rows.filter((i) => i.status === 'open').length} icon="alert" tone="red" />
        <Stat label="Investigating" value={rows.filter((i) => i.status === 'investigating').length} icon="search" tone="amber" />
        <Stat label="Resolved" value={rows.filter((i) => ['resolved', 'closed'].includes(i.status)).length} icon="check" tone="green" />
        <Stat label="Total" value={rows.length} icon="chart" />
      </StatGrid>
      <DataTable
        title="Incidents" desc="Newest first. Every action is written to the audit trail."
        rows={rows} search={(i) => `${i.no} ${i.title} ${i.severity} ${i.status} ${i.owner || ''}`}
        filters={[
          { key: 'status', label: 'Status', options: ['open', 'investigating', 'contained', 'resolved', 'closed', 'false_positive'].map((s) => ({ v: s, l: s })) },
          { key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ v: s, l: s })) },
        ]}
        columns={[
          { key: 'no', label: 'Ref', render: (i) => <span className="mono">INC-{i.no}</span> },
          { key: 'title', label: 'Title', render: (i) => <><b>{i.title}</b>{i.kind === 'finding' && <Badge className="ml" value="finding" />}</> },
          { key: 'severity', label: 'Severity', render: (i) => <Badge value={i.severity} /> },
          { key: 'status', label: 'Status', render: (i) => <Badge value={i.status} /> },
          { key: 'owner', label: 'Owner', render: (i) => i.owner || 'Unassigned' },
          { key: 'createdAt', label: 'Raised', sortable: true, render: (i) => ago(i.createdAt) },
        ]}
        actions={(i) => {
          const out = [{ label: 'View', onClick: () => setView(i) }];
          if (!perms('incident.manage')) return out;
          for (const to of (FLOW[i.status] || [])) out.push({ label: NEXT_LABEL[to] || to, onClick: () => setAct({ type: 'move', row: i, to }) });
          out.push({ label: 'Note', onClick: () => setAct({ type: 'note', row: i }) });
          out.push({ label: 'Assign', onClick: () => setAct({ type: 'assign', row: i }) });
          if (!['false_positive', 'closed'].includes(i.status)) out.push({ label: 'False positive', danger: true, onClick: () => setAct({ type: 'false', row: i }) });
          if (i.kind !== 'finding') out.push({ label: 'Promote', onClick: () => setAct({ type: 'promote', row: i }) });
          return out;
        }}
      />

      {creating && (
        <Modal title="Raise incident" desc="Record what happened. You can add more notes later." onClose={() => setCreating(false)}
          footer={<><button className="btn" onClick={() => setCreating(false)}>Cancel</button><button className="btn primary" form="incident-form" disabled={flash.busy}>{flash.busy ? 'Saving…' : 'Raise incident'}</button></>}>
          <form id="incident-form" onSubmit={create} className="formgrid">
            <Field label="Title" required className="span2"><Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} maxLength={140} autoFocus /></Field>
            <Field label="Severity"><Select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} options={SEVERITIES.map((s) => ({ v: s, l: s }))} placeholder={false} /></Field>
            <Field label="Description" className="span2"><Textarea rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} maxLength={400} /></Field>
          </form>
        </Modal>
      )}

      {view && (
        <Modal wide title={`INC-${view.no} · ${view.title}`} desc={`${view.severity} · ${view.status}`} onClose={() => setView(null)}
          footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={3} items={[
            ['Source', view.source || '—'], ['Owner', view.owner || 'Unassigned'],
            ['Kind', view.kind || 'alert'], ['Raised', fmt(view.createdAt)],
            ['Device', view.deviceId || '—'], ['Exam', view.examId || '—'],
          ]} />
          <h4>Investigation notes</h4>
          {view.notes?.length ? (
            <Timeline items={view.notes.map((n) => ({ id: `${n.at}`, title: n.by, meta: fmt(n.at), body: n.text }))} />
          ) : <Empty icon="ticket" title="No notes yet" />}
        </Modal>
      )}

      {act?.type === 'move' && (
        <ActionDialog title={NEXT_LABEL[act.to] || `Move to ${act.to}`} desc={`INC-${act.row.no}: ${act.row.title}`}
          confirmLabel="Confirm" requireReason={false} onClose={() => setAct(null)}
          onConfirm={() => flash.run(() => move(user, act.row, act.to))} />
      )}
      {act?.type === 'note' && (
        <ActionDialog title="Add investigation note" desc={`INC-${act.row.no}`} confirmLabel="Add note" requireReason={false}
          field={{ label: 'Note', type: 'textarea', max: 400 }} onClose={() => setAct(null)}
          onConfirm={(_r, val) => flash.run(() => addNote(user, act.row, val))} />
      )}
      {act?.type === 'assign' && (
        <ActionDialog title="Assign incident" desc={`INC-${act.row.no}`} confirmLabel="Assign" requireReason={false}
          field={{ label: 'Owner', options: users.filter((u) => u.tenantId === tenantId || !u.tenantId).map((u) => ({ v: u.id, l: `${u.name} (${u.role})` })) }}
          onClose={() => setAct(null)} onConfirm={(_r, val) => flash.run(() => assign(user, act.row, val))} />
      )}
      {act?.type === 'false' && (
        <ActionDialog title="Mark false positive" desc={`INC-${act.row.no}`} danger confirmLabel="Mark false positive"
          onClose={() => setAct(null)} onConfirm={(reason) => flash.run(() => falsePositive(user, act.row, reason))} />
      )}
      {act?.type === 'promote' && (
        <ActionDialog title="Promote to finding" desc="Promote only after a human has reviewed the evidence." confirmLabel="Promote"
          requireReason={false} onClose={() => setAct(null)} onConfirm={() => flash.run(() => promote(user, act.row))} />
      )}
    </Page>
  );
}

/* ------------------------------------------------------------------ submissions */
export function OperatorSubmissionsPage() {
  const { id } = useParams();
  const sessions = useCol('sessions', false);
  const candidates = useCol('candidates', false);
  const devices = useCol('devices', false);
  const exams = useCol('exams', false);
  const [view, setView] = useState(null);

  const { data: feed, loading } = useLoad(
    () => submissionFeed({ id: id || 'all' }, { sessions, candidates, devices }),
    [id, sessions, candidates, devices],
  );
  const rows = feed || [];
  const stats = submissionStats(rows);

  return (
    <Page title="Submissions" desc="Review submitted exam sessions and receipt integrity."
      breadcrumb={id ? <div className="crumbs-inline"><Link to="/operator/exams">Assigned exams</Link><Icon name="arrow" size={12} /><span>Submissions</span></div> : undefined}>
      <StatGrid cols={5}>
        <Stat label="Total sessions" value={stats.total} icon="chart" />
        <Stat label="Submitted" value={stats.submitted} icon="check" tone="green" />
        <Stat label="In progress" value={stats.inProgress} icon="pulse" tone="amber" />
        <Stat label="Terminated" value={stats.terminated} icon="warn" tone="red" />
        <Stat label="Average score" value={stats.avg} icon="chart" />
      </StatGrid>
      {loading ? <Loading /> : (
        <DataTable
          title="Submission feed" desc="Newest submissions first."
          rows={rows} search={(s) => `${s.receipt} ${s.candidate?.name} ${s.candidate?.rollNo} ${s.status}`}
          filters={[{ key: 'status', label: 'Status', options: ['in_progress', 'submitted', 'terminated'].map((s) => ({ v: s, l: s })) }]}
          defaultSort={{ key: 'submittedAt', dir: 'desc' }}
          columns={[
            { key: 'receipt', label: 'Receipt', render: (s) => <span className="mono">{s.receipt || '—'}</span> },
            { key: 'candidate', label: 'Candidate', render: (s) => s.candidate ? <><b>{s.candidate.name}</b><div className="muted sm mono">{s.candidate.rollNo}</div></> : '—' },
            { key: 'examId', label: 'Exam', render: (s) => exams.find((e) => e.id === s.examId)?.code || s.examId },
            { key: 'device', label: 'Device', render: (s) => s.device?.hostname || '—' },
            { key: 'status', label: 'Status', render: (s) => <Badge value={s.status} /> },
            { key: 'submittedAt', label: 'Submitted', sortable: true, render: (s) => (s.submittedAt ? fmt(s.submittedAt) : '—') },
            { key: 'score', label: 'Score', render: (s) => (s.status === 'submitted' ? `${s.score || 0}/${s.total || '—'}` : '—') },
            { key: 'auto', label: 'Auto', render: (s) => (s.auto ? <Badge value="auto" /> : '—') },
          ]}
          actions={(s) => [{ label: 'View', onClick: () => setView(s) }]}
        />
      )}
      {view && (
        <Modal wide title={`Submission ${view.receipt || view.id}`} desc={view.candidate?.name} onClose={() => setView(null)}
          footer={<button className="btn primary" onClick={() => setView(null)}>Close</button>}>
          <KeyValue cols={2} items={[
            ['Candidate', view.candidate ? `${view.candidate.name} (${view.candidate.rollNo})` : '—'],
            ['Status', <Badge key="s" value={view.status} />],
            ['Started', fmt(view.startedAt)], ['Submitted', view.submittedAt ? fmt(view.submittedAt) : '—'],
            ['Score', `${view.score ?? 0} / ${view.total ?? '—'}`], ['Auto-submitted', view.auto ? 'Yes' : 'No'],
            ['Receipt', view.receipt || '—'], ['Device', view.device?.hostname || '—'],
          ]} />
          {view.receiptSig && <Alert tone="success" title="Signed receipt">This submission carries a signed receipt payload.</Alert>}
        </Modal>
      )}
    </Page>
  );
}
