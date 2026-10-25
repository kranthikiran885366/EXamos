import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Alert, Steps, Progress,
  KeyValue, Timeline, Field, Input, Textarea, Modal, ActionDialog, Flash, useFlash,
} from '../../core/ui/kit';
import { useLoad } from '../../core/ui/hooks';
import { useNow } from '../../core/db/tenant';
import { fmt } from '../../core/ui/format';
import {
  STUDENT_STEPS, assignments, briefing, deviceCheck, startMyExam, saveMyAnswer, submitMyExam,
  receipt, myHistory, requestHelp, remaining,
} from './service';

const tone = (s) => (s === 'PASS' ? 'green' : s === 'WARN' ? 'amber' : 'red');

function StudentShell({ title, desc, children, actions }) {
  return <Page title={title} desc={desc} actions={actions}>{children}</Page>;
}

function AssignmentTable({ rows, onOpen }) {
  return <DataTable rows={rows} search={['status']} columns={[
    { label: 'Exam', render: (a) => <div><b>{a.exam?.code || 'Unassigned'}</b><div className="muted sm">{a.exam?.title || '—'}</div></div> },
    { label: 'Centre', render: (a) => (a.center ? `${a.center.code} · ${a.center.city}` : '—') },
    { label: 'Seat', render: (a) => a.candidate?.seat || '—' },
    { label: 'Starts', render: (a) => (a.exam?.startAt ? fmt(a.exam.startAt) : '—') },
    { label: 'Status', render: (a) => <Badge value={a.status} /> },
    { label: 'Action', render: (a) => (a.exam ? <Link className="btn small" to={`/student/exams/${a.exam.id}`}>{a.status === 'submitted' ? 'Receipt' : a.status === 'in-progress' ? 'Resume' : 'Open'}</Link> : '—') },
  ]} onRow={(a) => a.exam && onOpen?.(a.exam)} />;
}

export function StudentHomePage() {
  const { user } = useAuth();
  const { data, loading, error, reload } = useLoad(() => assignments(user), [user?.id]);
  if (loading) return <StudentShell title="My exams"><Card><div className="loading"><span className="spinner" /> Loading your assignments…</div></Card></StudentShell>;
  if (error) return <StudentShell title="My exams"><Alert tone="danger" title="We could not load your assignments">{error.message}</Alert></StudentShell>;
  const rows = data || [];
  const live = rows.filter((a) => a.status === 'ready' || a.status === 'in-progress');
  const upcoming = rows.filter((a) => a.status === 'scheduled');
  const submitted = rows.filter((a) => a.status === 'submitted');
  return <StudentShell title={`Welcome, ${user?.name?.split(' ')[0] || 'candidate'}`} desc="Your assigned exams, countdown and readiness." actions={<Link className="btn" to="/student/history">History & receipts</Link>}>
    <StatGrid cols={4}>
      <Stat label="Assigned" value={rows.length} icon="exam" />
      <Stat label="Live now" value={live.length} icon="pulse" tone="green" />
      <Stat label="Upcoming" value={upcoming.length} icon="clock" />
      <Stat label="Submitted" value={submitted.length} icon="check" />
    </StatGrid>
    {live.length > 0 && <Alert tone="info" title="An exam window is open">
      {live[0].exam.code} is ready. Open the briefing and complete your device check before starting.
      <div style={{ marginTop: 8 }}><Link className="btn primary small" to={`/student/exams/${live[0].exam.id}`}>Open briefing</Link></div>
    </Alert>}
    <Card title="Your next exams" desc="Exams are listed in start order.">
      {rows.length ? <AssignmentTable rows={rows} /> : <Empty icon="exam" title="No exams assigned">Your institution will assign exams here. Contact support if you expected an exam.</Empty>}
    </Card>
    <Card title="Before you start" desc="What the secure exam environment checks.">
      <Timeline items={[
        { title: 'Identity verified at the centre', body: 'A photo ID check is recorded by the invigilator.' },
        { title: 'Seat device checked', body: 'The kiosk verifies Secure Boot, TPM attestation and the approved release.' },
        { title: 'Policy deployed', body: 'Clipboard, screen capture and USB access follow your exam policy.' },
        { title: 'Answers saved continuously', body: 'Each answer is saved as you select it. Submit before the timer ends.' },
      ]} />
    </Card>
    <div className="row end"><button className="btn" onClick={reload}><Icon name="refresh" size={14} /> Refresh</button></div>
  </StudentShell>;
}

export function StudentExamsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => assignments(user), [user?.id]);
  if (loading) return <StudentShell title="Assignments"><Card><div className="loading"><span className="spinner" /> Loading assignments…</div></Card></StudentShell>;
  if (error) return <StudentShell title="Assignments"><Alert tone="danger">{error.message}</Alert></StudentShell>;
  return <StudentShell title="Assignments" desc="Every exam assigned to your candidate record." actions={<button className="btn" onClick={reload}><Icon name="refresh" size={14} /> Refresh</button>}>
    {data?.length ? <AssignmentTable rows={data} onOpen={(e) => navigate(`/student/exams/${e.id}`)} /> : <Empty icon="exam" title="No assignments yet" />}
  </StudentShell>;
}

export function StudentExamPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => briefing(user, id), [user?.id, id]);
  const { msg, setMsg, run, busy } = useFlash();
  if (loading) return <StudentShell title="Exam briefing"><Card><div className="loading"><span className="spinner" /> Loading briefing…</div></Card></StudentShell>;
  if (error) return <StudentShell title="Exam briefing"><Alert tone="danger" title="Exam unavailable">{error.message}</Alert></StudentShell>;
  const b = data;
  const submitted = b.session?.status === 'submitted';
  const active = b.session?.status === 'in_progress';
  const start = async () => {
    const r = await run(() => startMyExam(user, id), 'Session started.');
    if (r) navigate(`/student/exams/${id}/session`);
  };
  return <StudentShell title={`${b.exam.code} · ${b.exam.title}`} desc={b.exam.description || 'Read the briefing carefully before starting.'} actions={<Link className="btn" to="/student/exams">All assignments</Link>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <Steps steps={STUDENT_STEPS} current={submitted ? 3 : active ? 2 : 0} />
    <StatGrid cols={4}>
      <Stat label="Status" value={b.lifecycle} icon="exam" />
      <Stat label="Duration" value={b.exam.durationMin} unit="min" icon="clock" />
      <Stat label="Questions" value={b.exam.questions?.length || 0} icon="checklist" />
      <Stat label="Window" value={b.exam.startAt ? fmt(b.exam.startAt) : '—'} icon="clock" />
    </StatGrid>
    {b.exam.startAt && !b.windowOpen && <Alert tone="info" title="The exam window is not open yet">It opens at {fmt(b.exam.startAt)}. You can complete the device check early.</Alert>}
    {b.blocking?.length > 0 && <Alert tone="warn" title="Complete the device check">{b.blocking.join(', ')}</Alert>}
    <div className="grid2">
      <Card title="Instructions" pad><div className="prose">{b.instructions || 'No additional instructions were provided.'}</div></Card>
      <Card title="Centre & seat" pad>
        <KeyValue items={[
          ['Centre', b.center ? `${b.center.code} · ${b.center.name}` : '—'],
          ['City', b.center?.city || '—'],
          ['Seat', b.candidate.seat || '—'],
          ['Device', b.device ? `${b.device.hostname} · seat ${b.device.seat}` : 'No device'],
          ['Release', b.device?.release || '—'],
          ['Candidate', `${b.candidate.rollNo} · ${b.candidate.name}`],
        ]} />
      </Card>
    </div>
    <Card title="Security policy" desc="Your session runs under the institution exam policy." pad>
      {b.policySummary ? <KeyValue items={[
        ['TPM attestation', b.policySummary.tpm ? 'Required' : 'Not required'],
        ['Kiosk lockdown', b.policySummary.lockdown ? 'Enforced' : 'Off'],
        ['USB access', b.policySummary.usb ? 'Allowed' : 'Blocked'],
        ['On violation', b.policySummary.violation || '—'],
        ['Allowed origins', (b.policySummary.origins || []).join(', ') || '—'],
      ]} /> : <p className="muted">No policy is attached to this exam. Contact your invigilator.</p>}
    </Card>
    {b.accommodations && <Card title="Approved accommodations" pad>{b.accommodations}</Card>}
    <Card title="What happens next" pad>
      <ol className="prose-list">
        <li>Complete the device check to confirm the seat kiosk is trusted.</li>
        <li>Start the session. The timer begins immediately and cannot be paused.</li>
        <li>Answers save automatically. Submit before the timer reaches zero.</li>
      </ol>
      <div className="row gap">
        {submitted ? <Link className="btn primary" to={`/student/exams/${id}/submission`}>View receipt</Link>
          : active ? <Link className="btn primary" to={`/student/exams/${id}/session`}>Resume session</Link>
            : <>
              <Link className="btn" to={`/student/exams/${id}/device-check`}>Run device check</Link>
              <button className="btn primary" disabled={busy || !b.windowOpen} onClick={start} title={!b.windowOpen ? 'The exam window is not open yet' : ''}>{busy ? 'Starting…' : 'Start exam'}</button>
            </>}
        <button className="btn ghost" onClick={() => run(() => requestHelp(user, { tenantId: b.exam.tenantId, subject: `Help needed for ${b.exam.code}`, description: 'Student requested assistance from the briefing page.', category: 'exam' }), 'Support request created.')}>Request help</button>
      </div>
    </Card>
  </StudentShell>;
}

export function StudentDeviceCheckPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => deviceCheck(user, id), [user?.id, id]);
  const { msg, setMsg, run, busy } = useFlash();
  if (loading) return <StudentShell title="Device check"><Card><div className="loading"><span className="spinner" /> Running preflight checks…</div></Card></StudentShell>;
  if (error) return <StudentShell title="Device check"><Alert tone="danger">{error.message}</Alert></StudentShell>;
  const d = data;
  const passed = d.checks.filter((c) => c.status === 'PASS').length;
  return <StudentShell title="Device check" desc="Preflight checks for the seat kiosk before you start." actions={<Link className="btn" to={`/student/exams/${id}`}>Back to briefing</Link>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <Steps steps={STUDENT_STEPS} current={1} />
    <StatGrid cols={4}>
      <Stat label="Checks passed" value={`${passed}/${d.checks.length}`} icon="checklist" tone={d.ready ? 'green' : 'amber'} />
      <Stat label="Blocking issues" value={d.blocking.length} icon={d.blocking.length ? 'warn' : 'check'} tone={d.blocking.length ? 'red' : 'green'} />
      <Stat label="Seat" value={d.candidate.seat || '—'} icon="pin" />
      <Stat label="Device" value={d.device?.hostname || 'None'} icon="device" />
    </StatGrid>
    {d.ready ? <Alert tone="success" title="Your seat is ready">All checks passed. You can start the exam when the window is open.</Alert>
      : <Alert tone="danger" title="Not ready to start">Resolve the blocking checks below, or call an invigilator for help.</Alert>}
    <Card title="Preflight checks">
      <DataTable rows={d.checks} columns={[
        { label: 'Check', key: 'label' }, { label: 'Status', key: 'status', badge: true }, { label: 'Detail', key: 'detail' },
      ]} />
    </Card>
    <div className="row end">
      <button className="btn" onClick={reload}><Icon name="refresh" size={14} /> Re-run checks</button>
      <button className="btn primary" disabled={!d.ready || busy} onClick={async () => { const r = await run(() => startMyExam(user, id), 'Session started.'); if (r) navigate(`/student/exams/${id}/session`); }}>{busy ? 'Starting…' : 'Start exam'}</button>
    </div>
  </StudentShell>;
}

export function StudentSessionPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useLoad(() => briefing(user, id), [user?.id, id]);
  const { msg, setMsg, run } = useFlash();
  const [saving, setSaving] = useState(false);
  const [confirmSubmit, setConfirmSubmit] = useState(false);
  const now = useNow(1000);
  if (loading) return <StudentShell title="Exam session"><Card><div className="loading"><span className="spinner" /> Loading your session…</div></Card></StudentShell>;
  if (error) return <StudentShell title="Exam session"><Alert tone="danger">{error.message}</Alert></StudentShell>;
  const b = data; const s = b.session; const exam = b.exam;
  if (!s) return <StudentShell title="Exam session"><Empty icon="pulse" title="No session yet">Start the exam from the briefing page.</Empty><div className="row end"><Link className="btn primary" to={`/student/exams/${id}`}>Open briefing</Link></div></StudentShell>;
  if (s.status === 'submitted') return <StudentShell title="Exam session"><Alert tone="success" title="Session submitted">Your receipt is {s.receipt}. Answers can no longer be changed.</Alert><div className="row end"><Link className="btn primary" to={`/student/exams/${id}/submission`}>View receipt</Link></div></StudentShell>;
  const left = remaining(s, now);
  const answered = Object.keys(s.answers || {}).length;
  const choose = async (qi, choice) => {
    if (saving) return; setSaving(true);
    await run(() => saveMyAnswer(user, s.id, qi, choice), 'Answer saved.');
    setSaving(false); reload();
  };
  const submit = async () => {
    const r = await run(() => submitMyExam(user, s.id), 'Exam submitted.');
    if (r) navigate(`/student/exams/${id}/submission`);
  };
  return <StudentShell title={`${exam.code} · Session`} desc="Answers save automatically. Do not close this tab." actions={<span className={'badge ' + (left < 300000 ? 'r' : left < 900000 ? 'a' : 'g')}><i /> {Math.floor(left / 60000)}:{String(Math.floor((left % 60000) / 1000)).padStart(2, '0')} left</span>}>
    <Flash msg={msg} onClose={() => setMsg(null)} />
    <StatGrid cols={4}>
      <Stat label="Time left" value={`${Math.floor(left / 60000)}:${String(Math.floor((left % 60000) / 1000)).padStart(2, '0')}`} icon="clock" tone={left < 300000 ? 'red' : 'blue'} />
      <Stat label="Answered" value={`${answered}/${exam.questions.length}`} icon="checklist" />
      <Stat label="Deadline" value={fmt(s.deadline)} icon="clock" />
      <Stat label="Seat" value={b.candidate.seat || '—'} icon="pin" />
    </StatGrid>
    <Progress value={answered} max={exam.questions.length} label="Progress" />
    <Card title="Questions" desc="Select one option per question.">
      <ol className="qlist">
        {exam.questions.map((q, qi) => <li key={qi} className={s.answers?.[qi] !== undefined ? 'answered' : ''}>
          <div className="qhead"><b>{qi + 1}.</b><span>{q.q}</span></div>
          <div className="qopts">
            {q.options.map((opt, oi) => <label key={oi} className={'qopt' + (s.answers?.[qi] === oi ? ' on' : '')}>
              <input type="radio" name={`q-${qi}`} checked={s.answers?.[qi] === oi} onChange={() => choose(qi, oi)} disabled={left === 0} />
              <span>{String.fromCharCode(65 + oi)}. {opt}</span>
            </label>)}
          </div>
        </li>)}
      </ol>
    </Card>
    <div className="row end sticky-actions">
      <span className="muted sm">{saving ? 'Saving…' : 'All changes saved'}</span>
      <button className="btn primary" onClick={() => setConfirmSubmit(true)} disabled={left === 0}>Submit exam</button>
    </div>
    {confirmSubmit && <ActionDialog title="Submit exam" desc="You cannot change answers after submitting. Unanswered questions are marked incorrect." confirmLabel="Submit now" requireReason={false} onClose={() => setConfirmSubmit(false)} onConfirm={submit} />}
  </StudentShell>;
}

export function StudentSubmissionPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data, loading, error } = useLoad(async () => {
    const b = await briefing(user, id);
    if (!b.session) return { b, receipt: null };
    return { b, receipt: await receipt(user, b.session.id) };
  }, [user?.id, id]);
  if (loading) return <StudentShell title="Submission"><Card><div className="loading"><span className="spinner" /> Loading receipt…</div></Card></StudentShell>;
  if (error) return <StudentShell title="Submission"><Alert tone="danger">{error.message}</Alert></StudentShell>;
  const { b, receipt: r } = data;
  if (!r) return <StudentShell title="Submission"><Empty icon="check" title="Nothing submitted yet" /><div className="row end"><Link className="btn" to={`/student/exams/${id}`}>Back to briefing</Link></div></StudentShell>;
  return <StudentShell title="Submission receipt" desc="Signed proof that your answers were recorded." actions={<Link className="btn" to="/student/history">All receipts</Link>}>
    <Steps steps={STUDENT_STEPS} current={3} />
    <Alert tone={r.valid ? 'success' : 'danger'} title={r.valid ? 'Receipt signature verified' : 'Receipt could not be verified'}>{r.valid ? 'This receipt matches the stored answers and the ExamOS signing key.' : 'Contact support immediately. The stored receipt failed verification.'}</Alert>
    <StatGrid cols={4}>
      <Stat label="Receipt" value={r.receipt} icon="check" />
      <Stat label="Status" value={r.status} icon="exam" />
      <Stat label="Score" value={r.score != null ? r.score : '—'} unit={`/ ${b.exam.questions.length}`} icon="chart" />
      <Stat label="Submitted" value={fmt(r.submittedAt)} icon="clock" />
    </StatGrid>
    <div className="grid2">
      <Card title="Receipt details" pad>
        <KeyValue items={[
          ['Exam', `${b.exam.code} · ${b.exam.title}`],
          ['Candidate', `${b.candidate.rollNo} · ${b.candidate.name}`],
          ['Centre', b.center ? `${b.center.code} · ${b.center.city}` : '—'],
          ['Seat', b.candidate.seat || '—'],
          ['Answers recorded', Object.keys(r.answers || {}).length],
          ['Auto-submitted', r.auto ? 'Yes' : 'No'],
        ]} />
      </Card>
      <Card title="Signature" pad>
        <p className="muted sm">The receipt payload is hashed with SHA-256 and signed with the ExamOS receipt key.</p>
        <div className="codebox">{r.receiptSig || 'No signature'}</div>
      </Card>
    </div>
  </StudentShell>;
}

export function StudentHistoryPage() {
  const { user } = useAuth();
  const { data, loading, error } = useLoad(() => myHistory(user), [user?.id]);
  if (loading) return <StudentShell title="History & receipts"><Card><div className="loading"><span className="spinner" /> Loading history…</div></Card></StudentShell>;
  if (error) return <StudentShell title="History & receipts"><Alert tone="danger">{error.message}</Alert></StudentShell>;
  return <StudentShell title="History & receipts" desc="Past exam sessions and signed receipts.">
    <DataTable rows={data || []} search={['status']} columns={[
      { label: 'Exam', render: (s) => <div><b>{s.exam?.code || s.examId}</b><div className="muted sm">{s.exam?.title || '—'}</div></div> },
      { label: 'Status', key: 'status', badge: true },
      { label: 'Started', render: (s) => fmt(s.startedAt) },
      { label: 'Submitted', render: (s) => (s.submittedAt ? fmt(s.submittedAt) : '—') },
      { label: 'Receipt', render: (s) => s.receipt || '—' },
      { label: 'Signature', render: (s) => <Badge value={s.valid ? 'verified' : 'invalid'} /> },
      { label: '', render: (s) => (s.exam ? <Link className="btn small" to={`/student/exams/${s.exam.id}/submission`}>Open</Link> : '—') },
    ]} />
  </StudentShell>;
}
