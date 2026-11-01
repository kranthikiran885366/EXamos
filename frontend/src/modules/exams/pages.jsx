import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { put } from '../../core/db/db';
import { useTenant, useCol, useColLoaded } from '../../core/db/tenant';
import { usePerm, useLoad } from '../../core/ui/hooks';
import * as Api from '../../core/api/services';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, KeyValue, Timeline, Tabs, Loading, Modal, Field, Input, Select, Textarea, Checkbox,
  Progress, Steps,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  createExam, updateExam, transition, nextSteps, duplicateExam, readiness, conflicts,
  configureExamPolicy, policyPreview, postponeExam, TYPES, LIFECYCLE, LIFECYCLE_LABEL,
  AUTH_MODES, SUBMISSION_MODES, ATTESTATION, REQUIRED_CHECKS,
} from './service';
import { assignToExam, unassign, setIdentity, readinessFor, isReady } from '../candidates/service';
import {
  listExaminationSessions, closeAuthorizedExamSession,
  configureEligibilityRule, listEligibilityRules,
  listExaminationRegistrations, evaluateRegistration, approveRegistration,
  rejectRegistration, grantRegistrationException, importExaminationRegistrations,
  publishExaminationRoster, launchExamSession, heartbeatExamSession,
  interruptExamSession, resumeExamSession,
} from '../../core/api/services';
import ExamsPage from './ExamsPage';

export { ExamsPage };

const local = (t) => {
  const d = new Date(t - new Date().getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
};
const split = (v) => String(v || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const STEP_LABEL = {
  configured: 'Configure exam',
  pending_approval: 'Submit for review',
  review: 'Submit for review',
  draft: 'Return to draft',
  approved: 'Approve exam',
  scheduled: 'Schedule & publish',
  published: 'Publish',
  ready: 'Mark ready',
  in_progress: 'Start exam (live)',
  live: 'Go live',
  closed: 'Close & score',
  finalized: 'Finalize & lock',
  cancelled: 'Cancel exam',
};
const STEP_PERM = {
  approved: 'exam.approve',
  ready: 'exam.operate',
  in_progress: 'exam.operate',
  live: 'exam.operate',
  closed: 'exam.operate',
  finalized: 'exam.manage',
};
const REASON = new Set(['live', 'in_progress', 'cancelled', 'draft']);

/* ------------------------------------------------------------------ new exam */
export function ExamNewPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const navigate = useNavigate();
  const centers = useCol('centers');
  const policies = useCol('policies');
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({
    code: '', title: '', type: 'internal', course: '', academicYear: '', description: '',
    centerIds: [], startAt: local(Date.now() + 3600e3), durationMin: 60, lateEntryMin: 0,
    capacity: 0, timeZone: 'Asia/Kolkata', policyId: '',
    instructions: '', resources: '', accommodations: '',
    authMode: 'candidate-login', identityRequired: true, origins: 'https://exam.examos.example',
    navigation: 'locked', allowedDestinations: '', compatibilityProfile: 'standard-uefi',
    attestationLevel: 'tpm', sessionTimeoutMin: 15, reconnectPolicy: 'allow-reconnect',
    submissionMode: 'either', requiredChecks: ['uefi', 'usb', 'tpm', 'network', 'display', 'keyboard'],
    examUrl: '',
  });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const activeCenters = centers.filter((c) => c.status === 'active');
  const publishedPolicies = policies.filter((p) => p.status === 'published');
  const toggleCenter = (id) => set('centerIds', v.centerIds.includes(id) ? v.centerIds.filter((x) => x !== id) : [...v.centerIds, id]);
  const toggleCheck = (key) => set('requiredChecks', v.requiredChecks.includes(key) ? v.requiredChecks.filter((x) => x !== key) : [...v.requiredChecks, key]);

  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => createExam(user, {
      tenantId, ...v, centerIds: v.centerIds, origins: split(v.origins),
      allowedDestinations: split(v.allowedDestinations),
      durationMin: Number(v.durationMin), lateEntryMin: Number(v.lateEntryMin),
      capacity: Number(v.capacity), sessionTimeoutMin: Number(v.sessionTimeoutMin),
      examUrl: v.examUrl.trim(),
    }), 'Exam created as a draft.');
    if (ok) navigate('/college/exams');
  };

  if (!may('exam.manage')) return <Page title="New exam"><Alert tone="danger">Your role cannot create exams.</Alert></Page>;

  return (
    <Page
      title="New exam"
      desc="Create a draft exam. Drafts can be edited until submitted for review; publication and live operation are gated separately."
      breadcrumb={<div className="crumbs-inline"><Link to="/college/exams">Exams</Link><Icon name="arrow" size={12} /><span>New exam</span></div>}
      actions={<button className="btn" onClick={() => navigate('/college/exams')}>Cancel</button>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <form onSubmit={submit} className="stack">
        <Card title="Exam details">
          <div className="formgrid">
            <Field label="Exam code" required help="4–20 letters, digits or dashes"><Input value={v.code} onChange={(e) => set('code', e.target.value.toUpperCase())} placeholder="NQT-VERB-01" maxLength={20} required /></Field>
            <Field label="Title" required><Input value={v.title} onChange={(e) => set('title', e.target.value)} maxLength={100} required /></Field>
            <Field label="Type"><Select value={v.type} onChange={(e) => set('type', e.target.value)} options={TYPES} placeholder={false} /></Field>
            <Field label="Course"><Input value={v.course} onChange={(e) => set('course', e.target.value)} maxLength={80} placeholder="B.Tech CSE" /></Field>
            <Field label="Academic year"><Input value={v.academicYear} onChange={(e) => set('academicYear', e.target.value)} maxLength={20} placeholder="2026–27" /></Field>
            <Field label="Time zone"><Input value={v.timeZone} onChange={(e) => set('timeZone', e.target.value)} maxLength={40} /></Field>
            <Field label="Description" className="span2"><Textarea rows={2} value={v.description} onChange={(e) => set('description', e.target.value)} maxLength={1000} /></Field>
          </div>
        </Card>

        <Card title="Schedule & centres" desc="Conflicts at a shared centre block publication.">
          <div className="formgrid">
            <Field label="Start" required><Input type="datetime-local" value={v.startAt} onChange={(e) => set('startAt', e.target.value)} required /></Field>
            <Field label="Duration (minutes)" help="15–300"><Input type="number" min={15} max={300} value={v.durationMin} onChange={(e) => set('durationMin', e.target.value)} /></Field>
            <Field label="Late entry (minutes)" help="0–60"><Input type="number" min={0} max={60} value={v.lateEntryMin} onChange={(e) => set('lateEntryMin', e.target.value)} /></Field>
            <Field label="Planned capacity" help="0 means no separate cap"><Input type="number" min={0} value={v.capacity} onChange={(e) => set('capacity', e.target.value)} /></Field>
          </div>
          <Field label="Exam centres" help={activeCenters.length ? 'Only active centres can host an exam.' : 'No active centres exist yet.'}>
            <div className="checkgrid">
              {activeCenters.map((c) => (
                <Checkbox key={c.id} label={`${c.code} · ${c.capacity} seats`} checked={v.centerIds.includes(c.id)} onChange={() => toggleCenter(c.id)} />
              ))}
              {!activeCenters.length && <p className="muted sm">Add a centre from Campuses before scheduling an exam.</p>}
            </div>
          </Field>
        </Card>

        <Card title="Policy & delivery">
          <div className="formgrid">
            <Field label="Exam policy" help="Only published policies can be selected.">
              <Select value={v.policyId} onChange={(e) => set('policyId', e.target.value)} options={publishedPolicies.map((p) => ({ v: p.id, l: `${p.name} v${p.version}` }))} placeholder="No policy selected" />
            </Field>
            <Field label="Candidate authentication">
              <Select value={v.authMode} onChange={(e) => set('authMode', e.target.value)} options={AUTH_MODES} placeholder={false} />
            </Field>
            <Field label="Submission mode"><Select value={v.submissionMode} onChange={(e) => set('submissionMode', e.target.value)} options={SUBMISSION_MODES} placeholder={false} /></Field>
            <Field label="Navigation"><Select value={v.navigation} onChange={(e) => set('navigation', e.target.value)} options={[{ v: 'locked', l: 'Locked to the exam' }, { v: 'allowlist', l: 'Allow listed destinations' }]} placeholder={false} /></Field>
            <Field label="Allowed origins" className="span2" help="Comma or space separated https origins"><Input value={v.origins} onChange={(e) => set('origins', e.target.value)} /></Field>
            {v.navigation === 'allowlist' && <Field label="Allowed destinations" className="span2" help="Optional allowlist for navigation"><Input value={v.allowedDestinations} onChange={(e) => set('allowedDestinations', e.target.value)} /></Field>}
            <Field label="Attestation"><Select value={v.attestationLevel} onChange={(e) => set('attestationLevel', e.target.value)} options={ATTESTATION} placeholder={false} /></Field>
            <Field label="Compatibility profile"><Input value={v.compatibilityProfile} onChange={(e) => set('compatibilityProfile', e.target.value)} maxLength={40} /></Field>
            <Field label="Session timeout (minutes)"><Input type="number" min={5} max={120} value={v.sessionTimeoutMin} onChange={(e) => set('sessionTimeoutMin', e.target.value)} /></Field>
            <Field label="Reconnect policy"><Select value={v.reconnectPolicy} onChange={(e) => set('reconnectPolicy', e.target.value)} options={[{ v: 'allow-reconnect', l: 'Allow reconnect with the same device' }, { v: 'resume-only', l: 'Resume only, no new device' }, { v: 'deny', l: 'Deny reconnection' }]} placeholder={false} /></Field>
            <div className="span2">
              <Checkbox label="Identity verification required at check-in" checked={v.identityRequired} onChange={(e) => set('identityRequired', e.target.checked)} />
            </div>
          </div>
          <Field label="Required device checks">
            <div className="checkgrid">
              {REQUIRED_CHECKS.map((c) => <Checkbox key={c.v} label={c.l} checked={v.requiredChecks.includes(c.v)} onChange={() => toggleCheck(c.v)} />)}
            </div>
          </Field>
        </Card>

        <Card title="Assessment Portal & Instructions" desc="ExamOS Kiosk will navigate candidates directly to this secure assessment URL.">
          <div className="formgrid">
            <Field label="Exam URL" required className="span2" help="The target assessment URL launched inside the secure kiosk environment (e.g. https://assessment.university.edu/exam/cs101)">
              <Input
                type="url"
                value={v.examUrl}
                onChange={(e) => set('examUrl', e.target.value)}
                placeholder="https://assessment.university.edu/exam/cs101"
                required
              />
            </Field>
            <Field label="Candidate instructions" className="span2" help="Required before publication.">
              <Textarea rows={4} value={v.instructions} onChange={(e) => set('instructions', e.target.value)} maxLength={3000} placeholder="Read all instructions before starting. Do not attempt to disconnect hardware or exit the kiosk window." />
            </Field>
            <Field label="Resources" className="span2"><Textarea rows={2} value={v.resources} onChange={(e) => set('resources', e.target.value)} maxLength={1000} /></Field>
            <Field label="Accommodations" className="span2"><Textarea rows={2} value={v.accommodations} onChange={(e) => set('accommodations', e.target.value)} maxLength={1000} /></Field>
          </div>
        </Card>

        <div className="form-actions">
          <button type="button" className="btn" onClick={() => navigate('/college/exams')}>Cancel</button>
          <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save draft'}</button>
        </div>
      </form>
    </Page>
  );
}

/* ------------------------------------------------------------------ edit exam */
function EditExamModal({ exam, centers, policies, onClose, onSaved }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({
    code: exam.code, title: exam.title, type: exam.type, course: exam.course || '',
    academicYear: exam.academicYear || '', description: exam.description || '',
    startAt: local(exam.startAt), durationMin: exam.durationMin, lateEntryMin: exam.lateEntryMin || 0,
    capacity: exam.capacity || 0, timeZone: exam.timeZone || 'Asia/Kolkata', policyId: exam.policyId || '',
    instructions: exam.instructions || '', resources: exam.resources || '', accommodations: exam.accommodations || '',
    examUrl: exam.examUrl || '',
    centerIds: exam.centerIds || [],
  });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const toggleCenter = (id) => set('centerIds', v.centerIds.includes(id) ? v.centerIds.filter((x) => x !== id) : [...v.centerIds, id]);
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => updateExam(user, exam, {
      ...v, durationMin: Number(v.durationMin), lateEntryMin: Number(v.lateEntryMin), capacity: Number(v.capacity),
      examUrl: v.examUrl.trim(),
    }), 'Exam configuration saved.');
    if (ok) { onSaved?.(); onClose(); }
  };
  return (
    <Modal title={`Edit ${exam.code}`} desc="Critical settings are locked once the exam is live or closed." onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="exam-edit" disabled={busy}>{busy ? 'Saving…' : 'Save changes'}</button></>}>
      <form id="exam-edit" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <div className="formgrid">
          <Field label="Code"><Input value={v.code} onChange={(e) => set('code', e.target.value.toUpperCase())} maxLength={20} /></Field>
          <Field label="Title"><Input value={v.title} onChange={(e) => set('title', e.target.value)} maxLength={100} /></Field>
          <Field label="Type"><Select value={v.type} onChange={(e) => set('type', e.target.value)} options={TYPES} placeholder={false} /></Field>
          <Field label="Policy"><Select value={v.policyId} onChange={(e) => set('policyId', e.target.value)} options={policies.filter((p) => p.status === 'published').map((p) => ({ v: p.id, l: `${p.name} v${p.version}` }))} placeholder="No policy" /></Field>
          <Field label="Start"><Input type="datetime-local" value={v.startAt} onChange={(e) => set('startAt', e.target.value)} /></Field>
          <Field label="Duration (minutes)"><Input type="number" min={15} max={300} value={v.durationMin} onChange={(e) => set('durationMin', e.target.value)} /></Field>
          <Field label="Late entry (minutes)"><Input type="number" min={0} max={60} value={v.lateEntryMin} onChange={(e) => set('lateEntryMin', e.target.value)} /></Field>
          <Field label="Capacity"><Input type="number" min={0} value={v.capacity} onChange={(e) => set('capacity', e.target.value)} /></Field>
          <Field label="Exam URL" className="span2" help="Secure assessment portal URL"><Input type="url" value={v.examUrl} onChange={(e) => set('examUrl', e.target.value)} placeholder="https://..." /></Field>
          <Field label="Instructions" className="span2"><Textarea rows={3} value={v.instructions} onChange={(e) => set('instructions', e.target.value)} maxLength={3000} /></Field>
          <Field label="Centres" className="span2">
            <div className="checkgrid">{centers.filter((c) => c.status === 'active').map((c) => <Checkbox key={c.id} label={`${c.code} · ${c.capacity} seats`} checked={v.centerIds.includes(c.id)} onChange={() => toggleCenter(c.id)} />)}</div>
          </Field>
        </div>
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------ detail */
export function ExamDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const may = usePerm();
  const navigate = useNavigate();
  // Backend-first: fetch exam detail from the real API.
  const { rows: localExams, loaded } = useColLoaded('exams');
  const [backendExam, setBackendExam] = useState(null);
  const [detailLoaded, setDetailLoaded] = useState(false);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    const fetchDetail = async () => {
      try {
        const res = await Api.getExamination(id);
        const exam = res?.examination || res;
        if (exam && !cancelled) {
          const mapped = {
            id: exam.id,
            tenantId: exam.institution_id,
            code: exam.code,
            title: exam.name || exam.title,
            type: exam.exam_type || exam.type || 'final',
            course: exam.subject || exam.course || '',
            academicYear: exam.academic_year || exam.academicYear || '',
            status: exam.status || 'draft',
            startAt: exam.scheduled_start || exam.startAt || 0,
            durationMin: exam.duration_minutes || exam.durationMin || 60,
            examUrl: exam.exam_url || exam.examUrl || '',
            instructions: exam.instructions || '',
            policyId: exam.policy_id || exam.policyId || null,
            centerIds: exam.center_ids || exam.centerIds || [],
            createdBy: exam.created_by || exam.createdBy || '',
            createdAt: exam.created_at || exam.createdAt || 0,
            updatedAt: exam.updated_at || exam.updatedAt || 0,
            version: exam.version || 1,
            history: exam.history || [],
            attestationLevel: exam.attestation_level || exam.attestationLevel || 'tpm',
            authMode: exam.auth_mode || exam.authMode || 'candidate-login',
            submissionMode: exam.submission_mode || exam.submissionMode || 'either',
            navigation: exam.navigation || 'locked',
            sessionTimeoutMin: exam.session_timeout_min || exam.sessionTimeoutMin || 15,
            reconnectPolicy: exam.reconnect_policy || exam.reconnectPolicy || 'allow-reconnect',
            identityRequired: exam.identity_required ?? exam.identityRequired ?? true,
          };
          setBackendExam(mapped);
          await put('exams', mapped).catch(() => {});
        }
      } catch { /* fall through to local */ }
      if (!cancelled) setDetailLoaded(true);
    };
    fetchDetail();
    return () => { cancelled = true; };
  }, [id]);
  const centers = useCol('centers');
  const policies = useCol('policies');
  const candidates = useCol('candidates');
  const devices = useCol('devices');
  const releases = useCol('releases');

  // Use backend data when available, fall back to local
  const exams = backendExam ? [backendExam, ...localExams.filter(x => x.id !== backendExam.id)] : localExams;
  const isLoaded = detailLoaded || loaded;
  const [tab, setTab] = useState('overview');
  const [edit, setEdit] = useState(false);
  const [pending, setPending] = useState(null);
  const [postpone, setPostpone] = useState(null);
  const { msg, setMsg, run, busy } = useFlash();

  const e = exams.find((x) => x.id === id);
  const { data: checks, loading: readinessLoading, reload: reloadReadiness } = useLoad(async () => (e ? readiness(e) : []), [e?.id, e?.version, e?.status]);
  const { data: preview } = useLoad(async () => (e ? policyPreview(e) : null), [e?.id, e?.policyId]);

  if (!isLoaded) return <Page title="Exam"><Loading /></Page>;
  if (!e) return <Page title="Exam not found"><Empty icon="exam" title="No such exam" action={<Link className="btn" to="/college/exams">Back to exams</Link>} /></Page>;
  const assigned = candidates.filter((c) => c.examId === e.id);
  const centersList = (e.centerIds || []).map((cid) => centers.find((c) => c.id === cid)).filter(Boolean);
  const currentStep = LIFECYCLE.indexOf(e.status);
  const readyCount = (checks || []).filter((c) => c.status === 'PASS').length;
  const conflict = conflicts(exams, e);

  const advance = async (to, reason) => {
    const ok = await run(() => transition(user, e, to, reason), 'Lifecycle updated.');
    if (ok) { setPending(null); reloadReadiness(); }
  };

  return (
    <Page
      title={e.code}
      desc={`${e.title} · ${LIFECYCLE_LABEL[e.status]}`}
      breadcrumb={<div className="crumbs-inline"><Link to="/college/exams">Exams</Link><Icon name="arrow" size={12} /><span>{e.code}</span></div>}
      actions={<>
        {may('exam.manage') && !['live', 'closed'].includes(e.status) && <button className="btn" onClick={() => setEdit(true)}>Edit</button>}
        {may('exam.manage') && ['review', 'approved', 'published'].includes(e.status) && <button className="btn" onClick={() => setPostpone({ startAt: local(e.startAt + 864e5) })}>Postpone</button>}
        {nextSteps(e.status).filter((to) => may(STEP_PERM[to] || 'exam.manage')).map((to) => (
          <button key={to} className={'btn ' + (to === 'cancelled' ? 'danger' : to === 'published' || to === 'live' ? 'primary' : '')} disabled={busy} onClick={() => {
            if (REASON.has(to)) setPending({ to });
            else run(() => transition(user, e, to), 'Lifecycle updated.');
          }}>{STEP_LABEL[to]}</button>
        ))}
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {e.status === 'live' && <Alert tone="success" title="Exam is live">Critical configuration is locked. Sessions started before the deadline can be monitored from Operations.</Alert>}
      {conflict && <Alert tone="warn" title={`Schedule conflict with ${conflict.code}`}>Both exams overlap at a shared centre. Adjust the window before publishing.</Alert>}
      {e.status === 'cancelled' && <Alert tone="danger" title="Exam cancelled">Reason: {e.cancelReason || 'not recorded'}</Alert>}

      <StatGrid cols={4}>
        <Stat label="Status" value={LIFECYCLE_LABEL[e.status]} icon="badge" />
        <Stat label="Target Portal" value={e.examUrl ? 'URL Assigned' : 'No URL'} icon="browser" sub={e.examUrl ? e.examUrl.replace(/^https?:\/\//, '').slice(0, 24) : 'Not assigned'} />
        <Stat label="Centres" value={centersList.length} icon="building" sub={centersList.map((c) => c.code).join(', ')} />
        <Stat label="Seated" value={assigned.length} icon="candidate" sub={`${assigned.filter((c) => c.identity === 'verified').length} verified`} />
      </StatGrid>

      <Card pad>
        <Steps steps={['Draft', 'Review', 'Approved', 'Published', 'Live', 'Closed']} current={Math.max(0, Math.min(5, currentStep - 1))} />
      </Card>

      <Tabs value={tab} onChange={setTab} tabs={[
        { key: 'overview', label: 'Overview' },
        { key: 'readiness', label: 'Readiness', count: checks ? `${readyCount}/${checks.length}` : undefined },
        { key: 'candidates', label: 'Candidates', count: assigned.length },
        { key: 'sessions', label: 'Sessions' },
        { key: 'policy', label: 'Policy' },
        { key: 'history', label: 'History', count: e.history?.length || 0 },
      ]} />

      {tab === 'overview' && <>
        <Card title="Configuration">
          <KeyValue cols={3} items={[
            ['Code', e.code], ['Title', e.title], ['Type', e.type],
            ['Exam URL', e.examUrl || '—'], ['Course', e.course || '—'], ['Academic year', e.academicYear || '—'], ['Version', `v${e.version || 1}`],
            ['Window', `${fmt(e.startAt)} · ${e.durationMin} min`], ['Late entry', `${e.lateEntryMin || 0} min`], ['Time zone', e.timeZone || '—'],
            ['Policy', pol ? `${pol.name} v${pol.version}` : '—'], ['Policy status', pol?.status || '—'], ['Attestation', e.attestationLevel],
            ['Authentication', e.authMode], ['Submission', e.submissionMode], ['Navigation', e.navigation],
            ['Session timeout', `${e.sessionTimeoutMin} min`], ['Reconnect', e.reconnectPolicy], ['Identity check', e.identityRequired ? 'Required' : 'Optional'],
            ['Created by', e.createdBy || '—'], ['Created', fmt(e.createdAt)], ['Updated', fmt(e.updatedAt)],
          ]} />
        </Card>
        {e.instructions && <Card title="Candidate instructions"><p className="prewrap">{e.instructions}</p></Card>}
        <Card title="Quick links">
          <div className="quicklinks">
            <Link to={`/college/exams/${e.id}/candidates`}><Icon name="candidate" size={14} /> Candidates & seating</Link>
            <Link to={`/college/exams/${e.id}/policies`}><Icon name="policy" size={14} /> Exam policy</Link>
            <Link to={`/operator/exams/${e.id}/live`}><Icon name="pulse" size={14} /> Live operations</Link>
            <Link to={`/operator/exams/${e.id}/submissions`}><Icon name="checklist" size={14} /> Submissions</Link>
          </div>
        </Card>
      </>}

      {tab === 'readiness' && <Card title="Publication readiness" desc="Checks run against the live workspace. A FAIL blocks publication." actions={<button className="btn" onClick={reloadReadiness}>Re-run checks</button>}>
        {readinessLoading ? <Loading label="Running readiness checks…" /> : (
          <DataTable rows={checks || []} columns={[
            { label: 'Check', key: 'label' }, { label: 'Status', key: 'status', badge: true }, { label: 'Detail', key: 'detail' },
          ]} empty={<Empty title="No checks" />} />
        )}
      </Card>}

      {tab === 'candidates' && <Card title="Candidates assigned" actions={<Link className="btn" to={`/college/exams/${e.id}/candidates`}>Manage seating</Link>}>
        <DataTable rows={assigned} columns={[
          { label: 'Roll no', key: 'rollNo' }, { label: 'Name', key: 'name' }, { label: 'Email', key: 'email' },
          { label: 'Centre', render: (c) => centers.find((x) => x.id === c.centerId)?.code || '—' },
          { label: 'Seat', key: 'seat' }, { label: 'Identity', key: 'identity', badge: true },
          { label: 'Ready', render: (c) => {
            const checks2 = readinessFor(c, { devices, exams, policies, releases });
            return <Badge value={isReady(checks2) ? 'ready' : 'not ready'} />;
          } },
        ]} empty={<Empty icon="candidate" title="No candidates assigned">Assign candidates from the exam candidates page.</Empty>} />
      </Card>}

      {tab === 'policy' && <Card title="Exam policy" actions={<Link className="btn" to={`/college/exams/${e.id}/policies`}>Configure policy</Link>}>
        {pol ? <KeyValue cols={2} items={[
          ['Policy', `${pol.name} v${pol.version}`], ['Status', pol.status],
          ['Require TPM', pol.config?.requireTpm ? 'Yes' : 'No'], ['Kiosk lockdown', pol.config?.kioskLockdown ? 'Yes' : 'No'],
          ['Allow USB', pol.config?.allowUsb ? 'Yes' : 'No'], ['On violation', pol.config?.onViolation || '—'],
          ['Allowed origins', (pol.config?.origins || []).join(', ') || '—'], ['Signature', pol.status === 'published' ? 'verified on publish' : 'not published'],
        ]} /> : <Empty icon="policy" title="No policy assigned">Choose a published policy or create an exam-specific policy.</Empty>}
        {preview && <pre className="code">{JSON.stringify(preview, null, 2)}</pre>}
      </Card>}

      {tab === 'history' && <Card title="Lifecycle history">
        <Timeline items={[...(e.history || [])].reverse().map((h, i) => ({
          id: `${h.at}-${i}`,
          title: `${LIFECYCLE_LABEL[h.to] || h.to}${h.reason ? ' · ' + h.reason : ''}`,
          meta: `${fmt(h.at)} · ${h.by || 'system'}${h.note ? ' · ' + h.note : ''}`,
          tone: h.to === 'cancelled' ? 'r' : h.to === 'live' ? 'g' : '',
        }))} />
      </Card>}

      {tab === 'sessions' && <ExamSessionsTab examId={e.id} />}

      {pending && <ActionDialog
        title={`${STEP_LABEL[pending.to]} · ${e.code}`}
        desc={pending.to === 'live' ? 'Starting before the window opens needs a reason. Live exams lock critical configuration.' : pending.to === 'cancelled' ? 'Cancelling is permanent and notifies candidates.' : 'This transition is recorded in the audit trail.'}
        confirmLabel={STEP_LABEL[pending.to]}
        danger={pending.to === 'cancelled'}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={(reason) => advance(pending.to, reason)}
      />}

      {postpone && <PostponeModal exam={e} value={postpone.startAt} onChange={(x) => setPostpone({ startAt: x })} onClose={() => setPostpone(null)} onDone={() => { setPostpone(null); reloadReadiness(); }} />}

      {edit && <EditExamModal exam={e} centers={centers} policies={policies} onClose={() => setEdit(false)} onSaved={reloadReadiness} />}
    </Page>
  );
}

function PostponeModal({ exam, value, onChange, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [reason, setReason] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => postponeExam(user, exam, value, reason), 'Exam postponed.');
    if (ok) onDone();
  };
  return (
    <Modal title={`Postpone ${exam.code}`} desc="Candidates are notified through the inbox. The original schedule stays in the audit trail." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="postpone-form" disabled={busy}>{busy ? 'Saving…' : 'Postpone exam'}</button></>}>
      <form id="postpone-form" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="New start" required><Input type="datetime-local" value={value} onChange={(e) => onChange(e.target.value)} required /></Field>
        <Field label="Reason" required help="At least 8 characters, recorded in the audit trail."><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} autoFocus /></Field>
      </form>
    </Modal>
  );
}

function ExamSessionsTab({ examId }) {
  const { data: sessData, loading, reload } = useLoad(async () => {
    try {
      const res = await listExaminationSessions(examId);
      return res?.sessions || [];
    } catch {
      return [];
    }
  }, [examId]);

  if (loading) return <Loading />;
  const sessions = sessData || [];

  return (
    <Card title="Live Exam Sessions" action={<button className="btn small" onClick={reload}>Refresh</button>}>
      {sessions.length === 0 ? (
        <Empty icon="candidate" title="No active or past sessions">
          Sessions will appear here when authorized candidates connect from ExamOS terminals.
        </Empty>
      ) : (
        <DataTable
          rows={sessions}
          cols={[
            { key: 'roll_no', label: 'Roll Number' },
            { key: 'student_name', label: 'Student' },
            { key: 'device_id', label: 'Terminal Device', render: (d) => d || '—' },
            { key: 'status', label: 'Status', render: (s) => (
              <Badge tone={s === 'active' ? 'success' : s === 'interrupted' ? 'warn' : s === 'closed' ? 'muted' : 'info'}>
                {String(s).toUpperCase()}
              </Badge>
            )},
            { key: 'interruption_count', label: 'Interruptions' },
            { key: 'last_heartbeat_at', label: 'Last Heartbeat', render: (t) => t ? fmt(Number(t)) : '—' },
            { key: 'closure_reason', label: 'Closure Reason', render: (r) => r || '—' },
          ]}
        />
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ exam candidates */
export function ExamCandidatesPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const may = usePerm();
  const { rows: exams, loaded } = useColLoaded('exams');
  const candidates = useCol('candidates');
  const centers = useCol('centers');
  const devices = useCol('devices');
  const policies = useCol('policies');
  const releases = useCol('releases');
  const { msg, setMsg, run, busy } = useFlash();
  const [activeTab, setActiveTab] = useState('seating');
  const [centerId, setCenterId] = useState('');
  const [count, setCount] = useState('');
  const [pending, setPending] = useState(null);

  // Module 10: Eligibility state
  const { data: rules, reload: reloadRules } = useLoad(async () => (id ? listEligibilityRules(id) : []), [id]);
  const { data: liveSessions, reload: reloadSessions } = useLoad(async () => (id ? listExaminationSessions(id) : []), [id]);
  const [newRule, setNewRule] = useState({ rule_type: 'min_attendance', rule_value: '75', is_strict: true });

  const e = exams.find((x) => x.id === id);
  const rows = candidates.filter((c) => c.examId === id);
  const examCenters = e ? (e.centerIds || []).map((cid) => centers.find((c) => c.id === cid)).filter(Boolean) : [];

  if (!loaded) return <Page title="Candidates"><Loading /></Page>;
  if (!e) return <Page title="Candidates"><Empty icon="exam" title="Exam not found" /></Page>;

  const assign = async () => {
    const ok = await run(() => assignToExam(user, { tenantId: e.tenantId, examId: e.id, centerId, count }), 'Candidates seated.');
    if (ok) { setCount(''); }
  };

  const handleAddRule = async (e2) => {
    e2.preventDefault();
    await run(async () => {
      await configureEligibilityRule(e.id, newRule);
      reloadRules();
      return 'Eligibility rule configured.';
    });
  };

  const handlePublishRoster = async () => {
    await run(async () => {
      const res = await publishExaminationRoster(e.id);
      return `Roster v${res?.version || 1} published (hash: ${res?.roster_hash?.slice(0, 16) || 'sealed'}...).`;
    });
  };

  return (
    <Page
      title={`${e.code} · Candidates & Eligibility`}
      desc="Seat allocation, eligibility rules (Module 10) and runtime live sessions (Module 11)."
      breadcrumb={<div className="crumbs-inline"><Link to="/college/exams">Exams</Link><Icon name="arrow" size={12} /><Link to={`/college/exams/${e.id}`}>{e.code}</Link><Icon name="arrow" size={12} /><span>Candidates</span></div>}
      actions={<>
        <button className="btn" disabled={busy} onClick={() => { reloadRules(); reloadSessions(); }}>Refresh</button>
        <button className="btn primary" disabled={busy || !may('exam.manage')} onClick={handlePublishRoster}>Publish official roster</button>
        <Link className="btn" to={`/college/exams/${e.id}`}>Back to exam</Link>
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Seated" value={rows.length} icon="candidate" />
        <Stat label="Identity verified" value={rows.filter((c) => c.identity === 'verified').length} icon="check" tone="green" />
        <Stat label="Eligibility rules" value={(rules?.rules || rules || []).length} icon="policy" tone="blue" />
        <Stat label="Live sessions" value={(liveSessions?.sessions || liveSessions || []).length} icon="pulse" tone="violet" />
      </StatGrid>

      <Tabs
        value={activeTab}
        onChange={setActiveTab}
        tabs={[
          { key: 'seating', label: 'Seating plan & readiness', count: rows.length },
          { key: 'eligibility', label: 'Module 10 Eligibility rules', count: (rules?.rules || rules || []).length },
          { key: 'sessions', label: 'Module 11 Live exam sessions', count: (liveSessions?.sessions || liveSessions || []).length },
        ]}
      />

      {activeTab === 'seating' && (
        <div className="stack gap">
          {may('candidate.manage') && (
            <Card title="Assign candidates" desc="Seats are allocated automatically from free centre capacity. Only unassigned candidates are seated.">
              <div className="row wrap gap">
                <Select aria-label="Centre" value={centerId} onChange={(e2) => setCenterId(e2.target.value)} options={examCenters.map((c) => ({ v: c.id, l: `${c.code} · ${c.capacity} seats` }))} placeholder="Choose a centre" />
                <Input aria-label="Count" type="number" min={1} value={count} onChange={(e2) => setCount(e2.target.value)} placeholder="How many (blank = all)" />
                <button className="btn primary" disabled={busy || !centerId} onClick={assign}>Assign</button>
                <span className="muted sm">{candidates.filter((c) => !c.examId).length} unassigned candidate(s) available</span>
              </div>
            </Card>
          )}

          <Card title="Seating plan">
            <DataTable
              rows={rows}
              search={(c) => `${c.rollNo} ${c.name} ${c.email} ${c.seat || ''}`}
              filters={[
                { key: 'centerId', label: 'All centres', options: examCenters.map((c) => ({ v: c.id, l: c.code })) },
                { key: 'identity', label: 'Any identity', options: [{ v: 'verified', l: 'verified' }, { v: 'pending', l: 'pending' }, { v: 'rejected', l: 'rejected' }, { v: 'exempt', l: 'exempt' }] },
              ]}
              columns={[
                { label: 'Roll no', key: 'rollNo' }, { label: 'Name', key: 'name' }, { label: 'Email', key: 'email' },
                { label: 'Centre', render: (c) => centers.find((x) => x.id === c.centerId)?.code || '—' },
                { label: 'Seat', key: 'seat' }, { label: 'Identity', key: 'identity', badge: true },
                { label: 'Readiness', render: (c) => {
                  const checks = readinessFor(c, { devices, exams, policies, releases });
                  const fail = checks.filter((x) => x.status === 'FAIL');
                  return <Badge value={isReady(checks) ? 'ready' : fail.length ? `${fail.length} blocker(s)` : 'not run'} />;
                } },
              ]}
              actions={(c) => [
                { label: 'Verify ID', disabled: !may('candidate.verify') || c.identity === 'verified', onClick: () => setPending({ kind: 'identity', c, outcome: 'verified' }) },
                { label: 'Reject ID', danger: true, disabled: !may('candidate.verify') || c.identity === 'rejected', onClick: () => setPending({ kind: 'identity', c, outcome: 'rejected' }) },
                { label: 'Unassign', danger: true, disabled: !may('candidate.manage'), onClick: () => setPending({ kind: 'unassign', c }) },
              ]}
              empty={<Empty icon="candidate" title="No candidates seated">Assign candidates to this exam to build the seating plan.</Empty>}
            />
          </Card>
        </div>
      )}

      {activeTab === 'eligibility' && (
        <div className="stack gap">
          <Card title="Configure eligibility rule (Module 10)" desc="Automatic gates for academic standing, prerequisites, and attendance.">
            <form className="row wrap gap" onSubmit={handleAddRule}>
              <Select
                value={newRule.rule_type}
                onChange={(e2) => setNewRule((s) => ({ ...s, rule_type: e2.target.value }))}
                options={[
                  { v: 'min_attendance', l: 'Minimum attendance percentage' },
                  { v: 'prerequisite_course', l: 'Completed prerequisite course' },
                  { v: 'allowed_semester', l: 'Enrolled semester match' },
                  { v: 'max_backlogs', l: 'Maximum active backlogs' },
                ]}
              />
              <Input
                placeholder="Rule threshold (e.g. 75, CS101, 5)"
                value={newRule.rule_value}
                onChange={(e2) => setNewRule((s) => ({ ...s, rule_value: e2.target.value }))}
              />
              <button className="btn primary" disabled={busy || !newRule.rule_value}>Add rule</button>
            </form>
          </Card>

          <Card title="Configured rules">
            <DataTable
              rows={rules?.rules || rules || []}
              columns={[
                { label: 'Rule type', key: 'rule_type', render: (r) => <Badge value={r.rule_type} tone="blue" /> },
                { label: 'Threshold / Value', key: 'rule_value' },
                { label: 'Enforcement', render: (r) => (r.is_strict ? <Badge value="STRICT BLOCK" tone="red" /> : <Badge value="WARNING" tone="amber" />) },
                { label: 'Created at', render: (r) => (r.created_at ? fmt(Number(r.created_at)) : 'Active') },
              ]}
              empty={<Empty title="No rules configured" desc="Add an eligibility rule above to automatically evaluate candidate eligibility." />}
            />
          </Card>
        </div>
      )}

      {activeTab === 'sessions' && (
        <div className="stack gap">
          <Card title="Active exam sessions (Module 11)" desc="Runtime session controls: cryptographic URL token launch, liveness heartbeats, and interruption recovery.">
            <DataTable
              rows={liveSessions?.sessions || liveSessions || []}
              columns={[
                { label: 'Session ID', key: 'id' },
                { label: 'Student ID', key: 'student_id' },
                { label: 'Status', render: (s) => <Badge value={s.status} tone={s.status === 'active' ? 'green' : s.status === 'interrupted' ? 'red' : 'blue'} /> },
                { label: 'Heartbeats', key: 'heartbeat_count' },
                { label: 'Interruptions', key: 'interrupt_count' },
                { label: 'IP Address', key: 'ip_address' },
                { label: 'Started', render: (s) => (s.start_time ? fmt(Number(s.start_time)) : '—') },
              ]}
              actions={(s) => [
                { label: 'Send heartbeat', onClick: () => run(async () => { await heartbeatExamSession(s.id); reloadSessions(); return 'Heartbeat acknowledged.'; }) },
                { label: 'Simulate interrupt', danger: true, disabled: s.status !== 'active', onClick: () => run(async () => { await interruptExamSession(s.id, 'Network packet loss simulated'); reloadSessions(); return 'Session interrupted.'; }) },
                { label: 'Resume', disabled: s.status !== 'interrupted', onClick: () => run(async () => { await resumeExamSession(s.id); reloadSessions(); return 'Session resumed.'; }) },
                { label: 'Close session', danger: true, disabled: s.status === 'closed', onClick: () => run(async () => { await closeAuthorizedExamSession(s.id); reloadSessions(); return 'Session closed.'; }) },
              ]}
              empty={<Empty title="No sessions recorded yet" desc="Candidates launch sessions from the secure ExamOS bootable kiosk terminal." />}
            />
          </Card>
        </div>
      )}

      {pending && <ActionDialog
        title={pending.kind === 'unassign' ? `Unassign ${pending.c.rollNo}` : `${pending.outcome === 'verified' ? 'Verify' : 'Reject'} ${pending.c.rollNo}`}
        desc={pending.kind === 'unassign' ? 'The candidate returns to the unassigned pool. An in-progress session blocks this action.' : 'The decision and note are written to the audit trail.'}
        danger={pending.kind === 'unassign' || pending.outcome === 'rejected'}
        confirmLabel={pending.kind === 'unassign' ? 'Unassign' : pending.outcome === 'verified' ? 'Verify identity' : 'Reject identity'}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason) => {
          await run(() => pending.kind === 'unassign' ? unassign(user, pending.c, reason) : setIdentity(user, pending.c, pending.outcome, reason));
          setPending(null);
        }}
      />}
    </Page>
  );
}

/* ------------------------------------------------------------------ exam policy */
export function ExamPoliciesPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const may = usePerm();
  const { rows: exams, loaded } = useColLoaded('exams');
  const policies = useCol('policies');
  const { msg, setMsg, run, busy } = useFlash();
  const e = exams.find((x) => x.id === id);
  const pol = policies.find((p) => p.id === e?.policyId);
  const [v, setV] = useState({ requireTpm: true, kioskLockdown: true, allowUsb: false, onViolation: 'Warn candidate & log', origins: 'https://exam.examos.example' });
  const [publish, setPublish] = useState(false);
  const [reason, setReason] = useState('');
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));

  useEffect(() => {
    if (pol?.config) setV({
      requireTpm: !!pol.config.requireTpm, kioskLockdown: !!pol.config.kioskLockdown,
      allowUsb: !!pol.config.allowUsb, onViolation: pol.config.onViolation || 'Warn candidate & log',
      origins: (pol.config.origins || []).join(', '),
    });
  }, [pol?.id]);

  if (!loaded) return <Page title="Exam policy"><Loading /></Page>;
  if (!e) return <Page title="Exam policy"><Empty icon="exam" title="Exam not found" /></Page>;

  const submit = async (ev) => {
    ev.preventDefault();
    const ok = await run(() => configureExamPolicy(user, e, v, publish, reason), publish ? 'Policy published and attached to the exam.' : 'Policy draft saved.');
    if (ok) setReason('');
  };

  return (
    <Page
      title={`${e.code} · Policy`}
      desc="Exam-specific network, kiosk and attestation controls. Publishing creates a signed policy version."
      breadcrumb={<div className="crumbs-inline"><Link to="/college/exams">Exams</Link><Icon name="arrow" size={12} /><Link to={`/college/exams/${e.id}`}>{e.code}</Link><Icon name="arrow" size={12} /><span>Policy</span></div>}
      actions={<Link className="btn" to={`/college/exams/${e.id}`}>Back to exam</Link>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <Card title="Current policy">
        {pol ? <KeyValue cols={2} items={[
          ['Name', pol.name], ['Version', `v${pol.version}`], ['Status', <Badge value={pol.status} />],
          ['Require TPM', pol.config?.requireTpm ? 'Yes' : 'No'], ['Kiosk lockdown', pol.config?.kioskLockdown ? 'Yes' : 'No'],
          ['Allow USB', pol.config?.allowUsb ? 'Yes' : 'No'], ['On violation', pol.config?.onViolation || '—'],
          ['Allowed origins', (pol.config?.origins || []).join(', ') || '—'],
        ]} /> : <Empty icon="policy" title="No policy assigned">Create and publish an exam-specific policy below, or select one while editing the exam.</Empty>}
      </Card>

      {may('exam.policy') ? <Card title="Configure exam policy" desc="A new policy version is created for this exam. Publishing signs it with the platform key.">
        <form className="stack" onSubmit={submit}>
          <div className="formgrid">
            <Field label="On violation"><Select value={v.onViolation} onChange={(e2) => set('onViolation', e2.target.value)} options={['Warn candidate & log', 'Lock the session', 'Terminate the session', 'Notify invigilator']} placeholder={false} /></Field>
            <Field label="Allowed origins" help="Comma-separated https origins"><Input value={v.origins} onChange={(e2) => set('origins', e2.target.value)} /></Field>
          </div>
          <div className="checkrow">
            <Checkbox label="Require TPM 2.0 attestation" checked={v.requireTpm} onChange={(e2) => set('requireTpm', e2.target.checked)} />
            <Checkbox label="Enforce kiosk lockdown" checked={v.kioskLockdown} onChange={(e2) => set('kioskLockdown', e2.target.checked)} />
            <Checkbox label="Allow USB storage" checked={v.allowUsb} onChange={(e2) => set('allowUsb', e2.target.checked)} />
            <Checkbox label="Publish immediately" checked={publish} onChange={(e2) => setPublish(e2.target.checked)} />
          </div>
          {publish && <Field label="Publication reason"><Input value={reason} onChange={(e2) => setReason(e2.target.value)} maxLength={200} placeholder="Why this policy is being published" /></Field>}
          <div className="form-actions"><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : publish ? 'Publish policy' : 'Save draft'}</button></div>
        </form>
      </Card> : <Alert tone="warn">Your role cannot configure exam policies.</Alert>}
    </Page>
  );
}

