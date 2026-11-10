import { useMemo, useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { usePerm, useLoad } from '../../core/ui/hooks';
import * as Api from '../../core/api/services';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, Modal, Field, Input, Select, Textarea, KeyValue, Loading, CopyButton, Tabs,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  addCandidate, previewImport, commitImport, assignToExam, unassign, setIdentity,
  correctName, readinessFor, isReady, CSV_TEMPLATE, notifyCandidate,
  suspendStudent, reactivateStudent, progressSemester, getStudent360,
} from './service';
import { listCenters } from '../centers/service';

function ImportPanel({ tenantId, onDone }) {
  const { user } = useAuth();
  const may = usePerm();
  const [text, setText] = useState('');
  const [prev, setPrev] = useState(null);
  const { msg, setMsg, run, busy } = useFlash();
  const readFile = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    if (f.size > 1e6) return setMsg({ ok: false, text: 'File is larger than 1 MB.' });
    const r = new FileReader();
    r.onload = () => { setText(String(r.result)); setPrev(null); };
    r.readAsText(f);
  };
  return (
    <Card title="Bulk import" desc="CSV header: rollNo,name,email,course,batch,semester,section. Rows are validated by the backend before confirmation.">
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <div className="row wrap gap">
        <label className="btn filebtn">Choose CSV<input type="file" accept=".csv,text/csv" onChange={readFile} hidden /></label>
        <button className="mini" onClick={() => setText(CSV_TEMPLATE)}>Use template</button>
        <CopyButton value={CSV_TEMPLATE} label="Copy template" />
        <span className="grow" />
        <button className="btn" disabled={!text || busy} onClick={() => run(async () => {
          setPrev(await previewImport(tenantId, text));
          return 'Preview ready.';
        })}>Preview</button>
        {prev && <button className="btn primary" disabled={!prev.valid.length || !prev.jobId || busy || !may('candidate.manage')} onClick={() => run(async () => {
          const m = await commitImport(user, tenantId, prev);
          setPrev(null); setText(''); onDone?.();
          return m;
        })}>Import {prev.valid.length} valid</button>}
      </div>
      <Textarea rows={4} className="mono" placeholder="…or paste CSV here" value={text} onChange={(e) => { setText(e.target.value); setPrev(null); }} />
      {prev && <div className="stack">
        <div className="row gap"><Badge value={`${prev.valid.length} valid`} /><Badge value={`${prev.invalid.length} rejected`} /></div>
        {prev.invalid.length > 0 && <div className="scroll"><table className="dense"><thead><tr><th>Line</th><th>Roll no</th><th>Name</th><th>Problems</th></tr></thead><tbody>
          {prev.invalid.slice(0, 20).map((r) => <tr key={r.line}><td>{r.line}</td><td className="mono">{r.rollNo}</td><td>{r.name}</td><td className="redt">{r.errs.join('; ')}</td></tr>)}
        </tbody></table></div>}
      </div>}
    </Card>
  );
}

function AssignPanel({ tenantId, exams, candidates, rosterLoading, rosterError, onDone }) {
  const { user } = useAuth();
  const may = usePerm();
  const [centers, setCenters] = useState([]);
  const [centersLoading, setCentersLoading] = useState(true);
  const [centersError, setCentersError] = useState('');
  const [examId, setExamId] = useState('');
  const [centerId, setCenterId] = useState('');
  const [count, setCount] = useState('');
  const { msg, setMsg, run, busy } = useFlash();
  const exam = exams.find((e) => e.id === examId);
  const free = candidates.filter((c) => !c.examId).length;
  useEffect(() => {
    let active = true;
    setCentersLoading(true);
    setCentersError('');
    listCenters(tenantId).then((rows) => {
      if (active) setCenters(rows.filter((center) => center.status === 'active'));
    }).catch((error) => {
      if (active) {
        setCenters([]);
        setCentersError(error.message || 'Unable to load centers from the backend.');
      }
    }).finally(() => {
      if (active) setCentersLoading(false);
    });
    return () => { active = false; };
  }, [tenantId]);
  const examCenterIds = Array.isArray(exam?.centerIds) ? exam.centerIds : [];
  const availableCenters = centers.filter((center) => examCenterIds.includes(center.id));
  const noCenterMapping = !!examId && examCenterIds.length === 0;
  return (
    <Card title="Assign & seat" desc="Seats are allocated automatically from free centre capacity. Only unassigned candidates are seated.">
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {centersError && <Alert tone="danger">{centersError}</Alert>}
      {noCenterMapping && (
        <Alert tone="warn" title="No centres mapped to this exam">
          Edit the exam and select at least one active centre before assigning candidates.
        </Alert>
      )}
      <div className="formgrid">
        <Field label="Exam"><Select value={examId} onChange={(e) => { setExamId(e.target.value); setCenterId(''); }} options={exams.map((e) => ({ v: e.id, l: `${e.code} · ${e.status}` }))} placeholder="Choose an exam" /></Field>
        <Field label="Centre"><Select value={centerId} onChange={(e) => setCenterId(e.target.value)} options={availableCenters.map((c) => ({ v: c.id, l: `${c.code} · ${c.capacity} seats` }))} placeholder={centersLoading ? 'Loading centres…' : 'Choose a centre'} /></Field>
        <Field label="How many" help={`${free} unassigned candidate(s) available`}><Input type="number" min={1} value={count} onChange={(e) => setCount(e.target.value)} placeholder="Blank = all" /></Field>
        <div className="field"><span className="field-label">&nbsp;</span><button className="btn primary" disabled={!examId || !centerId || busy || rosterLoading || !!rosterError || !may('candidate.manage')} onClick={() => run(async () => {
          try {
            const m = await assignToExam(user, { tenantId, examId, centerId, count });
            onDone?.(); return m;
          } catch (error) {
            onDone?.();
            throw error;
          }
        })}>Assign candidates</button></div>
      </div>
    </Card>
  );
}

function AddCandidate({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({
    rollNo: '', name: '', email: '', personalEmail: '', phoneNumber: '',
    course: '', batch: '', semester: '', section: '',
    accommodations: '', notes: ''
  });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => addCandidate(user, { tenantId, ...v }), 'Candidate profile registered.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Register candidate (Module 5)" desc="Create canonical student profile with institutional enrollment." onClose={onClose} wide footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="cand-form" disabled={busy}>{busy ? 'Saving…' : 'Add student'}</button></>}>
      <form id="cand-form" className="formgrid" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="Roll number" required><Input value={v.rollNo} onChange={(e) => set('rollNo', e.target.value.toUpperCase())} maxLength={20} autoFocus placeholder="e.g. VU-2026-CSE-001" /></Field>
        <Field label="Full name" required><Input value={v.name} onChange={(e) => set('name', e.target.value)} maxLength={80} placeholder="e.g. Aarav Sharma" /></Field>
        <Field label="Institutional email" required><Input type="email" value={v.email} onChange={(e) => set('email', e.target.value)} maxLength={120} placeholder="aarav@vignan.ac.in" /></Field>
        <Field label="Personal email"><Input type="email" value={v.personalEmail} onChange={(e) => set('personalEmail', e.target.value)} maxLength={120} placeholder="aarav.personal@gmail.com" /></Field>
        <Field label="Phone number"><Input value={v.phoneNumber} onChange={(e) => set('phoneNumber', e.target.value)} maxLength={20} placeholder="+919876543210" /></Field>
        <Field label="Course / Program" required><Input value={v.course} onChange={(e) => set('course', e.target.value)} maxLength={128} /></Field>
        <Field label="Batch" required><Input value={v.batch} onChange={(e) => set('batch', e.target.value)} maxLength={64} /></Field>
        <Field label="Semester" required><Input type="number" min={1} max={12} value={v.semester} onChange={(e) => set('semester', e.target.value)} /></Field>
        <Field label="Section" required><Input value={v.section} onChange={(e) => set('section', e.target.value)} maxLength={32} /></Field>
        <Field label="Accommodations"><Input value={v.accommodations} onChange={(e) => set('accommodations', e.target.value)} maxLength={250} placeholder="e.g. Extra 15 mins for visual fatigue" /></Field>
        <div className="full-width"><Field label="Administrative notes"><Textarea rows={2} value={v.notes} onChange={(e) => set('notes', e.target.value)} placeholder="e.g. Dean honors list, transfer credits verified" /></Field></div>
      </form>
    </Modal>
  );
}

function CandidateDetail({ c, exams, centers, devices, policies, releases, onClose }) {
  const [tab, setTab] = useState('overview');
  const checks = readinessFor(c, { devices, exams, policies, releases });
  const exam = exams.find((e) => e.id === c.examId);
  const center = centers.find((x) => x.id === c.centerId);
  const { data: s360, loading, error: detailError } = useLoad(() => getStudent360(c), [c?.id]);

  const p = s360?.profile;
  const detailErrors = Object.entries(s360?.errors || {}).map(([section, message]) => `${section}: ${message}`);

  return (
    <Modal title={`${c.rollNo} · ${c.name}`} desc="Student 360: canonical profile, multi-semester enrollments, eligibility, device trust & sessions." onClose={onClose} wide footer={<button className="btn" onClick={onClose}>Close</button>}>
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'overview', label: 'Overview' },
          { key: 'enrollments', label: 'Enrollments', count: s360?.enrollments?.length || 0 },
          { key: 'eligibility', label: 'Module 10 Eligibility', count: s360?.eligibility?.length || 0 },
          { key: 'devices', label: 'Module 13 Devices', count: s360?.devices?.length || 0 },
          { key: 'sessions', label: 'Module 11 Sessions', count: s360?.sessions?.length || 0 },
          { key: 'history', label: 'Audit Trail', count: s360?.history?.length || 0 },
        ]}
      />
      {detailError && <Alert tone="danger" title="Student details unavailable">{detailError.message || String(detailError)}</Alert>}
      {detailErrors.length > 0 && <Alert tone="danger" title="Some student details could not be loaded">{detailErrors.join(' ')}</Alert>}

      {tab === 'overview' && (
        <div className="stack gap">
          <KeyValue cols={3} items={[
            ['Roll number', p?.roll_no || '—'],
            ['Full name', p?.name || '—'],
            ['Display name', p?.display_name || '—'],
            ['Institutional email', p?.email || '—'],
            ['Personal email', p?.personal_email || '—'],
            ['Phone number', p?.phone_number || '—'],
            ['Program / Course', p?.course || '—'],
            ['Batch', p?.batch || '—'],
            ['Current semester', p?.semester != null ? `Sem ${p.semester} (${p.section || '—'})` : '—'],
            ['Academic status', p?.academic_status ? <Badge key="stat" value={p.academic_status} tone={p.academic_status === 'suspended' ? 'red' : 'green'} /> : '—'],
            ['Administrative hold', p ? (p.administrative_hold ? <Badge key="hold" value="ON HOLD" tone="red" /> : <Badge key="nohold" value="CLEAR" tone="green" />) : '—'],
            ['Verification status', p?.verification_status ? <Badge key="ver" value={p.verification_status} tone={p.verification_status === 'VERIFIED' ? 'green' : 'amber'} /> : '—'],
            ['Accommodations', p?.accommodations || '—'],
            ['Assigned exam', exam ? `${exam.code} · ${exam.title}` : '—'],
            ['Assigned seat', c.seat ? `${center?.code || 'Centre'} · Seat ${c.seat}` : '—'],
          ]} />

          <h4 className="mt">Readiness check</h4>
          <DataTable rows={checks} columns={[
            { label: 'Check', key: 'label' },
            { label: 'Status', key: 'status', badge: true },
            { label: 'Detail', key: 'detail' },
          ]} />
          <Alert tone={isReady(checks) ? 'success' : 'warn'} title={isReady(checks) ? 'Ready to sit' : 'Not ready'}>
            {isReady(checks) ? 'All pre-exam gates passed.' : 'Resolve blockers before candidate can launch.'}
          </Alert>
        </div>
      )}

      {tab === 'enrollments' && (
        <div className="stack gap">
          <Alert tone="info" title="Multi-semester academic progression (Module 5)">
            Past semesters are preserved permanently as completed records; the active semester is marked current.
          </Alert>
          {loading ? <Loading /> : (
            <DataTable
              rows={s360?.enrollments || []}
              columns={[
                { label: 'Academic year', key: 'academic_year' },
                { label: 'Term', key: 'term' },
                { label: 'Semester', render: (r) => `Semester ${r.semester} (${r.section || 'A'})` },
                { label: 'Program', key: 'program_id' },
                { label: 'Status', render: (r) => <Badge value={r.status} tone={r.status === 'current' ? 'green' : 'blue'} /> },
                { label: 'Start date', render: (r) => (r.start_date ? fmt(Number(r.start_date)) : '—') },
                { label: 'End date', render: (r) => (r.end_date ? fmt(Number(r.end_date)) : 'Active') },
              ]}
              empty={<Empty title="No historical enrollments found" desc="Enrollment records will appear as the student progresses." />}
            />
          )}
        </div>
      )}

      {tab === 'eligibility' && (
        <div className="stack gap">
          <Alert tone="info" title="Examination eligibility & rules (Module 10)">
            Live eligibility evaluations calculated from attendance, prerequisites, and administrative holds.
          </Alert>
          {loading ? <Loading /> : (
            <DataTable
              rows={s360?.eligibility || []}
              columns={[
                { label: 'Examination ID', key: 'examination_id' },
                { label: 'Registration status', render: (r) => <Badge value={r.registration_status} /> },
                { label: 'Eligibility', render: (r) => <Badge value={r.eligibility_status} tone={r.eligibility_status === 'eligible' ? 'green' : 'red'} /> },
                { label: 'Approval decision', render: (r) => <Badge value={r.approval_decision} /> },
                { label: 'Registered at', render: (r) => (r.registered_at ? fmt(Number(r.registered_at)) : '—') },
              ]}
              empty={<Empty title="No exam registrations" desc="Candidate has not yet registered for an upcoming exam roster." />}
            />
          )}
        </div>
      )}

      {tab === 'devices' && (
        <div className="stack gap">
          <Alert tone="info" title="Authorized ExamOS hardware (Module 13)">
            Device assignment is recorded here. Exam launch requires server-verified TPM evidence; legacy console attestation claims are not trusted.
          </Alert>
          {loading ? <Loading /> : (
            <DataTable
              rows={s360?.devices || []}
              columns={[
                { label: 'Device ID', key: 'device_id' },
                { label: 'Hostname', key: 'hostname' },
                { label: 'Device name', key: 'device_name' },
                { label: 'Trust status', render: (r) => {
                  const verified = (r.backendTrustOutcome || r.backend_trust_outcome) === 'ALLOW';
                  return <Badge value={verified ? 'Server verified' : 'Unverified'} tone={verified ? 'green' : 'amber'} />;
                } },
                { label: 'Assignment', render: (r) => <Badge value={r.assignment_status || 'active'} /> },
              ]}
              empty={<Empty title="No hardware devices assigned" desc="Devices will be allocated during seating or attestation." />}
            />
          )}
        </div>
      )}

      {tab === 'sessions' && (
        <div className="stack gap">
          <Alert tone="info" title="Runtime exam sessions (Module 11)">
            Audit events, heartbeats, and network interruptions during live exam delivery.
          </Alert>
          {loading ? <Loading /> : (
            <DataTable
              rows={s360?.sessions || []}
              columns={[
                { label: 'Session ID', key: 'id' },
                { label: 'Exam ID', key: 'examination_id' },
                { label: 'Status', render: (r) => <Badge value={r.status} tone={r.status === 'active' ? 'green' : 'blue'} /> },
                { label: 'Heartbeats', key: 'heartbeat_count' },
                { label: 'Interruptions', key: 'interrupt_count' },
                { label: 'IP address', key: 'ip_address' },
                { label: 'Started at', render: (r) => (r.start_time ? fmt(Number(r.start_time)) : '—') },
              ]}
              empty={<Empty title="No active or past sessions" desc="Exam delivery runtime sessions will be tracked here in real-time." />}
            />
          )}
        </div>
      )}

      {tab === 'history' && (
        <div className="stack gap">
          <Alert tone="info" title="Immutable student lifecycle audit log">
            Durable PostgreSQL audit events recorded across all institutional operations.
          </Alert>
          {loading ? <Loading /> : (
            <DataTable
              rows={s360?.history || []}
              columns={[
                { label: 'Action', render: (r) => <Badge value={r.action} tone="blue" /> },
                { label: 'Actor', key: 'actor_id' },
                { label: 'Details', key: 'details' },
                { label: 'Timestamp', render: (r) => (r.occurred_at ? fmt(Number(r.occurred_at)) : '—') },
              ]}
              empty={<Empty title="No audit entries" desc="Actions on this candidate profile will be logged here." />}
            />
          )}
        </div>
      )}
    </Modal>
  );
}

export default function CandidatesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const {
    data: backendExams,
    loading: examsLoading,
    error: examsError,
  } = useLoad(async () => {
    const response = await Api.listExaminations();
    const rows = response?.examinations || response;
    if (!Array.isArray(rows)) throw new Error('The examination-list endpoint returned an invalid response.');
    return rows
      .filter((exam) => exam.institution_id === tenantId)
      .map((exam) => {
        let config = exam.exam_config || exam.exam_config_json || {};
        if (typeof config === 'string') {
          try { config = JSON.parse(config); } catch { config = {}; }
        }
        return {
          ...exam,
          id: exam.exam_id || exam.id,
          tenantId: exam.institution_id,
          code: exam.code,
          title: exam.name || exam.title,
          status: exam.status,
          centerIds: Array.isArray(exam.center_ids) ? exam.center_ids : Array.isArray(config.centerIds) ? config.centerIds : [],
          policyId: exam.policy_id || config.policyId || null,
        };
      });
  }, [tenantId]);
  const exams = backendExams || [];
  const [backendCandidates, setBackendCandidates] = useState(null);
  const [loadingBackend, setLoadingBackend] = useState(false);
  const [fetchError, setFetchError] = useState('');

  const fetchCandidates = useCallback(async () => {
    if (!backendExams) return;
    try {
      setLoadingBackend(true);
      setFetchError('');
      const res = await Api.listStudents();
      if (!Array.isArray(res?.students)) throw new Error('The student-directory endpoint returned an invalid response.');
      const list = res.students.filter((student) => student.institution_id === tenantId);
      const assignments = (await Promise.all(exams.map((exam) => Api.listExaminationStudents(exam.id))))
        .flat();
      const assignmentByStudent = new Map(assignments.map((assignment) => [assignment.student_id, assignment]));
      const mapped = list.map((s) => {
        const assignment = assignmentByStudent.get(s.id);
        return {
          id: s.id,
          tenantId: s.institution_id,
          rollNo: s.roll_no,
          name: s.name,
          displayName: s.display_name || s.name,
          email: s.email,
          course: s.course || '',
          batch: s.batch || '',
          semester: s.semester ?? null,
          section: s.section || '',
          academic_status: s.academic_status || 'active',
          attendance_pct: s.attendance_pct ?? 100,
          administrative_hold: !!s.administrative_hold,
          verification_status: s.verification_status || 'UNVERIFIED',
          identity: (s.verification_status || '').toLowerCase() === 'verified'
            ? 'verified'
            : (s.verification_status || '').toLowerCase() === 'rejected'
              ? 'rejected'
              : (s.verification_status || '').toLowerCase() === 'exempt'
                ? 'exempt'
                : 'pending',
          examId: assignment?.exam_id || null,
          centerId: assignment?.center_id || null,
          seat: assignment?.seat_no || null,
          personalEmail: s.personal_email || '',
          phoneNumber: s.phone_number || '',
          accommodations: s.accommodations || '',
          notes: s.notes || '',
          createdAt: s.created_at || null,
        };
      });
      setBackendCandidates(mapped);
    } catch (error) {
      setBackendCandidates([]);
      setFetchError(error.message || 'Unable to load candidates from the backend.');
    } finally {
      setLoadingBackend(false);
    }
  }, [backendExams, exams, tenantId]);

  useEffect(() => {
    if (backendExams && !examsLoading && !examsError) fetchCandidates();
  }, [backendExams, examsError, examsLoading, fetchCandidates]);

  const candidates = backendCandidates || [];
  const centers = useCol('centers');
  const devices = useCol('devices');
  const policies = useCol('policies');
  const releases = useCol('releases');
  const { msg, setMsg, run, busy } = useFlash();
  const [add, setAdd] = useState(false);
  const [detail, setDetail] = useState(null);
  const [pending, setPending] = useState(null);

  const code = (arr, id) => arr.find((x) => x.id === id)?.code;
  const stats = useMemo(() => ({
    total: candidates.length,
    assigned: candidates.filter((c) => c.examId).length,
    verified: candidates.filter((c) => c.identity === 'verified').length,
    ready: candidates.filter((c) => c.examId && isReady(readinessFor(c, { devices, exams, policies, releases }))).length,
  }), [candidates, devices, exams, policies, releases]);

  return (
    <Page
      title="Candidates"
      desc="Enrolment, seat allocation, identity verification and readiness for every candidate."
      actions={<>
        <button className="btn" disabled={busy || loadingBackend || examsLoading || !!examsError} onClick={fetchCandidates}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
        <button className="btn" disabled={busy || !may('candidate.verify')} onClick={() => run(async () => {
          const target = candidates.filter((c) => c.examId && c.identity === 'pending');
          if (!target.length) throw new Error('No candidates are waiting for identity verification.');
          let done = 0;
          for (const c of target.slice(0, 50)) { await setIdentity(user, c, 'verified', 'Bulk verification from candidate list'); done += 1; }
          await fetchCandidates();
          return `${done} candidate(s) verified.`;
        })}>Verify pending</button>
        <button className="btn primary" disabled={!may('candidate.manage')} onClick={() => setAdd(true)}><Icon name="plus" size={15} /> Add candidate</button>
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {examsError && <Alert tone="danger" title="Live examination list unavailable">{examsError.message || 'Unable to load examinations from the backend.'}</Alert>}
      {examsLoading && <Loading />}
      {fetchError && <Alert tone="danger" title="Live candidate roster unavailable">{fetchError}</Alert>}
      {loadingBackend && <Loading />}
      <StatGrid cols={4}>
        <Stat label="Candidates" value={stats.total} icon="candidate" />
        <Stat label="Assigned" value={stats.assigned} icon="exam" sub={`${stats.total - stats.assigned} unassigned`} />
        <Stat label="Identity verified" value={stats.verified} icon="check" tone="green" />
        <Stat label="Ready to sit" value={stats.ready} icon="device" tone="blue" />
      </StatGrid>

      <div className="two">
        <ImportPanel tenantId={tenantId} onDone={fetchCandidates} />
        <AssignPanel tenantId={tenantId} exams={exams.filter((exam) => ['draft', 'configured', 'pending_approval', 'approved'].includes(exam.status))} candidates={candidates} rosterLoading={loadingBackend || examsLoading} rosterError={fetchError || examsError?.message} onDone={fetchCandidates} />
      </div>

      <Card title="Candidate register">
        <DataTable
          rows={candidates}
          search={(c) => `${c.rollNo} ${c.name} ${c.email} ${c.seat || ''} ${code(exams, c.examId)}`}
          filters={[
            { key: 'identity', label: 'Any identity', options: [{ v: 'verified', l: 'verified' }, { v: 'pending', l: 'pending' }, { v: 'rejected', l: 'rejected' }, { v: 'exempt', l: 'exempt' }] },
            { key: 'examId', label: 'Any exam', options: exams.map((e) => ({ v: e.id, l: e.code })) },
            { key: 'centerId', label: 'Any centre', options: centers.map((c) => ({ v: c.id, l: c.code })) },
          ]}
          columns={[
            { label: 'Roll no', key: 'rollNo' },
            { label: 'Name', render: (c) => <><b>{c.name}</b><br /><small className="muted">{c.email}</small></> },
            { label: 'Exam', render: (c) => code(exams, c.examId) || <span className="muted">Unassigned</span> },
            { label: 'Centre', render: (c) => code(centers, c.centerId) || '—' },
            { label: 'Seat', key: 'seat' },
            { label: 'Identity', key: 'identity', badge: true },
            { label: 'Ready', render: (c) => (c.examId ? <Badge value={isReady(readinessFor(c, { devices, exams, policies, releases })) ? 'ready' : 'not ready'} /> : '—') },
          ]}
          actions={(c) => [
            { label: 'Student 360', onClick: () => setDetail(c) },
            { label: 'Verify ID', disabled: !may('candidate.verify') || c.identity === 'verified', onClick: () => setPending({ kind: 'identity', c, outcome: 'verified' }) },
            { label: 'Reject ID', danger: true, disabled: !may('candidate.verify') || c.identity === 'rejected', onClick: () => setPending({ kind: 'identity', c, outcome: 'rejected' }) },
            { label: 'Progress sem', disabled: !may('candidate.manage'), onClick: () => setPending({ kind: 'progress', c }) },
            { label: c.academic_status === 'suspended' ? 'Reactivate' : 'Suspend', danger: c.academic_status !== 'suspended', disabled: !may('candidate.manage'), onClick: () => setPending({ kind: c.academic_status === 'suspended' ? 'reactivate' : 'suspend', c }) },
            { label: 'Correct name', disabled: !may('candidate.manage'), onClick: () => setPending({ kind: 'name', c }) },
            { label: 'Unassign', danger: true, disabled: !may('candidate.manage') || !c.examId, onClick: () => setPending({ kind: 'unassign', c }) },
            { label: 'Notify', disabled: !may('candidate.manage') || !c.examId, onClick: () => run(() => notifyCandidate(user, c, 'Exam update', 'Please review your exam briefing for the latest instructions.')) },
          ]}
          onRow={(c) => setDetail(c)}
          empty={<Empty icon="candidate" title="No candidates yet">Import a CSV or add candidates individually, then assign them to an exam.</Empty>}
        />
      </Card>

      {add && <AddCandidate tenantId={tenantId} onClose={() => setAdd(false)} onDone={fetchCandidates} />}
      {detail && <CandidateDetail c={detail} exams={exams} centers={centers} devices={devices} policies={policies} releases={releases} onClose={() => setDetail(null)} />}

      {pending && <ActionDialog
        title={
          pending.kind === 'unassign' ? `Unassign ${pending.c.rollNo}` :
          pending.kind === 'name' ? `Correct name · ${pending.c.rollNo}` :
          pending.kind === 'suspend' ? `Suspend student · ${pending.c.rollNo}` :
          pending.kind === 'reactivate' ? `Reactivate student · ${pending.c.rollNo}` :
          pending.kind === 'progress' ? `Progress semester · ${pending.c.rollNo}` :
          `${pending.outcome === 'verified' ? 'Verify' : 'Reject'} identity · ${pending.c.rollNo}`
        }
        desc={
          pending.kind === 'name' ? 'The previous name is retained in the correction history.' :
          pending.kind === 'unassign' ? 'The candidate returns to the unassigned pool.' :
          pending.kind === 'suspend' ? 'Places student on administrative hold and blocks exam launch.' :
          pending.kind === 'reactivate' ? 'Lifts administrative hold and restores active academic standing.' :
          pending.kind === 'progress' ? 'Enrolls student in the next semester while preserving historical records.' :
          'The decision and note are written to the audit trail.'
        }
        confirmLabel={
          pending.kind === 'unassign' ? 'Unassign' :
          pending.kind === 'name' ? 'Save correction' :
          pending.kind === 'suspend' ? 'Suspend' :
          pending.kind === 'reactivate' ? 'Reactivate' :
          pending.kind === 'progress' ? 'Enroll in semester' :
          'Record decision'
        }
        danger={pending.kind === 'unassign' || pending.kind === 'suspend' || pending.outcome === 'rejected'}
        field={
          pending.kind === 'name' ? { label: 'Corrected name', type: 'text', default: pending.c.name } :
          pending.kind === 'progress' ? { label: 'New semester number', type: 'number', default: (pending.c.semester || 1) + 1 } :
          undefined
        }
        requireReason={pending.kind !== 'progress'}
        onClose={() => setPending(null)}
        onConfirm={async (reason, value) => {
          await run(async () => {
            if (pending.kind === 'unassign') return unassign(user, pending.c, reason);
            if (pending.kind === 'name') return correctName(user, pending.c, value, reason);
            if (pending.kind === 'suspend') return suspendStudent(user, pending.c, reason);
            if (pending.kind === 'reactivate') return reactivateStudent(user, pending.c, reason);
            if (pending.kind === 'progress') return progressSemester(user, pending.c, value || (pending.c.semester || 1) + 1);
            return setIdentity(user, pending.c, pending.outcome, reason);
          });
          await fetchCandidates();
          setPending(null);
        }}
      />}
    </Page>
  );
}
