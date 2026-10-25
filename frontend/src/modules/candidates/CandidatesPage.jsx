import { useMemo, useState } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { usePerm } from '../../core/ui/hooks';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash, Empty,
  Icon, Modal, Field, Input, Select, Textarea, KeyValue, Loading, CopyButton,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  addCandidate, previewImport, commitImport, assignToExam, unassign, setIdentity,
  correctName, readinessFor, isReady, CSV_TEMPLATE, notifyCandidate,
} from './service';

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
    <Card title="Bulk import" desc="CSV header: rollNo,name,email. Rows are validated and duplicates rejected before anything is saved.">
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
        {prev && <button className="btn primary" disabled={!prev.valid.length || busy || !may('candidate.manage')} onClick={() => run(async () => {
          const m = await commitImport(user, tenantId, prev.valid);
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

function AssignPanel({ tenantId, onDone }) {
  const { user } = useAuth();
  const may = usePerm();
  const exams = useCol('exams').filter((e) => ['draft', 'review', 'approved', 'published'].includes(e.status));
  const centers = useCol('centers');
  const candidates = useCol('candidates');
  const [examId, setExamId] = useState('');
  const [centerId, setCenterId] = useState('');
  const [count, setCount] = useState('');
  const { msg, setMsg, run, busy } = useFlash();
  const exam = exams.find((e) => e.id === examId);
  const free = candidates.filter((c) => !c.examId).length;
  return (
    <Card title="Assign & seat" desc="Seats are allocated automatically from free centre capacity. Only unassigned candidates are seated.">
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <div className="formgrid">
        <Field label="Exam"><Select value={examId} onChange={(e) => { setExamId(e.target.value); setCenterId(''); }} options={exams.map((e) => ({ v: e.id, l: `${e.code} · ${e.status}` }))} placeholder="Choose an exam" /></Field>
        <Field label="Centre"><Select value={centerId} onChange={(e) => setCenterId(e.target.value)} options={centers.filter((c) => exam?.centerIds.includes(c.id)).map((c) => ({ v: c.id, l: `${c.code} · ${c.capacity} seats` }))} placeholder="Choose a centre" /></Field>
        <Field label="How many" help={`${free} unassigned candidate(s) available`}><Input type="number" min={1} value={count} onChange={(e) => setCount(e.target.value)} placeholder="Blank = all" /></Field>
        <div className="field"><span className="field-label">&nbsp;</span><button className="btn primary" disabled={!examId || !centerId || busy || !may('candidate.manage')} onClick={() => run(async () => {
          const m = await assignToExam(user, { tenantId, examId, centerId, count });
          onDone?.(); return m;
        })}>Assign candidates</button></div>
      </div>
    </Card>
  );
}

function AddCandidate({ tenantId, onClose, onDone }) {
  const { user } = useAuth();
  const { msg, setMsg, run, busy } = useFlash();
  const [v, setV] = useState({ rollNo: '', name: '', email: '' });
  const set = (k, x) => setV((s) => ({ ...s, [k]: x }));
  const submit = async (e) => {
    e.preventDefault();
    const ok = await run(() => addCandidate(user, { tenantId, ...v }), 'Candidate added.');
    if (ok) { onDone?.(); onClose(); }
  };
  return (
    <Modal title="Add candidate" desc="Roll numbers must be 6–14 letters or digits and emails unique within the institution." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="cand-form" disabled={busy}>{busy ? 'Saving…' : 'Add candidate'}</button></>}>
      <form id="cand-form" className="stack" onSubmit={submit}>
        <Flash msg={msg} onClose={() => setMsg(null)} />
        <Field label="Roll number" required><Input value={v.rollNo} onChange={(e) => set('rollNo', e.target.value.toUpperCase())} maxLength={14} autoFocus /></Field>
        <Field label="Name" required><Input value={v.name} onChange={(e) => set('name', e.target.value)} maxLength={80} /></Field>
        <Field label="Email" required><Input type="email" value={v.email} onChange={(e) => set('email', e.target.value)} maxLength={120} /></Field>
      </form>
    </Modal>
  );
}

function CandidateDetail({ c, exams, centers, devices, policies, releases, onClose }) {
  const checks = readinessFor(c, { devices, exams, policies, releases });
  const exam = exams.find((e) => e.id === c.examId);
  const center = centers.find((x) => x.id === c.centerId);
  return (
    <Modal title={`${c.rollNo} · ${c.name}`} desc="Candidate record and readiness summary." onClose={onClose} wide footer={<button className="btn" onClick={onClose}>Close</button>}>
      <KeyValue cols={2} items={[
        ['Roll number', c.rollNo], ['Name', c.name], ['Email', c.email], ['Status', <Badge value={c.status} />],
        ['Exam', exam ? `${exam.code} · ${exam.title}` : '—'], ['Centre', center?.code || '—'],
        ['Seat', c.seat || '—'], ['Identity', <Badge value={c.identity} />],
        ['Registered', fmt(c.createdAt)], ['Assigned', c.assignedAt ? fmt(c.assignedAt) : '—'],
        ['Identity note', c.identityNote || '—'], ['Corrections', (c.corrections || []).length],
      ]} />
      <h3 className="mt">Readiness</h3>
      <DataTable rows={checks} columns={[
        { label: 'Check', key: 'label' }, { label: 'Status', key: 'status', badge: true }, { label: 'Detail', key: 'detail' },
      ]} />
      <Alert tone={isReady(checks) ? 'success' : 'warn'} title={isReady(checks) ? 'Ready to sit' : 'Not ready'}>
        {isReady(checks) ? 'All blocking checks pass for this candidate.' : 'Resolve failed checks before the session can start.'}
      </Alert>
    </Modal>
  );
}

export default function CandidatesPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const candidates = useCol('candidates');
  const exams = useCol('exams');
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
        <button className="btn" disabled={busy || !may('candidate.verify')} onClick={() => run(async () => {
          const target = candidates.filter((c) => c.examId && c.identity === 'pending');
          if (!target.length) throw new Error('No candidates are waiting for identity verification.');
          let done = 0;
          for (const c of target.slice(0, 50)) { await setIdentity(user, c, 'verified', 'Bulk verification from candidate list'); done += 1; }
          return `${done} candidate(s) verified.`;
        })}>Verify pending</button>
        <button className="btn primary" disabled={!may('candidate.manage')} onClick={() => setAdd(true)}><Icon name="plus" size={15} /> Add candidate</button>
      </>}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      <StatGrid cols={4}>
        <Stat label="Candidates" value={stats.total} icon="candidate" />
        <Stat label="Assigned" value={stats.assigned} icon="exam" sub={`${stats.total - stats.assigned} unassigned`} />
        <Stat label="Identity verified" value={stats.verified} icon="check" tone="green" />
        <Stat label="Ready to sit" value={stats.ready} icon="device" tone="blue" />
      </StatGrid>

      <div className="two">
        <ImportPanel tenantId={tenantId} onDone={() => {}} />
        <AssignPanel tenantId={tenantId} onDone={() => {}} />
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
            { label: 'View', onClick: () => setDetail(c) },
            { label: 'Verify ID', disabled: !may('candidate.verify') || !c.examId || c.identity === 'verified', onClick: () => setPending({ kind: 'identity', c, outcome: 'verified' }) },
            { label: 'Reject ID', danger: true, disabled: !may('candidate.verify') || !c.examId || c.identity === 'rejected', onClick: () => setPending({ kind: 'identity', c, outcome: 'rejected' }) },
            { label: 'Correct name', disabled: !may('candidate.manage'), onClick: () => setPending({ kind: 'name', c }) },
            { label: 'Unassign', danger: true, disabled: !may('candidate.manage') || !c.examId, onClick: () => setPending({ kind: 'unassign', c }) },
            { label: 'Notify', disabled: !may('candidate.manage') || !c.examId, onClick: () => run(() => notifyCandidate(user, c, 'Exam update', 'Please review your exam briefing for the latest instructions.')) },
          ]}
          onRow={(c) => setDetail(c)}
          empty={<Empty icon="candidate" title="No candidates yet">Import a CSV or add candidates individually, then assign them to an exam.</Empty>}
        />
      </Card>

      {add && <AddCandidate tenantId={tenantId} onClose={() => setAdd(false)} onDone={() => {}} />}
      {detail && <CandidateDetail c={detail} exams={exams} centers={centers} devices={devices} policies={policies} releases={releases} onClose={() => setDetail(null)} />}

      {pending && <ActionDialog
        title={pending.kind === 'unassign' ? `Unassign ${pending.c.rollNo}` : pending.kind === 'name' ? `Correct name · ${pending.c.rollNo}` : `${pending.outcome === 'verified' ? 'Verify' : 'Reject'} identity · ${pending.c.rollNo}`}
        desc={pending.kind === 'name' ? 'The previous name is retained in the correction history.' : pending.kind === 'unassign' ? 'The candidate returns to the unassigned pool.' : 'The decision and note are written to the audit trail.'}
        confirmLabel={pending.kind === 'unassign' ? 'Unassign' : pending.kind === 'name' ? 'Save correction' : 'Record decision'}
        danger={pending.kind === 'unassign' || pending.outcome === 'rejected'}
        field={pending.kind === 'name' ? { label: 'Corrected name', type: 'text', default: pending.c.name } : undefined}
        requireReason
        onClose={() => setPending(null)}
        onConfirm={async (reason, value) => {
          await run(() => {
            if (pending.kind === 'unassign') return unassign(user, pending.c, reason);
            if (pending.kind === 'name') return correctName(user, pending.c, value, reason);
            return setIdentity(user, pending.c, pending.outcome, reason);
          });
          setPending(null);
        }}
      />}
    </Page>
  );
}
