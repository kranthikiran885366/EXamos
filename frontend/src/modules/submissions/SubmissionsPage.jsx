import { useEffect, useState } from 'react';
import Crud, { Tabs, useRun, Flash } from '../../core/ui/Crud';
import Badge from '../../core/ui/Badge';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { useTick } from '../../core/ui/useTick';
import { fmt, ago, hms } from '../../core/ui/format';
import { startSession, saveAnswer, submitSession, verifyReceipt, terminate } from './service';
import { attest } from '../tpm/service';

function Runner({ s, ex, onDone }) {
  const { user } = useAuth(); const [i, setI] = useState(0); const [ans, setAns] = useState(s.answers || {}); const [msg, run, setMsg] = useRun(); useTick(1000);
  const left = s.deadline - Date.now();
  const finish = (auto) => run(async () => { const o = await submitSession(user, s.id, { auto }); onDone(o); return `Submitted. Receipt ${o.receipt}.`; });
  useEffect(() => { if (left <= 0) finish(true); });

  return (
    <div className="card pad2">
      <div className="split"><b>{ex.title}</b><span className={'big sm2 ' + (left < 300000 ? 'redt' : '')}>{hms(left)}</span></div>
      {ex.instructions && (
        <div className="pad bg-muted rounded mb" style={{ margin: '12px 0', padding: '12px', background: 'var(--bg-subtle, #f8fafc)', borderRadius: '6px' }}>
          <b>Instructions:</b>
          <p style={{ margin: '6px 0 0', whiteSpace: 'pre-wrap' }}>{ex.instructions}</p>
        </div>
      )}
      <div style={{ margin: '16px 0' }}>
        <p className="muted sm">Target Assessment Portal: {ex.examUrl || 'Configured URL'}</p>
        {ex.examUrl ? (
          <div style={{ width: '100%', height: '520px', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden', marginTop: '10px' }}>
            <iframe src={ex.examUrl} title="Assessment Portal" style={{ width: '100%', height: '100%', border: 'none' }} allow="fullscreen; camera; microphone" sandbox="allow-scripts allow-same-origin allow-forms allow-popups" />
          </div>
        ) : (
          <div className="muted pad">No exam URL configured for this session.</div>
        )}
        <div className="row end" style={{ marginTop: '14px' }}>
          <button className="btn primary" onClick={() => finish(false)}>Submit exam</button>
        </div>
      </div>
      <Flash msg={msg} onClose={() => setMsg(null)} />
    </div>
  );
}
function Kiosk() {
  const { user } = useAuth(); const exams = useCol('exams'), cands = useCol('candidates'), sess = useCol('sessions'), devs = useCol('devices'); useTick(3000);
  const [cid, setCid] = useState(''); const [msg, run, setMsg] = useRun(); const [done, setDone] = useState(null);
  const live = exams.filter((e) => e.status === 'live'); const pool = cands.filter((c) => live.some((e) => e.id === c.examId) && c.identity === 'verified' && !sess.some((s) => s.candidateId === c.id && s.status !== 'in_progress'));
  const cand = pool.find((c) => c.id === cid); const ex = cand && exams.find((e) => e.id === cand.examId); const dev = cand && devs.find((d) => d.centerId === cand.centerId && d.seat === cand.seat);
  const active = cand && sess.find((s) => s.candidateId === cand.id && s.status === 'in_progress');
  return (
    <div className="pad"><p className="muted">Simulates the exam kiosk UI. Candidate launch is blocked until server-side TPM quote verification is available; local simulation cannot authorize an exam.</p>
      <div className="card pad2"><div className="row wrap"><select value={cid} onChange={(e) => { setCid(e.target.value); setDone(null); }}><option value="">Select a verified candidate…</option>{pool.map((c) => <option key={c.id} value={c.id}>{c.rollNo} · {c.name} · {c.seat}</option>)}</select>
        {dev && <span className="muted sm">Device <b className="mono">{dev.hostname}</b> · server trust <Badge>{dev.backendTrustOutcome === 'ALLOW' ? 'Verified' : 'Unverified'}</Badge> · last report {ago(dev.lastAttested)} · heartbeat {ago(dev.lastSeen)}</span>}</div>
        {cand && !active && <div className="row"><button className="btn" disabled={!dev || !can(user.role, 'tpm.run')} onClick={() => run(() => attest(user, dev.id))}>1 · Run device check</button><button className="btn primary" onClick={() => run(async () => { await startSession(user, cand.id); return 'Session started.'; })}>2 · Start exam</button></div>}
        <Flash msg={msg} onClose={() => setMsg(null)} /></div>
      {active && ex && <Runner key={active.id} s={active} ex={ex} onDone={setDone} />}
      {done && <div className="okmsg">Submitted at {fmt(done.submittedAt)} · Receipt <b>{done.receipt}</b></div>}
    </div>
  );
}
export default function SubmissionsPage() {
  const { user } = useAuth(); const [tab, setTab] = useState('Sessions'); const sess = useCol('sessions'), cands = useCol('candidates'), exams = useCol('exams'), devs = useCol('devices'); const [msg, run, setMsg] = useRun();
  return (
    <>
      <div className="pad pb0"><Tabs tabs={['Sessions', 'Candidate kiosk']} value={tab} onChange={setTab} /><Flash msg={msg} onClose={() => setMsg(null)} /></div>
      {tab === 'Candidate kiosk' ? <Kiosk /> : (
        <Crud title="Submissions" desc="Exam sessions and server-returned receipts. Independent receipt verification is not available in this console." rows={[...sess].sort((a, b) => b.startedAt - a.startedAt)} search={(s) => `${s.id} ${s.receipt || ''} ${cands.find((c) => c.id === s.candidateId)?.rollNo || ''}`}
          columns={[{ label: 'Candidate', render: (s) => cands.find((c) => c.id === s.candidateId)?.rollNo }, { label: 'Exam', render: (s) => exams.find((e) => e.id === s.examId)?.code }, { label: 'Device', render: (s) => <span className="mono">{devs.find((d) => d.id === s.deviceId)?.hostname}</span> }, { label: 'Started', render: (s) => fmt(s.startedAt) },
            { label: 'Answered', render: (s) => Object.keys(s.answers).length }, { label: 'Score', render: (s) => (s.score ?? '—') }, { label: 'Receipt', render: (s) => <span className="mono">{s.receipt || '—'}</span> }, { label: 'Status', render: (s) => <Badge>{s.status === 'in_progress' ? 'Active' : s.status === 'submitted' ? 'Complete' : 'Failed'}</Badge> }]}
          actions={[{ label: 'Verify receipt', show: (s) => s.status === 'submitted', run: (s) => verifyReceipt(s) },
            { label: 'Terminate', perm: 'session.terminate', danger: true, reason: true, show: (s) => s.status === 'in_progress', run: (s, r) => terminate(user, s, r) }]} />)}
    </>
  );
}
