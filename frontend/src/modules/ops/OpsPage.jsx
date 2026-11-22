import { useState } from 'react';
import Spark from '../../core/ui/Spark';
import Badge from '../../core/ui/Badge';
import PolicyInspector from './PolicyInspector';
import { hist } from './engine';
import { p95 } from '../../core/db/db';
import { useCol } from '../../core/db/tenant';
import { useAuth } from '../../core/auth/AuthContext';
import { can } from '../../core/security/rbac';
import { csvCell } from '../../core/security/sanitize';
import { record } from '../../core/security/auditChain';
import { seatLabel } from '../../core/services/common';
import { compliant, reachable } from '../fleet/service';
import { useTick } from '../../core/ui/useTick';
import { ist, ago, hms } from '../../core/ui/format';

const TABS = ['Live operations', 'Exam sessions', 'Infrastructure', 'Incident log'];
const OPEN = ['open', 'investigating', 'contained'];

export default function OpsPage() {
  const { user } = useAuth(); useTick(1000);
  const exams = useCol('exams'), sess = useCol('sessions'), devs = useCol('devices'), incs = useCol('incidents'), ctrs = useCol('centers'), cands = useCol('candidates'), pols = useCol('policies'), rels = useCol('releases', false), audit = useCol('audit', false), atts = useCol('attestations');
  const [tab, setTab] = useState(0); const [exId, setExId] = useState(''); const [ceId, setCeId] = useState('');
  const now = Date.now(); const live = exams.filter((e) => e.status === 'live'); const ex = live.find((e) => e.id === exId) || live[0];
  const exCenters = ex?.centerIds ? ctrs.filter((c) => ex.centerIds.includes(c.id)) : []; const ce = exCenters.find((c) => c.id === ceId) || exCenters[0];
  const active = sess.filter((s) => s.status === 'in_progress'); const enrolled = devs.filter((d) => d.status === 'enrolled'); const okDevs = enrolled.filter((d) => compliant(d, pols, rels, now));
  const open = incs.filter((i) => OPEN.includes(i.status)); const crit = open.filter((i) => i.severity === 'critical').length;
  const lat = p95(); const pct = enrolled.length ? (okDevs.length / enrolled.length) * 100 : 100;
  const kpis = [
    { label: 'Active exams', value: String(live.length), sub: `${active.length} candidates in session`, spark: hist.active, step: true, color: '#2f5bea' },
    { label: 'Fleet compliance', value: pct.toFixed(1) + '%', sub: `${okDevs.length} / ${enrolled.length} devices`, spark: hist.compliance, color: '#2f9e6e' },
    { label: 'API latency · p95', value: lat.toFixed(0), unit: 'ms', sub: lat < 200 ? 'Measured · within SLO < 200 ms' : 'Measured · above SLO', spark: hist.latency, color: lat < 200 ? '#2f5bea' : '#d64545' },
    { label: 'Open incidents', value: String(open.length).padStart(2, '0'), sub: `${crit} critical · ${open.filter((i) => i.status === 'investigating').length} investigating`, warn: open.length > 0 },
  ];
  const seats = ce && ex ? Array.from({ length: ce.capacity || 0 }, (_, i) => {
    const label = seatLabel(i); const c = cands.find((x) => x.examId === ex.id && x.centerId === ce.id && x.seat === label); const dv = devs.find((x) => x.centerId === ce.id && x.seat === label);
    const s = c && sess.find((x) => x.candidateId === c.id);
    let st = 'empty';
    if (c || dv) { st = 'idle'; if (dv && (dv.isolated || !reachable(dv, now))) st = 'offline'; else if (dv && incs.some((i) => i.deviceId === dv.id && OPEN.includes(i.status))) st = 'review'; else if (s?.status === 'in_progress') st = 'active'; else if (s?.status === 'submitted') st = 'done'; }
    return { label, st, who: c?.rollNo };
  }) : [];
  const n = (k) => seats.filter((s) => s.st === k).length; const rows = Math.ceil((ce?.capacity || 0) / 16);
  const end = ex ? (ex.liveAt || ex.startAt || 0) + (ex.durationMin || 60) * 60000 : 0;
  const registry = [...devs].sort((a, b) => Number(compliant(a, pols, rels, now)) - Number(compliant(b, pols, rels, now)) || a.hostname.localeCompare(b.hostname)).slice(0, 8);
  const stream = [...audit].sort((a, b) => b.seq - a.seq).slice(0, 8);
  const exportReport = () => { const rowsOut = [['metric', 'value'], ...kpis.map((k) => [k.label, k.value + (k.unit || '')])]; const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([rowsOut.map((r) => r.map(csvCell).join(',')).join('\n')], { type: 'text/csv' })); a.download = 'ops-overview.csv'; a.click(); record(user.id, 'EXPORT_REPORT', 'ops-overview'); };
  const spark = (k) => (k.spark && k.spark.length > 1 ? <Spark data={k.spark} color={k.color} step={k.step} /> : k.warn ? <span className="tri">⚠</span> : <span />);
  return (
    <div className="opsgrid">
      <div className="pad">
        <div className="head"><div><h1>Operations overview</h1><p className="muted sm">{ex ? `${ex.code} · ${ex.title}` : 'No live exam'} · {ist()} IST</p></div>
          <div className="row"><button className="btn" disabled={!can(user.role, 'export')} onClick={exportReport}>Export report</button><button className="btn primary" onClick={() => setTab(0)}>((·)) Live view</button></div></div>
        <div className="kpis">{kpis.map((k) => <div className="card kpi" key={k.label}><small>{k.label}</small><div className="kv"><span className="big">{k.value}{k.unit && <em>{k.unit}</em>}</span>{spark(k)}</div><small className="link">{k.sub}</small></div>)}</div>
        <div className="tabs" role="tablist">{TABS.map((t, i) => <button key={t} role="tab" aria-selected={tab === i} className={tab === i ? 'on' : ''} onClick={() => setTab(i)}>{t}</button>)}</div>

        {tab === 0 && <>
          <section className="card"><div className="ctitle"><b>Live exam control</b><span className={'badge ' + (ex ? 'g' : 'n')}><i />{ex ? 'Live' : 'Idle'}</span><span className="grow" />
            <select value={ex?.id || ''} onChange={(e) => { setExId(e.target.value); setCeId(''); }}>{live.map((e) => <option key={e.id} value={e.id}>{e.code}</option>)}</select>
            <select value={ce?.id || ''} onChange={(e) => setCeId(e.target.value)}>{exCenters.map((c) => <option key={c.id} value={c.id}>{c.code}</option>)}</select></div>
            {ex && ce ? <div className="live"><div className="liveinfo"><b>{ex.title}</b><small>{ex.code} · {ce.code} · {ce.labs} labs</small>
              <div className="split2"><div><span className="big sm2">{n('active')}</span><small>of {seats.filter((s) => s.who).length} seated candidates active</small></div><div><span className="big sm2">{hms(end - now)}</span><small>remaining in window</small></div></div>
              <small className="okt">● {enrolled.filter((d) => d.centerId === ce.id && reachable(d, now)).length} devices reporting heartbeat</small></div>
              <div className="heat" role="img" aria-label="Seat heatmap"><div className="hgrid">{seats.map((s) => <i key={s.label} className={'seat ' + s.st} title={`${s.label}${s.who ? ' · ' + s.who : ''} · ${s.st}`} />)}</div>
                <div className="legend"><span><i className="seat active" />Active {n('active')}</span><span><i className="seat done" />Done {n('done')}</span><span><i className="seat idle" />Not started {n('idle')}</span><span><i className="seat review" />Review {n('review')}</span><span><i className="seat offline" />Offline {n('offline')}</span><span><i className="seat empty" />Empty {n('empty')}</span></div><small className="muted">{rows} rows × 16 seats</small></div></div>
              : <p className="pad2 muted">No exam is live. Move one through the lifecycle in Exam Lifecycle.</p>}</section>
          <section className="card"><div className="ctitle"><b>Device registry</b><small className="muted">{devs.length} devices</small><span className="grow" /><small>Exceptions first</small></div>
            <table><thead><tr><th>Device / Seat</th><th>Server trust</th><th>Policy</th><th>Last reported</th><th>Last attestation report</th></tr></thead><tbody>{registry.map((d) => <tr key={d.id}><td className="mono">🖥 {d.hostname}</td><td><Badge>{d.backendTrustOutcome === 'ALLOW' ? 'Verified' : 'Unverified'}</Badge></td><td><Badge>{d.isolated ? 'Isolated' : compliant(d, pols, rels, now) ? 'Compliant' : 'Review'}</Badge></td><td className={reachable(d, now) ? '' : 'redt'}>{ago(d.lastSeen)}</td><td className="muted">{ago(d.lastAttested)}</td></tr>)}{!registry.length && <tr><td colSpan="5" className="muted">No devices enrolled.</td></tr>}</tbody></table></section>
        </>}
        {tab === 1 && <section className="card"><div className="ctitle"><b>Exam sessions</b><small className="muted">{sess.length} total</small></div><table><thead><tr><th>Candidate</th><th>Exam</th><th>Started</th><th>Answered</th><th>Status</th></tr></thead><tbody>{[...sess].sort((a, b) => b.startedAt - a.startedAt).slice(0, 12).map((s) => <tr key={s.id}><td>{cands.find((c) => c.id === s.candidateId)?.rollNo}</td><td>{exams.find((e) => e.id === s.examId)?.code}</td><td>{ago(s.startedAt)}</td><td>{Object.keys(s.answers).length}</td><td><Badge>{s.status === 'in_progress' ? 'Active' : s.status === 'submitted' ? 'Complete' : 'Failed'}</Badge></td></tr>)}</tbody></table></section>}
        {tab === 2 && <section className="card"><div className="ctitle"><b>Infrastructure</b></div><table><thead><tr><th>Check</th><th>Value</th></tr></thead><tbody>
          <tr><td>Console data API p95 latency</td><td>{lat.toFixed(1)} ms</td></tr><tr><td>Attestations recorded</td><td>{atts.filter((a) => a.result).length}</td></tr><tr><td>Attestation failures</td><td>{atts.filter((a) => a.result === 'failed').length}</td></tr>
          <tr><td>Unreachable devices</td><td>{enrolled.filter((d) => !reachable(d, now)).length}</td></tr><tr><td>Isolated devices</td><td>{devs.filter((d) => d.isolated).length}</td></tr><tr><td>Audit entries</td><td>{audit.length}</td></tr></tbody></table></section>}
        {tab === 3 && <section className="card"><div className="ctitle"><b>Incident log</b></div><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>{[...incs].sort((a, b) => b.createdAt - a.createdAt).slice(0, 10).map((i) => <tr key={i.id}><td>INC-{i.no}</td><td>{i.title}</td><td><Badge>{i.severity}</Badge></td><td><Badge>{i.status}</Badge></td></tr>)}{!incs.length && <tr><td colSpan="4" className="muted">No incidents recorded. That is not proof of safety; check telemetry freshness.</td></tr>}</tbody></table></section>}

        <section className="card"><div className="ctitle"><b>Audit stream</b><small className="muted">{audit.length} events</small></div>
          <table><thead><tr><th>Time / IST</th><th>Event</th><th>Actor</th><th>Chain hash</th></tr></thead><tbody>{stream.map((s) => <tr key={s.id}><td className="mono">{ist(Date.parse(s.ts))}</td><td>{s.event} <span className="muted">{s.detail.slice(0, 50)}</span></td><td className="mono">{s.actor}</td><td className="mono muted">{s.hash.slice(0, 12)}…</td></tr>)}</tbody></table></section>
        <p className="foot">● Engine running · refreshes every 5s<span>{new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()} · {ist()} IST</span></p>
      </div>
      {can(user.role, 'policies') && <PolicyInspector />}
    </div>
  );
}
