import { all, get, put } from '../../core/db/db';
import { fail, log, need, requireReason, pct } from '../../core/services/common';
import { setIdentity } from '../candidates/service';
import { startSession, terminate } from '../submissions/service';
import { deviceState, reachable } from '../fleet/service';

export async function assignedExams(user, ctx = {}) {
  const { exams = await all('exams'), centers = await all('centers'), candidates = await all('candidates'), sessions = await all('sessions') } = ctx;
  return exams.filter((e) => e.tenantId === user.tenantId).map((e) => {
    const cs = candidates.filter((c) => c.examId === e.id);
    const ss = sessions.filter((s) => s.examId === e.id);
    return {
      ...e, centers: centers.filter((c) => e.centerIds.includes(c.id)),
      assigned: cs.length, started: ss.length, submitted: ss.filter((s) => s.status === 'submitted').length,
      inProgress: ss.filter((s) => s.status === 'in_progress').length,
      incidents: 0,
    };
  }).sort((a, b) => {
    const rank = { live: 0, published: 1, approved: 2, review: 3, draft: 4, closed: 5, cancelled: 6 };
    return (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || a.startAt - b.startAt;
  });
}

export async function liveBoard(exam, ctx = {}) {
  const { candidates = await all('candidates'), sessions = await all('sessions'), devices = await all('devices'), centers = await all('centers'), incidents = await all('incidents'), attestations = await all('attestations') } = ctx;
  const cs = candidates.filter((c) => c.examId === exam.id);
  const rows = cs.map((c) => {
    const s = sessions.filter((x) => x.candidateId === c.id).sort((a, b) => b.startedAt - a.startedAt)[0] || null;
    const d = devices.find((x) => x.centerId === c.centerId && x.seat === c.seat) || null;
    const att = attestations.filter((a) => a.deviceId === d?.id && a.result).sort((a, b) => b.verifiedAt - a.verifiedAt)[0];
    return {
      ...c, center: centers.find((x) => x.id === c.centerId) || null, session: s, device: d,
      deviceState: d ? deviceState(d) : 'none', lastAttestation: att || null,
      remaining: s ? Math.max(0, (s.deadline || 0) - Date.now()) : 0,
      state: s ? s.status : c.identity === 'verified' ? 'ready' : 'waiting-identity',
    };
  });
  const byCenter = centers.filter((c) => exam.centerIds.includes(c.id)).map((c) => ({
    center: c, seats: rows.filter((r) => r.centerId === c.id),
    started: rows.filter((r) => r.centerId === c.id && r.session).length,
    submitted: rows.filter((r) => r.centerId === c.id && r.session?.status === 'submitted').length,
    issues: rows.filter((r) => r.centerId === c.id && r.device && ['offline', 'isolated', 'failed', 'compat-fail'].includes(r.deviceState)).length,
  }));
  return { rows, byCenter, incidents: incidents.filter((i) => i.tenantId === exam.tenantId && ['open', 'investigating', 'contained'].includes(i.status)) };
}

export function boardStats(board) {
  const rows = board.rows;
  return {
    assigned: rows.length, verified: rows.filter((r) => r.identity === 'verified').length,
    started: rows.filter((r) => r.session).length, inProgress: rows.filter((r) => r.session?.status === 'in_progress').length,
    submitted: rows.filter((r) => r.session?.status === 'submitted').length,
    waiting: rows.filter((r) => !r.session && r.identity !== 'verified').length,
    issues: rows.filter((r) => ['offline', 'isolated', 'failed', 'compat-fail'].includes(r.deviceState)).length,
    attendance: pct(rows.filter((r) => r.session).length, rows.length),
  };
}

export async function checkIn(user, candidate) {
  if (candidate.examId == null) fail('Assign the candidate to an exam first.');
  return setIdentity(user, candidate, 'verified', 'Photo ID checked at the desk');
}
export async function startCandidate(user, candidate) {
  return startSession(user, candidate.id);
}
export async function terminateSession(user, session, reason) {
  return terminate(user, session, reason);
}
export async function extendTime(user, session, minutes, reason) {
  need(user, 'exam.operate');
  if (session.status !== 'in_progress') fail('Only an active session can be extended.');
  const m = Number(minutes);
  if (!(m >= 1 && m <= 60)) fail('Extension must be 1–60 minutes.');
  const r = requireReason(reason, 8);
  const next = { ...session, deadline: session.deadline + m * 60000, extensions: [...(session.extensions || []), { at: Date.now(), by: user.id, minutes: m, reason: r }] };
  await put('sessions', next);
  await log(user, 'SESSION_EXTENDED', `${session.id} +${m}m: ${r}`);
  return `Session extended by ${m} minutes.`;
}
export async function submissionFeed(exam, ctx = {}) {
  const { sessions = await all('sessions'), candidates = await all('candidates'), devices = await all('devices') } = ctx;
  return sessions.filter((s) => s.examId === exam.id).sort((a, b) => (b.submittedAt || b.startedAt) - (a.submittedAt || a.startedAt)).map((s) => ({
    ...s, candidate: candidates.find((c) => c.id === s.candidateId) || null, device: devices.find((d) => d.id === s.deviceId) || null,
  }));
}
export function submissionStats(list) {
  const submitted = list.filter((s) => s.status === 'submitted');
  return {
    total: list.length, submitted: submitted.length, inProgress: list.filter((s) => s.status === 'in_progress').length,
    terminated: list.filter((s) => s.status === 'terminated').length,
    auto: submitted.filter((s) => s.auto).length,
    avg: submitted.length ? +(submitted.reduce((n, s) => n + (s.score || 0), 0) / submitted.length).toFixed(1) : 0,
  };
}
export async function deskLookup(rollNo, tenantId, ctx = {}) {
  const { candidates = await all('candidates'), centers = await all('centers'), devices = await all('devices') } = ctx;
  const c = candidates.find((x) => x.tenantId === tenantId && x.rollNo.toLowerCase() === String(rollNo || '').trim().toLowerCase());
  if (!c) fail('No candidate matches that roll number.');
  return { ...c, center: centers.find((x) => x.id === c.centerId) || null, device: devices.find((d) => d.centerId === c.centerId && d.seat === c.seat) || null };
}
export const isLive = (e) => e.status === 'live';
export const deviceOk = (d) => d && d.status === 'enrolled' && !d.isolated && reachable(d);
export async function sessionFor(candidateId) {
  return (await all('sessions')).filter((s) => s.candidateId === candidateId).sort((a, b) => b.startedAt - a.startedAt)[0] || null;
}
export async function incidentList(tenantId) {
  return (await all('incidents')).filter((i) => i.tenantId === tenantId).sort((a, b) => b.createdAt - a.createdAt);
}
export async function resolveExamSession(user, sessionId) { return get('sessions', sessionId); }
