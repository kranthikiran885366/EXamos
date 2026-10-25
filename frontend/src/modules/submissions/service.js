import { all, get, put } from '../../core/db/db';
import { sha256, canon, sign, verify } from '../../core/security/crypto';
import { id, need, fail, log, score, ensureKey } from '../../core/services/common';
import { verifyPolicy } from '../policies/service';

export async function startSession(a, candidateId) {
  need(a, 'exam.operate');
  return openSession(a, candidateId);
}
async function openSession(a, candidateId) {
  const c = await get('candidates', candidateId); if (!c || !c.examId) fail('Candidate is not assigned to an exam.');
  const ex = await get('exams', c.examId); if (!ex || ex.status !== 'live') fail('The exam is not live.');
  if (c.identity !== 'verified') fail('Identity is not verified for this candidate.');
  const sessions = (await all('sessions')).filter((s) => s.candidateId === c.id);
  const open = sessions.find((s) => s.status === 'in_progress'); if (open) return open;
  if (sessions.length) fail('This candidate already has a completed session.');
  const dev = (await all('devices')).find((d) => d.centerId === c.centerId && d.seat === c.seat); if (!dev) fail('No device is enrolled for this seat.');
  if (dev.status !== 'enrolled') fail(`Device is ${dev.status}.`);
  if (dev.isolated) fail('Device is isolated by policy.');
  if (Date.now() - dev.lastSeen > 40000) fail('Device is unreachable (no heartbeat).');
  const rel = await get('releases', dev.releaseId); if (!rel || rel.status === 'revoked') fail('Device runs a revoked release.');
  const pol = await get('policies', ex.policyId); if (!pol || !(await verifyPolicy(pol))) fail('Exam policy signature is invalid.');
  const dp = dev.policyId ? await get('policies', dev.policyId) : null; if (!dp || dp.status !== 'published') fail('Device policy is out of date; wait for rollout.');
  if (pol.config.requireTpm && (dev.trust !== 'attested' || Date.now() - dev.lastAttested > 5 * 60000)) fail('Device check required: attest the device (valid for 5 minutes).');
  const now = Date.now();
  const s = { id: id('ses'), tenantId: c.tenantId, examId: ex.id, candidateId: c.id, deviceId: dev.id, status: 'in_progress', startedAt: now, deadline: now + ex.durationMin * 60000, answers: {}, lastSavedAt: now };
  await put('sessions', s); await log(a, 'SESSION_STARTED', `${c.rollNo} on ${dev.hostname}`); return s;
}

/** Candidate-initiated start: ownership is enforced, no operator permission is granted to the student. */
export async function startSessionForStudent(user, candidateId) {
  if (user.role !== 'student' || user.candidateId !== candidateId) fail('You can only start your own assigned exam.');
  const c = await get('candidates', candidateId);
  if (!c) fail('Candidate record not found.');
  const s = await openSession({ id: user.id, role: 'student' }, candidateId);
  return s;
}
export async function saveAnswer(sid, qi, choice, actor = null) {
  const s = await get('sessions', sid); if (!s || s.status !== 'in_progress') fail('Session is not active.');
  if (actor && actor.role === 'student' && actor.candidateId !== s.candidateId) fail('This session belongs to another candidate.');
  if (Date.now() > s.deadline) { await submitSession({ id: 'system', role: 'system' }, sid, { auto: true, why: 'time expired' }); fail('Time is up. Your answers were submitted automatically.'); }
  const ex = await get('exams', s.examId);
  if (!Number.isInteger(qi) || qi < 0 || qi >= ex.questions.length || !Number.isInteger(choice) || choice < 0 || choice > 3) fail('Invalid answer.');
  await put('sessions', { ...s, answers: { ...s.answers, [qi]: choice }, lastSavedAt: Date.now() });
}
export async function saveAnswerForStudent(user, sid, qi, choice) {
  const s = await get('sessions', sid);
  if (!s || s.candidateId !== user.candidateId) fail('This session does not belong to you.');
  return saveAnswer(sid, qi, choice, user);
}
export async function submitSessionForStudent(user, sid) {
  const s = await get('sessions', sid);
  if (!s || s.candidateId !== user.candidateId) fail('This session does not belong to you.');
  return submitSession({ id: user.id, role: 'student' }, sid);
}
export async function submitSession(a, sid, { auto = false, why = '' } = {}) {
  const s = await get('sessions', sid); if (!s) fail('Session not found.');
  if (s.status !== 'in_progress') fail('Session is already closed.');
  const ex = await get('exams', s.examId); const now = Date.now();
  const payload = { sessionId: s.id, examId: s.examId, candidateId: s.candidateId, answersHash: await sha256(canon(s.answers)), submittedAt: now };
  const k = await ensureKey('receipt-signer'); const h = await sha256(canon(payload));
  const out = { ...s, status: 'submitted', submittedAt: now, auto, score: score(ex, s.answers), receiptPayload: payload, receiptSig: await sign(k.priv, h), receipt: 'RC-' + h.slice(0, 12).toUpperCase() };
  await put('sessions', out); await log(a, 'SESSION_SUBMITTED', `${out.receipt}${auto ? ' (auto: ' + why + ')' : ''}`);
  if (ex?.status === 'live') {
    try { const n = await import('../notifications/service'); await n.broadcast({ tenantId: s.tenantId, title: 'Submission received', body: `${out.receipt} was recorded for ${ex.code}.`, link: '/operator/exams', role: 'invigilator', tone: 'success' }); } catch { /* non-blocking */ }
  }
  return out;
}
export async function verifyReceipt(s) {
  if (!s.receiptPayload) return false;
  const h = await sha256(canon(s.receiptPayload));
  if ('RC-' + h.slice(0, 12).toUpperCase() !== s.receipt || (await sha256(canon(s.answers))) !== s.receiptPayload.answersHash) return false;
  const k = await get('keys', 'receipt-signer'); return !!k && verify(k.pub, h, s.receiptSig);
}
export async function terminate(a, s, reason) {
  need(a, 'session.terminate'); if (s.status !== 'in_progress') fail('Only active sessions can be terminated.');
  if ((reason || '').length < 8) fail('Reason needs 8+ characters.');
  await put('sessions', { ...s, status: 'terminated', terminatedBy: a.id, terminatedReason: reason, submittedAt: Date.now() }); await log(a, 'SESSION_TERMINATED', `${s.id}: ${reason}`);
  return 'Session terminated and recorded.';
}
