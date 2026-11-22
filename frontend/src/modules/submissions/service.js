import { all, get, put } from '../../core/db/db';
import { need, fail, log } from '../../core/services/common';
import * as Api from '../../core/api/services';

export async function startSession(a, candidateId) {
  need(a, 'exam.operate');
  return openSession(a, candidateId);
}

async function openSession(a, candidateId) {
  const c = await get('candidates', candidateId); if (!c || !c.examId) fail('Candidate is not assigned to an exam.');
  const ex = await get('exams', c.examId); if (!ex || ex.status !== 'live') fail('The exam is not live.');
  if (c.identity !== 'verified') fail('Identity is not verified for this candidate.');
  const sessions = (await all('sessions')).filter((s) => s.candidateId === c.id);
  if (sessions.length) fail('A session record already exists. The backend does not support session recovery, so it cannot be resumed.');
  const dev = (await all('devices')).find((d) => d.centerId === c.centerId && d.seat === c.seat); if (!dev) fail('No device is enrolled for this seat.');
  if (dev.status !== 'enrolled') fail(`Device is ${dev.status}.`);
  if (dev.isolated) fail('Device is isolated by policy.');
  if (Date.now() - dev.lastSeen > 40000) fail('Device is unreachable (no heartbeat).');
  const rel = await get('releases', dev.releaseId); if (!rel || rel.status === 'revoked') fail('Device runs a revoked release.');
  const pol = await get('policies', ex.policyId);
  if (!pol || pol.status !== 'published') fail('The exam does not have a published policy.');
  fail('Server-side policy signature verification is unavailable. Session launch is blocked until the trust integration is complete.');
  const dp = dev.policyId ? await get('policies', dev.policyId) : null; if (!dp || dp.status !== 'published') fail('Device policy is out of date; wait for rollout.');
  if (pol.config.requireTpm && dev.backendTrustOutcome !== 'ALLOW')
    fail('The backend has not verified trusted TPM evidence for this device; the exam cannot start.');

  let response;
  try {
    response = await Api.createAuthorizedExamSession({
      examination_id: ex.id,
      student_id: c.id,
      device_id: dev.id,
    });
  } catch (error) {
    fail(error.message || 'The backend could not authorize the exam session.');
  }
  if (response?.status !== 'authorized' || response.session?.status !== 'authorized' ||
      typeof response.session.id !== 'string' || !response.session.id)
    fail('The backend did not confirm an authorized exam session.');

  const now = Date.now();
  const s = {
    id: response.session.id, tenantId: c.tenantId, examId: ex.id, candidateId: c.id,
    deviceId: dev.id, status: 'in_progress', startedAt: now,
    deadline: now + ex.durationMin * 60000, answers: {}, lastSavedAt: now,
  };
  await put('sessions', s);
  await log(a, 'SESSION_STARTED', `${c.rollNo} on ${dev.hostname}`);
  return s;
}

export async function startSessionForStudent(user, candidateId) {
  if (user.role !== 'student' || user.candidateId !== candidateId) fail('You can only start your own assigned exam.');
  const c = await get('candidates', candidateId);
  if (!c) fail('Candidate record not found.');
  return openSession({ id: user.id, role: 'student' }, candidateId);
}

export async function saveAnswer(sid, qi, choice, actor = null) {
  const s = await get('sessions', sid); if (!s || s.status !== 'in_progress') fail('Session is not active.');
  if (actor && actor.role === 'student' && actor.candidateId !== s.candidateId) fail('This session belongs to another candidate.');
  if (Date.now() > s.deadline) fail('Time is up. The backend does not support automatic answer submission; this session was not changed.');
  const ex = await get('exams', s.examId);
  if (!Array.isArray(ex?.questions) || !Number.isInteger(qi) || qi < 0 || qi >= ex.questions.length ||
      !Number.isInteger(choice) || choice < 0 || choice > 3) fail('Invalid answer.');

  fail('Backend answer persistence is unavailable. The answer was not saved.');
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
  fail(`Backend answer persistence and submission are unavailable. The session was not marked submitted${auto ? ` automatically (${why || 'time expired'})` : ''}.`);
}

export async function verifyReceipt(s) {
  fail('Independent server-side receipt verification is unavailable; the receipt was not verified.');
}

export async function terminate(a, s, reason) {
  need(a, 'session.terminate'); if (s.status !== 'in_progress') fail('Only active sessions can be terminated.');
  if ((reason || '').length < 8) fail('Reason needs 8+ characters.');

  const result = await Api.closeAuthorizedExamSession(s.id, reason);
  if (result?.status !== 'closed' && result?.status !== 'already_closed')
    fail('The backend did not confirm session closure. The local session was not changed.');

  await put('sessions', { ...s, status: 'terminated', terminatedBy: a.id, terminatedReason: reason, submittedAt: Date.now() });
  await log(a, 'SESSION_TERMINATED', `${s.id}: ${reason}`);
  return 'Session terminated and recorded.';
}
