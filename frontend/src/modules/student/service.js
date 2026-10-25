import { all, get } from '../../core/db/db';
import { fail } from '../../core/services/common';
import { startSessionForStudent, saveAnswerForStudent, submitSessionForStudent, verifyReceipt } from '../submissions/service';
import { LIFECYCLE_LABEL } from '../exams/service';
import { createRequest } from '../support/service';

export const STUDENT_STEPS = ['Briefing', 'Device check', 'Exam session', 'Submission'];

export async function myCandidate(user) {
  if (!user?.candidateId) fail('Your account is not linked to a candidate record. Contact your institution.');
  const c = await get('candidates', user.candidateId);
  if (!c) fail('Your candidate record could not be found.');
  return c;
}

export async function assignments(user, ctx = {}) {
  const { exams = await all('exams'), centers = await all('centers'), devices = await all('devices'), sessions = await all('sessions'), policies = await all('policies'), releases = await all('releases') } = ctx;
  const c = await myCandidate(user);
  const mine = (await all('candidates')).filter((x) => x.id === c.id);
  return mine.map((cand) => {
    const ex = exams.find((e) => e.id === cand.examId);
    const center = centers.find((x) => x.id === cand.centerId);
    const device = devices.find((d) => d.centerId === cand.centerId && d.seat === cand.seat);
    const session = sessions.filter((s) => s.candidateId === cand.id).sort((a, b) => b.startedAt - a.startedAt)[0] || null;
    return {
      candidate: cand, exam: ex || null, center: center || null, device: device || null, session,
      policy: policies.find((p) => p.id === ex?.policyId) || null,
      release: releases.find((r) => r.id === device?.releaseId) || null,
      status: !ex ? 'unassigned' : session?.status === 'submitted' ? 'submitted' : session?.status === 'in_progress' ? 'in-progress' : ex.status === 'live' ? 'ready' : ex.status === 'published' ? 'scheduled' : ex.status === 'cancelled' ? 'cancelled' : ex.status,
    };
  }).sort((a, b) => (a.exam?.startAt || 0) - (b.exam?.startAt || 0));
}

export async function briefing(user, examId, ctx = {}) {
  const list = await assignments(user, ctx);
  const a = list.find((x) => x.exam?.id === examId);
  if (!a) fail('This exam is not assigned to you.');
  const { exam, center, device, session, policy, release } = a;
  return {
    ...a,
    lifecycle: LIFECYCLE_LABEL[exam.status] || exam.status,
    startsIn: exam.startAt - Date.now(),
    windowOpen: exam.status === 'live' || (exam.status === 'published' && Date.now() >= exam.startAt - 30 * 60000),
    instructions: exam.instructions || '',
    resources: exam.resources || '',
    accommodations: exam.accommodations || '',
    policySummary: policy ? {
      tpm: policy.config?.requireTpm, lockdown: policy.config?.kioskLockdown,
      usb: policy.config?.allowUsb, violation: policy.config?.onViolation, origins: policy.config?.origins || [],
    } : null,
    device: device ? { hostname: device.hostname, seat: device.seat, trust: device.trust, status: device.status, release: release?.version } : null,
    session,
  };
}

export async function deviceCheck(user, examId, ctx = {}) {
  const b = await briefing(user, examId, ctx);
  const { candidate, exam, center, device, release, policy, session } = b;
  const checks = [];
  const add = (key, label, status, detail) => checks.push({ key, label, status, detail });
  add('assignment', 'Exam assignment', candidate.examId === exam.id ? 'PASS' : 'FAIL', `${exam.code} · seat ${candidate.seat || 'unassigned'}`);
  add('identity', 'Identity verified', candidate.identity === 'verified' ? 'PASS' : candidate.identity === 'rejected' ? 'FAIL' : 'WARN', candidate.identity);
  add('centre', 'Exam centre active', center?.status === 'active' ? 'PASS' : 'FAIL', center ? `${center.code} · ${center.name}` : 'No centre');
  add('device', 'Seat device enrolled', device?.status === 'enrolled' ? 'PASS' : 'FAIL', device?.hostname || 'No device at your seat');
  add('reachable', 'Device reachable', device && Date.now() - (device.lastSeen || 0) < 40000 ? 'PASS' : 'FAIL', device ? `${Math.round((Date.now() - (device.lastSeen || 0)) / 1000)}s since heartbeat` : 'unknown');
  add('isolated', 'No security isolation', device && !device.isolated ? 'PASS' : 'FAIL', device?.isolated ? 'Device isolated by policy' : 'clear');
  add('release', 'Approved release', release && release.status !== 'revoked' ? 'PASS' : 'FAIL', release ? release.version : 'unknown');
  add('policy', 'Exam policy deployed', policy && device?.policyId === policy.id ? 'PASS' : policy ? 'WARN' : 'FAIL', policy ? `${policy.name} v${policy.version}` : 'No policy');
  add('attestation', 'TPM attestation', device?.trust === 'attested' && Date.now() - (device.lastAttested || 0) < 5 * 60000 ? 'PASS' : 'FAIL', device?.trust === 'attested' ? `verified ${Math.round((Date.now() - device.lastAttested) / 1000)}s ago` : 'Run attestation');
  add('compat', 'Hardware compatibility', device?.compatStatus === 'PASS' ? 'PASS' : device?.compatStatus === 'WARN' ? 'WARN' : 'FAIL', device?.compatStatus || 'not run');
  add('session', 'No previous submission', !session || session.status === 'in_progress' ? 'PASS' : 'FAIL', session ? session.status : 'not started');
  const blocking = checks.filter((c) => c.status === 'FAIL');
  return { ...b, checks, blocking, ready: blocking.length === 0 && ['published', 'live'].includes(exam.status) };
}

export async function startMyExam(user, examId) {
  const c = await myCandidate(user);
  if (c.examId !== examId) fail('This exam is not assigned to you.');
  const d = await deviceCheck(user, examId);
  if (!d.ready) fail(`Device check is not complete: ${d.blocking.map((b) => b.label).join(', ')}.`);
  return startSessionForStudent(user, c.id);
}

export async function saveMyAnswer(user, sessionId, qi, choice) {
  return saveAnswerForStudent(user, sessionId, qi, choice);
}
export async function submitMyExam(user, sessionId) {
  return submitSessionForStudent(user, sessionId);
}
export async function receipt(user, sessionId) {
  const c = await myCandidate(user);
  const s = await get('sessions', sessionId);
  if (!s || s.candidateId !== c.id) fail('Receipt not found.');
  return { ...s, valid: await verifyReceipt(s) };
}
export async function myHistory(user, ctx = {}) {
  const c = await myCandidate(user);
  const { sessions = await all('sessions'), exams = await all('exams'), centers = await all('centers') } = ctx;
  const rows = sessions.filter((s) => s.candidateId === c.id).sort((a, b) => b.startedAt - a.startedAt);
  return Promise.all(rows.map(async (s) => ({ ...s, exam: exams.find((e) => e.id === s.examId) || null, center: centers.find((x) => x.id === (exams.find((e) => e.id === s.examId)?.centerIds || [])[0]) || null, valid: await verifyReceipt(s) })));
}
export async function requestHelp(user, { tenantId, subject, description, category = 'exam' }) {
  return createRequest(user, { tenantId, subject, description, category, priority: 'high', requesterName: user.name, requesterEmail: user.email });
}
export const remaining = (s, now = Date.now()) => Math.max(0, (s?.deadline || 0) - now);
