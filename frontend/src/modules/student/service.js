// Student module service — backend-first, no local IndexedDB reads.
import { fail } from '../../core/services/common';
import * as Api from '../../core/api/services';

export const STUDENT_STEPS = ['Briefing', 'Device check', 'Exam session', 'Submission'];

function examSessionsFromResponse(response) {
  const sessions = response?.exam_sessions ?? response?.sessions ?? response;
  if (!Array.isArray(sessions)) fail('The server returned an invalid exam-session response.');
  return sessions;
}

export async function myCandidate(user) {
  if (!user?.candidateId) fail('Your account is not linked to a candidate record. Contact your institution.');
  try {
    const res = await Api.getStudentById(user.candidateId);
    const s = res?.student || res;
    if (!s) fail('Your candidate record could not be found on the server.');
    return {
      ...s,
      id: s.id || s.student_id || user.candidateId,
      tenantId: s.tenantId || s.institution_id,
      name: s.name || s.display_name || '',
      rollNo: s.rollNo || s.roll_no || '',
      seat: s.seat || s.assigned_seat || '',
    };
  } catch (err) {
    fail(err.message || 'Failed to load your candidate record from the server.');
  }
}

export async function assignments(user, ctx = {}) {
  const c = await myCandidate(user);
  let examSessions;
  try {
    const res = await Api.getStudentExamSessions(c.id || user.candidateId);
    examSessions = examSessionsFromResponse(res);
  } catch (err) {
    fail(err.message || 'Failed to load your exam sessions from the server.');
  }

  return examSessions.map((s) => {
    const exam = {
      id: s.examination_id || s.exam_id,
      code: s.exam_code,
      title: s.exam_name || s.title,
      status: s.exam_status,
      startAt: s.scheduled_start || 0,
      durationMin: s.duration_minutes || s.duration_min || 60,
      examUrl: s.exam_url || '',
      instructions: s.instructions || '',
    };
    const session = {
      id: s.session_id || s.id,
      status: s.session_status || s.status,
      startedAt: s.launched_at || s.start_time || s.authorized_at || 0,
      deadline: s.deadline || s.end_time || 0,
      receipt: s.receipt_hash || null,
    };
    const status = session.status === 'submitted' ? 'submitted'
      : session.status === 'in_progress' || session.status === 'active' ? 'in-progress'
      : exam.status === 'in_progress' || exam.status === 'live' ? 'ready'
      : exam.status === 'scheduled' || exam.status === 'published' ? 'scheduled'
      : exam.status === 'cancelled' ? 'cancelled' : exam.status;
    return {
      candidate: c,
      exam: exam.id ? exam : null,
      center: s.center_name ? { id: s.center_id, code: s.center_code, name: s.center_name, city: s.center_city, status: s.center_status } : null,
      device: s.device_id ? { id: s.device_id, hostname: s.device_hostname, seat: s.seat, trust: s.trust_status, status: s.device_status } : null,
      session,
      policy: null,
      release: null,
      status,
    };
  }).sort((a, b) => (a.exam?.startAt || 0) - (b.exam?.startAt || 0));
}

export async function briefing(user, examId, ctx = {}) {
  const list = await assignments(user, ctx);
  const a = list.find((x) => String(x.exam?.id) === String(examId));
  if (!a) fail('This exam is not assigned to you.');
  const { exam, center, device, session } = a;
  let examDetail;
  try {
    const res = await Api.getExamination(examId);
    examDetail = res?.examination || res;
  } catch (err) {
    fail(err.message || 'Failed to load examination details from the server.');
  }

  const fullExam = {
    ...exam,
    id: examDetail.exam_id || examDetail.id || exam.id,
    code: examDetail.code || exam.code,
    title: examDetail.name || examDetail.title || exam.title,
    status: examDetail.status || exam.status,
    startAt: examDetail.start_time || examDetail.scheduled_start || exam.startAt,
    durationMin: examDetail.duration_minutes || exam.durationMin,
    instructions: examDetail.instructions || exam.instructions || '',
    resources: examDetail.resources || '',
    accommodations: examDetail.accommodations || '',
    examUrl: examDetail.exam_url || exam.examUrl || '',
  };

  return {
    ...a,
    exam: fullExam,
    lifecycle: fullExam.status,
    startsIn: (fullExam.startAt || 0) - Date.now(),
    windowOpen: fullExam.status === 'in_progress' || (fullExam.status === 'scheduled' && Date.now() >= (fullExam.startAt || 0) - 30 * 60000),
    instructions: fullExam.instructions || '',
    resources: fullExam.resources || '',
    accommodations: fullExam.accommodations || '',
    policySummary: examDetail?.os_policy ? {
      tpm: examDetail.os_policy.require_tpm,
      lockdown: examDetail.os_policy.kiosk_lockdown,
      usb: !examDetail.os_policy.block_usb,
      violation: 'Enforced',
      origins: [],
    } : null,
    device,
    session,
  };
}

export async function deviceCheck(user, examId, ctx = {}) {
  const b = await briefing(user, examId, ctx);
  const { candidate, exam, center, device, session } = b;
  const checks = [];
  const add = (key, label, status, detail) => checks.push({ key, label, status, detail });

  let authResult;
  try {
    authResult = await Api.authorizeStudentExamSession({
      examination_id: examId,
      student_id: candidate.id || user.candidateId,
      device_id: device?.id || '',
    });
  } catch (err) {
    fail(err.message || 'Unable to verify exam authorization with the server.');
  }

  if (authResult) {
    if (String(authResult.status).toLowerCase() === 'authorized') add('authorization', 'Exam authorization', 'PASS', authResult.reason || 'Authorized');
    else if (authResult.status === 'pending') add('authorization', 'Exam authorization', 'WARN', authResult.reason || 'Waiting for exam window');
    else add('authorization', 'Exam authorization', 'FAIL', authResult.reason || 'Not authorized');
  }

  add('assignment', 'Exam assignment', exam ? 'PASS' : 'FAIL', exam ? `${exam.code} · seat ${candidate.seat || 'unassigned'}` : 'No exam');
  add('identity', 'Identity verified', candidate.verification_status === 'VERIFIED' ? 'PASS' : candidate.verification_status === 'REJECTED' ? 'FAIL' : 'WARN', candidate.verification_status || 'pending');
  add('centre', 'Exam centre active', center?.status === 'active' ? 'PASS' : center ? 'WARN' : 'FAIL', center ? `${center.code || ''} · ${center.name || ''}` : 'No centre');
  add('device', 'Seat device enrolled', device?.status === 'enrolled' || device?.status === 'active' ? 'PASS' : 'WARN', device?.hostname || 'No device at your seat');
  add('session', 'No previous submission', !session || session.status === 'in_progress' || session.status === 'active' ? 'PASS' : 'FAIL', session ? session.status : 'not started');

  const blocking = checks.filter((c) => c.status !== 'PASS');
  return { ...b, checks, blocking, ready: blocking.length === 0 && ['in_progress', 'published'].includes(exam?.status) };
}

export async function startMyExam(user, examId) {
  const c = await myCandidate(user);
  const d = await deviceCheck(user, examId);
  if (!d.ready) fail(`Device check is not complete: ${d.blocking.map((b) => b.label).join(', ')}.`);
  try {
    const res = await Api.createAuthorizedExamSession({
      examination_id: examId,
      student_id: c.id || user.candidateId,
      device_id: d.device?.id || '',
    });
    return res;
  } catch (err) {
    fail(err.message || 'Failed to start exam session on the server.');
  }
}

export async function saveMyAnswer(user, sessionId, qi, choice) {
  try {
    return await Api.saveAnswer({ questionId: qi, selectedOption: choice, status: 'answered' });
  } catch (err) {
    fail(err.message || 'Failed to save your answer on the server.');
  }
}

export async function submitMyExam(user, sessionId) {
  try {
    return await Api.submitExam();
  } catch (err) {
    fail(err.message || 'Failed to submit exam on the server.');
  }
}

export async function receipt(user, sessionId) {
  try {
    const res = await Api.getExamSessionDetails(sessionId);
    const session = res?.session || res;
    return {
      id: sessionId,
      status: session?.status || null,
      receipt: session?.receipt_hash || session?.document_digest || null,
      receiptSig: session?.receipt_signature || session?.receipt_sig || null,
      answers: null,
      auto: null,
      submittedAt: session?.closed_at || session?.submitted_at || null,
      valid: session?.receipt_verified === true,
    };
  } catch (err) {
    fail(err.message || 'Failed to retrieve submission receipt from the server.');
  }
}

export async function myHistory(user, ctx = {}) {
  const c = await myCandidate(user);
  try {
    const res = await Api.getStudentExamSessions(c.id || user.candidateId);
    return examSessionsFromResponse(res).map((s) => ({
      id: s.session_id || s.id,
      examId: s.examination_id || s.exam_id,
      status: s.status || s.session_status,
      startedAt: s.launched_at || s.start_time || s.authorized_at || null,
      submittedAt: s.closed_at || s.submitted_at || null,
      receipt: s.receipt_hash || s.document_digest || null,
      receiptSig: s.receipt_signature || s.receipt_sig || null,
      valid: s.receipt_verified === true,
      exam: { id: s.examination_id || s.exam_id, code: s.exam_code, title: s.exam_name },
    })).sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));
  } catch (err) {
    fail(err.message || 'Failed to load your exam history from the server.');
  }
}

export async function requestHelp(user, { tenantId, subject, description, category = 'exam' }) {
  const { createRequest } = await import('../support/service');
  return createRequest(user, { tenantId, subject, description, category, priority: 'high', requesterName: user.name, requesterEmail: user.email });
}

export const remaining = (s, now = Date.now()) => Math.max(0, ((s?.deadline || 0) - now));
