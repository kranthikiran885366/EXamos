// Student module service — backend-first, no local IndexedDB reads.
import { fail } from '../../core/services/common';
import * as Api from '../../core/api/services';

export const STUDENT_STEPS = ['Briefing', 'Device check', 'Exam session', 'Submission'];

function epochMs(value) {
  const timestamp = Number(value);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return 0;
  return timestamp < 10000000000 ? timestamp * 1000 : timestamp;
}

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
      verification_status: s.verification_status || s.identity || '',
    };
  } catch (err) {
    fail(err.message || 'Failed to load your candidate record from the server.');
  }
}

export async function assignments(user, ctx = {}) {
  const c = await myCandidate(user);
  let examSessions;
  try {
    const res = await Api.getStudentExamSessions(user.candidateId);
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
      startAt: epochMs(s.scheduled_start || s.start_time),
      durationMin: s.duration_minutes || s.duration_min || 60,
      examUrl: s.exam_url || '',
      instructions: s.instructions || '',
    };
    const session = s.session_id ? {
      id: s.session_id || s.id,
      status: s.session_status || s.status,
      startedAt: epochMs(s.launched_at || s.start_time || s.authorized_at),
      deadline: epochMs(s.deadline || s.end_time),
      receipt: s.receipt_hash || null,
    } : null;
    const status = session?.status === 'submitted' ? 'submitted'
      : session?.status === 'closed' ? 'submitted'
      : session?.status === 'in_progress' || session?.status === 'active' ? 'in-progress'
      : ['in_progress', 'live', 'ready'].includes(exam.status) ? 'ready'
      : exam.status === 'scheduled' || exam.status === 'published' ? 'scheduled'
      : exam.status === 'cancelled' ? 'cancelled' : exam.status;
    return {
      candidate: c,
      exam: exam.id ? exam : null,
      center: s.center_id ? { id: s.center_id, code: s.center_code, name: s.center_name, city: s.center_city, status: s.center_status } : null,
      device: s.device_id ? { id: s.device_id, hostname: s.device_hostname, seat: s.seat, trust: s.device_trust, status: s.device_status } : null,
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
    startAt: epochMs(examDetail.start_time || examDetail.scheduled_start || exam.startAt),
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
    windowOpen: ['in_progress', 'live'].includes(fullExam.status) ||
      (['scheduled', 'published', 'ready'].includes(fullExam.status) &&
       (!fullExam.startAt || Date.now() >= fullExam.startAt)),
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
  const identity = String(candidate.verification_status || '').toLowerCase();
  add('identity', 'Identity verified', identity === 'verified' ? 'PASS' : identity === 'rejected' ? 'FAIL' : 'WARN', identity || 'pending');
  add('centre', 'Exam centre active', String(center?.status).toLowerCase() === 'active' ? 'PASS' : center ? 'WARN' : 'FAIL', center ? `${center.code || ''} · ${center.name || ''}` : 'No centre');
  add('device', 'Seat device attested', ['enrolled', 'active'].includes(String(device?.status).toLowerCase()) && String(device?.trust).toLowerCase() === 'attested' ? 'PASS' : 'WARN', device?.hostname || 'No device at your seat');
  add('session', 'Session available', !session || ['authorized', 'active', 'in_progress'].includes(session.status) ? 'PASS' : 'FAIL', session ? session.status : 'not started');

  const blocking = checks.filter((c) => c.status !== 'PASS');
  return { ...b, checks, blocking, ready: blocking.length === 0 && String(authResult?.status).toLowerCase() === 'authorized' };
}

export async function startMyExam(user, examId) {
  const c = await myCandidate(user);
  const d = await deviceCheck(user, examId);
  if (!d.ready) fail(`Device check is not complete: ${d.blocking.map((b) => b.label).join(', ')}.`);
  try {
    let res;
    let sessionId;
    if (d.session?.status === 'authorized') {
      res = { session: d.session };
      sessionId = d.session.id;
    } else {
      res = await Api.createAuthorizedExamSession({
        examination_id: examId,
        student_id: c.id || user.candidateId,
        device_id: d.device?.id || '',
      });
      sessionId = res?.session?.id || res?.session_id;
    }
    if (!sessionId) fail('The server did not create an exam session. The exam was not launched.');
    const launch = await Api.launchAuthorizedExamUrl(sessionId);
    if (launch?.status !== 'launch_authorized' || !launch?.exam_url) {
      fail('The server did not authorize the assessment portal launch.');
    }
    return res;
  } catch (err) {
    fail(err.message || 'Failed to start exam session on the server.');
  }
}

export async function confirmPortalSubmission(user, sessionId) {
  try {
    return await Api.closeAuthorizedExamSession(sessionId, 'candidate_confirmed_portal_submission');
  } catch (err) {
    fail(err.message || 'Unable to record the portal submission confirmation.');
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
    const res = await Api.getStudentExamSessions(user.candidateId);
    return examSessionsFromResponse(res).map((s) => ({
      id: s.session_id || s.id,
      examId: s.examination_id || s.exam_id,
      status: s.status || s.session_status,
      startedAt: epochMs(s.launched_at || s.start_time || s.authorized_at) || null,
      submittedAt: epochMs(s.closed_at || s.submitted_at) || null,
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
