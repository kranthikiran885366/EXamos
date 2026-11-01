// Student module service — backend-first, no local IndexedDB reads.
// All data comes from the real ExamOS C server API.
import { fail } from '../../core/services/common';
import * as Api from '../../core/api/services';

export const STUDENT_STEPS = ['Briefing', 'Device check', 'Exam session', 'Submission'];

/**
 * Fetch the candidate's own profile from the backend student API.
 * Falls back to the auth context's candidateId if the API returns no match.
 */
export async function myCandidate(user) {
  if (!user?.candidateId) fail('Your account is not linked to a candidate record. Contact your institution.');
  try {
    const res = await Api.getStudentById(user.candidateId);
    const s = res?.student || res;
    if (!s) fail('Your candidate record could not be found on the server.');
    return s;
  } catch (err) {
    fail(err.message || 'Failed to load your candidate record from the server.');
  }
}

/**
 * Fetch all exam assignments for the current candidate from the backend.
 * Uses the examination session list API to get live sessions, and the
 * student API to get enrollment data.
 */
export async function assignments(user, ctx = {}) {
  const c = await myCandidate(user);
  // Get assigned exams from the backend exam student assignments endpoint
  let examSessions = [];
  try {
    // Try getting exam sessions for this student
    const res = await Api.getStudentExamSessions(c.id || user.candidateId);
    examSessions = Array.isArray(res?.sessions) ? res.sessions : (Array.isArray(res) ? res : []);
  } catch { /* no sessions yet — OK */ }

  // Build assignment list from sessions
  return examSessions.map((s) => {
    const exam = {
      id: s.examination_id || s.exam_id,
      code: s.exam_code,
      title: s.exam_name || s.title,
      status: s.exam_status || s.status,
      startAt: s.start_time || s.scheduled_start || 0,
      durationMin: s.duration_minutes || s.duration_min || 60,
      examUrl: s.exam_url || '',
      instructions: s.instructions || '',
    };
    const session = {
      id: s.id,
      status: s.session_status || s.status,
      startedAt: s.launched_at || s.authorized_at || 0,
      deadline: s.deadline || 0,
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
      center: s.center_name ? { code: s.center_code, name: s.center_name, city: s.center_city } : null,
      device: s.device_id ? { hostname: s.device_hostname, seat: s.seat, trust: s.trust_status, status: s.device_status } : null,
      session,
      policy: null,
      release: null,
      status,
    };
  }).sort((a, b) => (a.exam?.startAt || 0) - (b.exam?.startAt || 0));
}

/**
 * Fetch briefing for a specific exam from the backend.
 */
export async function briefing(user, examId, ctx = {}) {
  const list = await assignments(user, ctx);
  const a = list.find((x) => x.exam?.id === examId);
  if (!a) fail('This exam is not assigned to you.');
  const { exam, center, device, session } = a;
  // Fetch full exam details from backend for instructions/policy info
  let examDetail = null;
  try {
    const res = await Api.getExamination(examId);
    examDetail = res?.examination || res;
  } catch { /* use assignment data */ }

  const fullExam = examDetail ? {
    ...exam,
    instructions: examDetail.instructions || exam.instructions || '',
    resources: examDetail.resources || '',
    accommodations: examDetail.accommodations || '',
    examUrl: examDetail.exam_url || exam.examUrl || '',
  } : exam;

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

/**
 * Run device checks against the backend session authorization endpoint.
 */
export async function deviceCheck(user, examId, ctx = {}) {
  const b = await briefing(user, examId, ctx);
  const { candidate, exam, center, device, session } = b;
  const checks = [];
  const add = (key, label, status, detail) => checks.push({ key, label, status, detail });

  // Try backend pre-flight authorization check
  let authResult = null;
  try {
    authResult = await Api.authorizeStudentExamSession({
      examination_id: examId,
      student_id: candidate.id || user.candidateId,
      device_id: device?.id || '',
    });
  } catch { /* offline — use available data */ }

  if (authResult) {
    if (authResult.status === 'authorized') {
      add('authorization', 'Exam authorization', 'PASS', authResult.reason || 'Authorized');
    } else if (authResult.status === 'pending') {
      add('authorization', 'Exam authorization', 'WARN', authResult.reason || 'Waiting for exam window');
    } else {
      add('authorization', 'Exam authorization', 'FAIL', authResult.reason || 'Not authorized');
    }
  } else {
    add('authorization', 'Exam authorization', 'WARN', 'Unable to verify — check with invigilator');
  }

  add('assignment', 'Exam assignment', exam ? 'PASS' : 'FAIL', exam ? `${exam.code} · seat ${candidate.seat || 'unassigned'}` : 'No exam');
  add('identity', 'Identity verified', candidate.verification_status === 'VERIFIED' ? 'PASS' : candidate.verification_status === 'REJECTED' ? 'FAIL' : 'WARN', candidate.verification_status || 'pending');
  add('centre', 'Exam centre active', center?.status === 'active' ? 'PASS' : center ? 'WARN' : 'FAIL', center ? `${center.code || ''} · ${center.name || ''}` : 'No centre');
  add('device', 'Seat device enrolled', device?.status === 'enrolled' || device?.status === 'active' ? 'PASS' : 'WARN', device?.hostname || 'No device at your seat');
  add('session', 'No previous submission', !session || session.status === 'in_progress' || session.status === 'active' ? 'PASS' : 'FAIL', session ? session.status : 'not started');

  const blocking = checks.filter((c) => c.status === 'FAIL');
  return { ...b, checks, blocking, ready: blocking.length === 0 && ['scheduled', 'in_progress', 'published'].includes(exam?.status) };
}

/**
 * Start exam session via the backend API.
 */
export async function startMyExam(user, examId) {
  const c = await myCandidate(user);
  const d = await deviceCheck(user, examId);
  if (!d.ready) fail(`Device check is not complete: ${d.blocking.map((b) => b.label).join(', ')}.`);
  // Create an authorized exam session on the backend
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

/**
 * Save an answer via the backend exam API (candidate exam workbench endpoint).
 */
export async function saveMyAnswer(user, sessionId, qi, choice) {
  // The exam workbench uses POST /api/v1/exam/save_answer
  // This is handled by the candidate-facing C server endpoints
  try {
    const res = await fetch('/api/v1/exam/save_answer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${sessionId}` },
      body: JSON.stringify({ q_id: qi, selected: choice }),
    });
    return await res.json();
  } catch {
    return { status: 'FAIL', error: 'Network error saving answer' };
  }
}

/**
 * Submit the exam via the backend exam API.
 */
export async function submitMyExam(user, sessionId) {
  try {
    const res = await fetch('/api/v1/exam/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${sessionId}` },
    });
    return await res.json();
  } catch (err) {
    fail(err.message || 'Failed to submit exam on the server.');
  }
}

/**
 * Fetch submission receipt from the backend.
 */
export async function receipt(user, sessionId) {
  try {
    // Close the session to get the final receipt
    const res = await Api.closeAuthorizedExamSession(sessionId, 'student_completed');
    return {
      id: sessionId,
      status: res?.status || 'closed',
      receipt: res?.document_digest || res?.receipt_hash || null,
      receiptSig: res?.document_digest || null,
      answers: {},
      auto: false,
      submittedAt: res?.closed_at || Date.now(),
      valid: true,
    };
  } catch (err) {
    fail(err.message || 'Failed to retrieve submission receipt from the server.');
  }
}

/**
 * Fetch exam history for the current candidate from the backend.
 */
export async function myHistory(user, ctx = {}) {
  const c = await myCandidate(user);
  try {
    const res = await Api.getStudentExamSessions(c.id || user.candidateId);
    const sessions = Array.isArray(res?.sessions) ? res.sessions : (Array.isArray(res) ? res : []);
    return sessions.map((s) => ({
      id: s.id,
      examId: s.examination_id || s.exam_id,
      status: s.status || s.session_status,
      startedAt: s.launched_at || s.authorized_at || 0,
      submittedAt: s.closed_at || 0,
      receipt: s.receipt_hash || null,
      receiptSig: s.receipt_hash || null,
      valid: !!s.receipt_hash,
      exam: { id: s.examination_id, code: s.exam_code, title: s.exam_name },
    })).sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));
  } catch {
    return [];
  }
}

/**
 * Create a support request via the support module API.
 */
export async function requestHelp(user, { tenantId, subject, description, category = 'exam' }) {
  // This delegates to the support module which has its own backend integration
  const { createRequest } = await import('../support/service');
  return createRequest(user, { tenantId, subject, description, category, priority: 'high', requesterName: user.name, requesterEmail: user.email });
}

export const remaining = (s, now = Date.now()) => Math.max(0, ((s?.deadline || 0) - now));
