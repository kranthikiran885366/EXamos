import { clean } from '../../core/security/sanitize';
import { need, fail, log, seatLabel, assertScope, requireReason } from '../../core/services/common';
import { verifyPolicy } from '../policies/service';
import * as Api from '../../core/api/services';
import { listCenters } from '../centers/service';

export function parseCsv(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}
export const CSV_TEMPLATE = 'rollNo,name,email,course,batch,semester,section\nNQT26100001,Aarav Sharma,aarav.sharma@example.edu,BSc Computer Science,2026,1,A\nNQT26100002,Diya Nair,diya.nair@example.edu,BSc Mathematics,2026,1,B';
export const validate = ({ rollNo, name, email }) => {
  const e = [];
  if (!/^[A-Z0-9]{6,14}$/.test(rollNo)) e.push('roll number must be 6–14 letters/digits');
  if (!/^[\p{L} .'-]{2,80}$/u.test(name)) e.push('name must be 2–80 letters');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 120) e.push('email is invalid');
  return e;
};
export async function previewImport(tenantId, text) {
  if (text.length > 1_000_000) fail('File is larger than 1 MB.');
  const rows = parseCsv(text); if (rows.length < 2) fail('The CSV needs a header and at least one row.');
  const head = rows[0].map((h) => h.trim().toLowerCase()); const ix = (k) => head.indexOf(k);
  if (['rollno', 'name', 'email', 'course', 'batch', 'semester', 'section'].some((k) => ix(k) < 0)) {
    fail('Header must contain rollNo, name, email, course, batch, semester, and section.');
  }
  if (rows.length > 5001) fail('Import up to 5,000 rows at a time.');
  const valid = [], invalid = [], seen = new Set(), seenEmails = new Set();
  rows.slice(1).forEach((r, i) => {
    const c = {
      line: i + 2,
      rollNo: clean(r[ix('rollno')], 20).toUpperCase(),
      name: clean(r[ix('name')], 80),
      email: clean(r[ix('email')], 120).toLowerCase(),
      course: clean(r[ix('course')], 128),
      batch: clean(r[ix('batch')], 64),
      semester: clean(r[ix('semester')], 8),
      section: clean(r[ix('section')], 32),
    };
    const errs = validate(c);
    if (!c.course) errs.push('course is required');
    if (!c.batch) errs.push('batch is required');
    if (!/^[1-9]\d?$/.test(c.semester) || Number(c.semester) > 12) errs.push('semester must be 1–12');
    if (!c.section) errs.push('section is required');
    if (seen.has(c.rollNo)) errs.push('duplicate roll number in this file');
    if (seenEmails.has(c.email)) errs.push('duplicate email in this file');
    seen.add(c.rollNo);
    seenEmails.add(c.email);
    errs.length ? invalid.push({ line: i + 2, ...c, errs }) : valid.push(c);
  });
  if (!valid.length) return { valid, invalid, total: rows.length - 1, jobId: '' };
  const preview = await Api.previewStudentImport({
    institution_id: tenantId,
    filename: 'bulk_import.csv',
    rows: valid.map(({ rollNo, name, email, course, batch, semester, section }) => ({
      roll_no: rollNo,
      name,
      email,
      course,
      batch,
      semester,
      section,
    })),
  });
  if (!preview?.job_id) fail('Backend did not create an import preview.');
  const results = await Api.getStudentImportResults(preview.job_id);
  if (!Array.isArray(results?.results)) fail('Backend returned invalid import preview results.');
  const serverValid = [];
  for (const result of results.results) {
    const candidate = valid[result.row - 1];
    if (!candidate) continue;
    if (result.status === 'CREATED') serverValid.push(candidate);
    else invalid.push({
      ...candidate,
      errs: [result.error_reason || 'Rejected by the backend import validator.'],
    });
  }
  return { valid: serverValid, invalid, total: rows.length - 1, jobId: preview.job_id };
}
export async function commitImport(a, tenantId, valid) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  if (!valid?.jobId || !valid.valid?.length) fail('A valid backend import preview is required before importing.');
  let result;
  try {
    result = await Api.confirmStudentImport(valid.jobId);
  } catch (err) {
    fail(err.message || 'Backend bulk import failed.');
  }
  const imported = Number(result?.imported_count);
  const skipped = Number(result?.duplicate_count);
  if (result?.status !== 'completed' || !Number.isInteger(imported) || !Number.isInteger(skipped) ||
      imported < 0 || skipped < 0 || imported + skipped !== valid.valid.length) {
    fail('The backend returned an incomplete import outcome. Refresh the roster and review the import results.');
  }
  await log(a, 'CANDIDATES_IMPORTED', `${imported} imported; ${skipped} skipped after preview`);
  return skipped
    ? `${imported} candidate(s) imported; ${skipped} skipped because a duplicate appeared after preview.`
    : `${imported} candidate(s) imported.`;
}

export async function addCandidate(a, input) {
  need(a, 'candidate.manage'); assertScope(a, input.tenantId);
  const { tenantId, rollNo, name, email, personalEmail = '', phoneNumber = '', course, batch, semester, section, accommodations = '', notes = '' } = input;
  const c = { rollNo: clean(rollNo, 20).toUpperCase(), name: clean(name, 80), email: clean(email, 120).toLowerCase() };
  const errs = validate(c); if (errs.length) fail('Fix: ' + errs.join('; ') + '.');
  const courseValue = clean(course, 128);
  const batchValue = clean(batch, 64);
  const sectionValue = clean(section, 32);
  if (!courseValue) fail('Enter the candidate course or program.');
  if (!batchValue) fail('Enter the candidate batch.');
  if (!Number.isInteger(Number(semester)) || Number(semester) < 1 || Number(semester) > 12) fail('Semester must be 1–12.');
  if (!sectionValue) fail('Enter the candidate section.');
  let backendStudentId;
  try {
    const res = await Api.createStudent({
      institution_id: tenantId,
      roll_no: c.rollNo,
      name: c.name,
      display_name: c.name,
      email: c.email,
      personal_email: personalEmail,
      phone_number: phoneNumber,
      course: courseValue,
      batch: batchValue,
      semester: Number(semester),
      section: sectionValue,
      accommodations,
      notes,
    });
    backendStudentId = res?.student_id || res?.id;
    if (!backendStudentId) fail('Backend did not return a student ID.');
  } catch (err) {
    fail(err.message || 'Backend student creation failed. Candidate not saved.');
  }

  await log(a, 'CANDIDATE_ADDED', c.rollNo);
  return `${c.rollNo} added.`;
}
export async function assignToExam(a, { tenantId, examId, centerId, count }) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  const { ex, ce, students, assignedRows, freeSeats } = await assignmentContext(tenantId, examId, centerId);
  const assignmentsByStudent = new Map(assignedRows.map((assignment) => [assignment.student_id, assignment]));
  const pool = students.map((student) => ({
    ...student,
    assignment: assignmentsByStudent.get(student.id),
  })).filter((student) => !student.assignment);
  const requested = count === '' || count == null ? pool.length : Number(count);
  if (!Number.isInteger(requested) || requested < 1) fail('Enter a positive whole number of candidates.');
  if (requested > pool.length) fail(`Only ${pool.length} unassigned candidate(s) are available.`);
  const n = requested;
  if (n < 1) fail('There are no unassigned candidates.');
  if (n > freeSeats.length) fail(`Only ${freeSeats.length} free seat(s) at ${ce.code}.`);
  const selected = pool.slice(0, n);
  await persistAssignments(examId, selected, freeSeats, centerId, ex, ce);
  // Create Module 10 registration records for each newly seated student so
  // eligibility is visible in Student 360 without a separate manual step.
  await Promise.allSettled(selected.map((student) =>
    Api.registerStudentForExam(examId, { student_id: student.id, roll_no: student.roll_no, name: student.name })
  ));
  await log(a, 'CANDIDATES_ASSIGNED', `${n} -> ${ex.code} @ ${ce.code}`);
  return `${n} candidate(s) seated at ${ce.code}.`;
}

export async function assignCandidates(a, { tenantId, examId, centerId, candidateIds }) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  if (!Array.isArray(candidateIds) || !candidateIds.length) fail('Select at least one candidate.');
  const { ex, ce, students, assignedRows, freeSeats } = await assignmentContext(tenantId, examId, centerId);
  const assignmentsByStudent = new Map(assignedRows.map((assignment) => [assignment.student_id, assignment]));
  const studentsById = new Map(students.map((student) => [student.id, student]));
  const uniqueIds = [...new Set(candidateIds)];
  if (uniqueIds.length !== candidateIds.length) fail('The selected candidate list contains duplicates.');
  const pool = uniqueIds.map((id) => studentsById.get(id));
  if (pool.some((student) => !student)) fail('One or more selected candidates are not in this institution’s live roster.');
  if (pool.some((student) => assignmentsByStudent.has(student.id))) fail('One or more selected candidates are already assigned to this examination.');
  if (pool.length > freeSeats.length) fail(`Only ${freeSeats.length} free seat(s) at ${ce.code}.`);
  await persistAssignments(examId, pool, freeSeats, centerId, ex, ce);
  await log(a, 'CANDIDATES_ASSIGNED', `${pool.length} -> ${ex.code} @ ${ce.code}`);
  return `${pool.length} candidate(s) assigned to ${ce.code}.`;
}

async function assignmentContext(tenantId, examId, centerId) {
  const [examResponse, centerRows, studentResponse, assignedRows] = await Promise.all([
    Api.getExamination(examId),
    listCenters(tenantId),
    Api.listStudents(),
    Api.listExaminationStudents(examId),
  ]);
  const rawExam = examResponse?.examination || examResponse;
  if (!rawExam || (rawExam.id || rawExam.exam_id) !== examId || rawExam.institution_id !== tenantId) {
    fail('The selected exam is not available in this institution.');
  }
  let config = rawExam.exam_config || rawExam.exam_config_json || {};
  if (typeof config === 'string') {
    try { config = JSON.parse(config); } catch { config = {}; }
  }
  const ex = {
    ...rawExam,
    id: rawExam.id || rawExam.exam_id,
    tenantId: rawExam.institution_id,
    code: rawExam.code || rawExam.name || examId,
    status: rawExam.status,
    centerIds: Array.isArray(rawExam.center_ids)
      ? rawExam.center_ids
      : Array.isArray(config.centerIds) ? config.centerIds : [],
  };
  if (!['draft', 'configured', 'pending_approval', 'approved'].includes(ex.status)) {
    fail(`Exam is ${ex.status || 'unknown'}; assignments are locked.`);
  }
  const ce = centerRows.find((center) => center.id === centerId);
  if (!ce || !ex.centerIds.includes(centerId)) fail('That center is not part of this exam.');
  if (ce.status !== 'active') fail('Center is inactive.');
  if (!Number.isInteger(Number(ce.capacity)) || Number(ce.capacity) < 1) fail('The selected center has no valid seat capacity.');
  if (!Array.isArray(studentResponse?.students)) fail('The live student roster is unavailable.');
  const students = studentResponse.students.filter((student) => student.institution_id === tenantId);
  const occupied = new Set(assignedRows.filter((assignment) => assignment.center_id === centerId).map((assignment) => assignment.seat_no));
  const freeSeats = [];
  for (let i = 0; i < Number(ce.capacity); i += 1) {
    const seat = seatLabel(i);
    if (!occupied.has(seat)) freeSeats.push(seat);
  }
  return { ex, ce, students, assignedRows, freeSeats };
}

async function persistAssignments(examId, students, seats, centerId, exam, center) {
  const assigned = [];
  try {
    for (let i = 0; i < students.length; i += 1) {
      const student = students[i];
      await Api.assignExaminationStudent(examId, {
        student_id: student.id,
        roll_no: student.roll_no,
        name: student.name,
        center_id: centerId,
        seat_no: seats[i],
      });
      assigned.push(student.id);
    }
  } catch (err) {
    const rollbackErrors = [];
    for (const studentId of [...assigned].reverse()) {
      try {
        await Api.unassignExaminationStudent(examId, studentId);
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError.message || String(rollbackError));
      }
    }
    if (rollbackErrors.length) {
      fail(`Assignment stopped after ${assigned.length} successful request(s); rollback was incomplete (${rollbackErrors.length} error(s)). Refresh and reconcile the live roster before retrying.`);
    }
    fail(err.message || `Backend assignment failed for ${exam.code} at ${center.code}; earlier assignments were rolled back.`);
  }
}

export async function unassign(a, c, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const r = requireReason(reason, 8);
  try {
    await Api.unassignExaminationStudent(c.examId, c.id);
  } catch (err) {
    fail(err.message || 'Backend candidate unassignment failed. Local roster was not updated.');
  }
  await log(a, 'CANDIDATE_UNASSIGNED', `${c.rollNo}: ${r}`);
  return `${c.rollNo} removed from the exam.`;
}
export async function setIdentity(a, c, outcome, reason) {
  need(a, 'candidate.verify'); assertScope(a, c.tenantId);
  if (!['verified', 'rejected', 'exempt'].includes(outcome)) fail('Unknown identity outcome.');
  const r = requireReason(reason || (outcome === 'verified' ? 'Photo ID matched' : ''), 5);
  try {
    await Api.verifyStudentIdentity(c.id, {
      status: outcome.toUpperCase(),
      verification_type: 'document',
      notes: r,
    });
  } catch (err) {
    fail(err.message || 'Backend identity verification failed. Update not saved.');
  }
  await log(a, 'IDENTITY_' + outcome.toUpperCase(), `${c.rollNo}: ${r}`);
  return `${c.rollNo} identity marked ${outcome}.`;
}

export async function correctName(a, c, newName, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const nm = clean(newName, 80);
  if (!/^[\p{L} .'-]{2,80}$/u.test(nm)) fail('Name must be 2–80 letters.');
  const r = requireReason(reason, 8);
  try {
    const reqRes = await Api.requestStudentCorrection(c.id, {
      field_name: 'name',
      old_value: c.name,
      proposed_value: nm,
      reason: r,
      justification: r,
    });
    if (reqRes?.request_id) {
      await Api.reviewStudentCorrection(reqRes.request_id, {
        decision: 'APPROVED',
        review_notes: r,
      });
    }
  } catch (err) {
    fail(err.message || 'Backend correction request failed.');
  }
  await log(a, 'CANDIDATE_NAME_CORRECTED', `${c.rollNo}: ${r}`);
  return 'Name corrected and the change was recorded.';
}

export async function suspendStudent(a, c, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const r = requireReason(reason, 8);
  try {
    await Api.suspendStudentAccount(c.id, r);
  } catch (err) {
    fail(err.message || 'Backend suspension failed.');
  }
  await log(a, 'STUDENT_SUSPENDED', `${c.rollNo}: ${r}`);
  return `${c.rollNo} suspended.`;
}

export async function reactivateStudent(a, c, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const r = requireReason(reason, 5);
  try {
    await Api.reactivateStudentAccount(c.id, r);
  } catch (err) {
    fail(err.message || 'Backend reactivation failed.');
  }
  await log(a, 'STUDENT_REACTIVATED', `${c.rollNo}: ${r}`);
  return `${c.rollNo} reactivated.`;
}

export async function progressSemester(a, c, newSemester, section = 'A', academicYear = '2026-2027', term = 'Spring') {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const sem = Number(newSemester);
  if (!(sem >= 1 && sem <= 12)) fail('Semester must be 1–12.');
  try {
    await Api.progressStudentSemester(c.id, {
      semester: sem,
      section,
      academic_year: academicYear,
      term,
      notes: `Promoted to semester ${sem}`,
    });
  } catch (err) {
    fail(err.message || 'Backend semester progression failed.');
  }
  await log(a, 'STUDENT_PROGRESSED', `${c.rollNo} -> Sem ${sem}`);
  return `${c.rollNo} progressed to Semester ${sem}.`;
}

export async function getStudent360(c) {
  const [profile, enrollments, eligibility, devices, sessions, history] = await Promise.allSettled([
    Api.getStudentById(c.id),
    Api.getStudentEnrollments(c.id),
    Api.getStudentEligibilityProfile(c.id),
    Api.getStudentAssignedDevices(c.id),
    Api.getStudentExamSessions(c.id),
    Api.getStudentAuditHistory(c.id),
  ]);
  const values = { profile, enrollments, eligibility, devices, sessions, history };
  const value = (key, field) => {
    const result = values[key];
    if (result.status === 'rejected') return null;
    const records = result.value?.[field];
    return Array.isArray(records) ? records : null;
  };
  const errors = Object.fromEntries(Object.entries(values)
    .filter(([, result]) => result.status === 'rejected')
    .map(([key, result]) => [key, result.reason?.message || 'Backend request failed.']));
  if (profile.status === 'fulfilled' && !profile.value?.student) errors.profile = 'Backend returned no canonical student profile.';
  if (enrollments.status === 'fulfilled' && !value('enrollments', 'enrollments')) errors.enrollments = 'Backend returned an invalid enrollment response.';
  if (eligibility.status === 'fulfilled' && !value('eligibility', 'eligibility_records')) errors.eligibility = 'Backend returned an invalid eligibility response.';
  if (devices.status === 'fulfilled' && !value('devices', 'assigned_devices')) errors.devices = 'Backend returned an invalid device response.';
  if (sessions.status === 'fulfilled' && !value('sessions', 'exam_sessions')) errors.sessions = 'Backend returned an invalid session response.';
  if (history.status === 'fulfilled' && !value('history', 'history')) errors.history = 'Backend returned an invalid audit response.';
  return {
    profile: profile.status === 'fulfilled' ? profile.value?.student || null : null,
    enrollments: value('enrollments', 'enrollments') || [],
    eligibility: value('eligibility', 'eligibility_records') || [],
    devices: value('devices', 'assigned_devices') || [],
    sessions: value('sessions', 'exam_sessions') || [],
    history: value('history', 'history') || [],
    errors,
  };
}

export function readinessFor(c, ctx = {}) {
  const { devices = [], exams = [], policies = [], releases = [] } = ctx;
  const ex = exams.find((e) => e.id === c.examId);
  const dev = devices.find((d) => d.centerId === c.centerId && d.seat === c.seat);
  const pol = policies.find((p) => p.id === ex?.policyId);
  const rel = releases.find((r) => r.id === dev?.releaseId);
  const out = [];
  out.push({ key: 'assignment', label: 'Exam assignment', status: c.examId ? 'PASS' : 'FAIL', detail: ex ? `${ex.code} · seat ${c.seat}` : 'Not assigned' });
  out.push({ key: 'identity', label: 'Identity check', status: c.identity === 'verified' ? 'PASS' : c.identity === 'rejected' ? 'FAIL' : 'NOT_RUN', detail: c.identity });
  out.push({ key: 'device', label: 'Seat device', status: dev ? 'PASS' : 'FAIL', detail: dev ? dev.hostname : 'No device enrolled at this seat' });
  out.push({ key: 'trust', label: 'Device trust', status: dev?.backendTrustOutcome === 'ALLOW' ? 'PASS' : 'FAIL', detail: dev?.backendTrustOutcome === 'ALLOW' ? 'Server verified' : 'Server-verified device trust is unavailable' });
  out.push({ key: 'policy', label: 'Policy deployment', status: pol && pol.status === 'published' && dev?.policyId === pol.id ? 'PASS' : pol && dev?.policyId ? 'WARN' : 'FAIL', detail: pol ? `v${pol.version}` : 'No policy' });
  out.push({ key: 'release', label: 'Approved release', status: rel && !['revoked', 'candidate'].includes(rel.status) ? 'PASS' : 'FAIL', detail: rel?.version || 'unknown' });
  return out;
}
export const isReady = (checks) => checks.every((c) => c.status === 'PASS' || c.status === 'WARN');

export async function notifyCandidate(a, c, title, body) {
  const n = await import('../notifications/service');
  return n.broadcast({ tenantId: c.tenantId, userId: null, title, body, link: c.examId ? `/college/exams/${c.examId}/candidates` : '/college/candidates', role: 'student' });
}
export const candidateName = (cands, id) => cands.find((c) => c.id === id)?.name || '—';
export const candidateRoll = (cands, id) => cands.find((c) => c.id === id)?.rollNo || '—';
