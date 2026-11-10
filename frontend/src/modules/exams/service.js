import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, genQuestions, score, assertScope, requireReason, validHttps, inScope } from '../../core/services/common';
import { verifyPolicy } from '../policies/service';
import { submitSession } from '../submissions/service';
import * as Api from '../../core/api/services';
import { listCenters as listBackendCenters } from '../centers/service';

export const TYPES = ['practice', 'internal', 'laboratory', 'midterm', 'final'];
export const LIFECYCLE = ['draft', 'configured', 'pending_approval', 'approved', 'scheduled', 'ready', 'in_progress', 'closed', 'finalized', 'cancelled'];
export const LIFECYCLE_LABEL = {
  draft: 'Draft',
  configured: 'Configured',
  pending_approval: 'Pending Approval',
  review: 'In Review',
  approved: 'Approved',
  scheduled: 'Scheduled',
  published: 'Published',
  ready: 'Ready',
  in_progress: 'In Progress',
  live: 'Live',
  closed: 'Closed',
  finalized: 'Finalized',
  cancelled: 'Cancelled',
};
export const AUTH_MODES = [
  { v: 'candidate-login', l: 'Candidate ID + account PIN' },
  { v: 'exam-token', l: 'Candidate ID + single-use desk token' },
  { v: 'proctor-verify', l: 'Candidate ID + PIN + invigilator approval' },
];
export const SUBMISSION_MODES = [
  { v: 'manual', l: 'Candidate submits manually' },
  { v: 'auto', l: 'Auto-submit at the deadline' },
  { v: 'either', l: 'Manual, auto-submit at deadline' },
];
export const ATTESTATION = [
  { v: 'none', l: 'No attestation' },
  { v: 'tpm', l: 'TPM 2.0 quote required' },
  { v: 'tpm-secureboot', l: 'TPM quote + Secure Boot chain' },
];
export const REQUIRED_CHECKS = [
  { v: 'uefi', l: 'UEFI boot capability' }, { v: 'usb', l: 'USB boot support' },
  { v: 'tpm', l: 'TPM 2.0 present and ready' }, { v: 'secureboot', l: 'Secure Boot enabled' },
  { v: 'network', l: 'Connectivity to approved origins' }, { v: 'display', l: 'Display resolution' },
  { v: 'keyboard', l: 'Keyboard and pointer' }, { v: 'battery', l: 'Power / battery state' },
  { v: 'camera', l: 'Camera (only when required)' }, { v: 'microphone', l: 'Microphone (only when required)' },
];
export const COMPATIBILITY_PROFILES = ['standard-uefi', 'secure-lab', 'legacy-bios'];
export const NAVIGATION_MODES = ['locked', 'allowlist'];
export const RECONNECT_POLICIES = ['allow-reconnect', 'resume-only', 'deny'];

export function parseQuestions(text) {
  const out = [];
  (text || '').split('\n').map((l) => l.trim()).filter(Boolean).forEach((l, i) => {
    const p = l.split('|').map((s) => clean(s, 300));
    if (p.length !== 6) fail(`Line ${i + 1}: use "Question | A | B | C | D | correct (1-4)".`);
    const n = Number(p[5]); if (!(n >= 1 && n <= 4)) fail(`Line ${i + 1}: the correct answer must be 1–4.`);
    if (new Set(p.slice(1, 5)).size < 4) fail(`Line ${i + 1}: options must be different.`);
    out.push({ q: p[0], options: p.slice(1, 5), answer: n - 1 });
  });
  return out;
}

const startOf = (v) => (typeof v === 'number' ? v : Date.parse(v));

const normalizeOrigins = (values) => {
  if (!Array.isArray(values)) fail('Origins must be provided as a list.');
  return [...new Set(values.filter((value) => String(value || '').trim()).map((value) => {
  const origin = clean(value, 200);
  let parsed;
  try { parsed = new URL(origin); } catch { fail(`Allowed origin is invalid: ${origin}`); }
  if (!validHttps(origin) || (parsed.pathname !== '/' && parsed.pathname !== '') || parsed.search || parsed.hash) {
    fail(`Allowed origin must be an HTTPS origin without a path: ${origin}`);
  }
  return parsed.origin;
  }).filter(Boolean))];
};

const integerInRange = (value, min, max, label) => {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) fail(`${label} must be an integer from ${min} to ${max}.`);
  return number;
};

const validateTimezone = (value) => {
  const timezone = clean(value, 40);
  try { new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(0); } catch { fail('Choose a valid IANA time zone.'); }
  return timezone;
};

const validateDelivery = (exam) => {
  if (!AUTH_MODES.some(({ v }) => v === exam.authMode)) fail('Choose a valid candidate authentication mode.');
  if (!SUBMISSION_MODES.some(({ v }) => v === exam.submissionMode)) fail('Choose a valid submission mode.');
  if (!NAVIGATION_MODES.includes(exam.navigation)) fail('Choose a valid navigation mode.');
  if (!RECONNECT_POLICIES.includes(exam.reconnectPolicy)) fail('Choose a valid reconnect policy.');
  if (!ATTESTATION.some(({ v }) => v === exam.attestationLevel)) fail('Choose a valid attestation level.');
  if (!COMPATIBILITY_PROFILES.includes(exam.compatibilityProfile)) fail('Choose a valid compatibility profile.');
  if (typeof exam.identityRequired !== 'boolean') fail('Identity verification selection is invalid.');
  if (!Array.isArray(exam.requiredChecks) ||
      exam.requiredChecks.some((check) => !REQUIRED_CHECKS.some(({ v }) => v === check)) ||
      new Set(exam.requiredChecks).size !== exam.requiredChecks.length) {
    fail('Required device checks contain an invalid or duplicate selection.');
  }
  if (!Array.isArray(exam.centerIds) || new Set(exam.centerIds).size !== exam.centerIds.length ||
      exam.centerIds.some((centerId) => typeof centerId !== 'string' || !centerId.trim())) {
    fail('Exam centres contain an invalid or duplicate selection.');
  }
  if (exam.navigation === 'allowlist' && exam.allowedDestinations.length === 0) {
    fail('Add at least one allowed destination or select locked navigation.');
  }
  if (exam.allowedDestinations.some((destination) => !exam.origins.includes(destination))) {
    fail('Every allowed destination must also appear in the allowed origins.');
  }
};

const backendExamConfig = (exam) => ({
  title: exam.title, code: exam.code, type: exam.type, course: exam.course || '',
  departmentId: exam.departmentId || '', academicYear: exam.academicYear || '',
  description: exam.description || '', startAt: exam.startAt, durationMin: exam.durationMin,
  centerIds: exam.centerIds || [], timezone: exam.timeZone || 'Asia/Kolkata',
  lateEntryMin: exam.lateEntryMin || 0, capacity: exam.capacity || 0,
  instructions: exam.instructions || '', resources: exam.resources || '',
  accommodations: exam.accommodations || '', authMode: exam.authMode || 'candidate-login',
  identityRequired: !!exam.identityRequired, origins: exam.origins || [],
  navigation: exam.navigation || 'locked', allowedDestinations: exam.allowedDestinations || [],
  compatibilityProfile: exam.compatibilityProfile || 'standard-uefi',
  attestationLevel: exam.attestationLevel || 'tpm', sessionTimeoutMin: exam.sessionTimeoutMin || 15,
  reconnectPolicy: exam.reconnectPolicy || 'allow-reconnect', submissionMode: exam.submissionMode || 'either',
  requiredChecks: exam.requiredChecks || [], policyId: exam.policyId || null, examUrl: exam.examUrl || '',
});

export async function createExam(a, input) {
  need(a, 'exam.manage');
  const {
    tenantId, code, title, type = 'internal', centerIds = [], startAt, durationMin = 60, policyId = null,
    examUrl = '', questionsText = '', generate = 0, description = '', course = '', departmentId = '', academicYear = '',
    timeZone = 'Asia/Kolkata', lateEntryMin = 0, capacity = 0, instructions = '', resources = '',
    accommodations = '', authMode = 'candidate-login', identityRequired = true, origins = [],
    navigation = 'locked', allowedDestinations = [], compatibilityProfile = 'standard-uefi',
    attestationLevel = 'tpm', sessionTimeoutMin = 15, reconnectPolicy = 'allow-reconnect',
    submissionMode = 'either', requiredChecks = ['uefi', 'usb', 'tpm', 'network', 'display', 'keyboard'],
  } = input;
  assertScope(a, tenantId);
  if (typeof identityRequired !== 'boolean') fail('Identity verification selection is invalid.');
  const c = clean(code, 20).toUpperCase(); const t = clean(title, 100);
  if (!/^[A-Z0-9-]{4,20}$/.test(c)) fail('Code: 4–20 letters, digits or -.');
  if (t.length < 4) fail('Title needs 4+ characters.');
  if (!TYPES.includes(type)) fail('Choose a valid exam type.');
  if (!AUTH_MODES.some((mode) => mode.v === authMode)) fail('Choose a valid candidate authentication mode.');
  /* Duplicate code check is enforced server-side (409 on duplicate code). */
  if (!Array.isArray(centerIds)) fail('Exam centres must be provided as a list.');
  if (!Array.isArray(origins)) fail('Allowed origins must be provided as a list.');
  if (!Array.isArray(allowedDestinations)) fail('Allowed destinations must be provided as a list.');
  if (!Array.isArray(requiredChecks)) fail('Required device checks must be provided as a list.');
  const ids = centerIds;
  const st = startOf(startAt);
  const dur = integerInRange(durationMin, 15, 300, 'Duration');
  if (!Number.isFinite(st)) fail('Choose a start date and time.');
  if (!instructions.trim()) fail('Candidate instructions are required.');
  const targetInput = clean(examUrl || input.examUrl, 500);
  const targetUrl = (() => { try { return new URL(targetInput).href; } catch { return targetInput; } })();
  if (!validHttps(targetUrl)) fail('Exam URL must be a valid HTTPS URL.');
  const targetOrigin = new URL(targetUrl).origin;
  const allowedOrigins = normalizeOrigins([...origins.filter(Boolean), targetOrigin]);
  const destinations = normalizeOrigins(allowedDestinations);
  if (destinations.some((destination) => !allowedOrigins.includes(destination))) {
    fail('Every allowed destination must also appear in the allowed origins.');
  }
  const timezone = validateTimezone(timeZone);
  const lateEntry = integerInRange(lateEntryMin, 0, 60, 'Late entry');
  const plannedCapacity = integerInRange(capacity, 0, 1000000, 'Planned capacity');
  const timeout = integerInRange(sessionTimeoutMin, 5, 120, 'Session timeout');
  const normalizedDepartmentId = clean(departmentId, 64);
  const config = {
    description: clean(description, 1000), course: clean(course, 80), departmentId: normalizedDepartmentId,
    startAt: st, durationMin: dur, centerIds: ids, timezone,
    lateEntryMin: lateEntry, capacity: plannedCapacity,
    resources: clean(resources, 1000), accommodations: clean(accommodations, 1000),
    authMode, identityRequired, origins: allowedOrigins,
    navigation, allowedDestinations: destinations,
    compatibilityProfile, attestationLevel,
    sessionTimeoutMin: timeout, reconnectPolicy, submissionMode,
    requiredChecks,
  };
  validateDelivery(config);
  if (policyId) {
    const policy = (await all('policies')).find((candidate) => candidate.id === policyId);
    if (!policy || policy.tenantId !== tenantId || policy.status !== 'published') {
      fail('Select a published policy belonging to this institution.');
    }
    if (!(Array.isArray(policy.config?.origins) ? policy.config.origins : []).some((value) => {
      try { return new URL(value).origin === targetOrigin; } catch { return value === targetOrigin; }
    })) fail(`The selected policy does not allow the exam URL origin ${targetOrigin}.`);
  }
  const now = Date.now();
  const ex = {
    id: id('exm'), tenantId, code: c, title: t, description: config.description, course: config.course, departmentId: normalizedDepartmentId, academicYear: clean(academicYear, 20),
    type, centerIds: ids, startAt: st, durationMin: dur, timeZone: config.timezone, lateEntryMin: config.lateEntryMin, capacity: config.capacity,
    instructions: clean(instructions, 3000), resources: clean(resources, 1000), accommodations: clean(accommodations, 1000),
    examUrl: targetUrl,
    authMode, identityRequired, origins: allowedOrigins,
    navigation: config.navigation, allowedDestinations: config.allowedDestinations,
    compatibilityProfile, attestationLevel, sessionTimeoutMin: timeout,
    reconnectPolicy, submissionMode, requiredChecks,
    policyId: policyId || null, questions: [], status: 'draft', createdBy: a.id, createdAt: now, updatedAt: now,
    version: 1, locked: false,
    history: [{ at: now, by: a.id, to: 'draft', note: 'Exam created with assessment URL' }],
  };
  try {
    const backendRes = await Api.createExamination({
      title: t,
      name: t,
      course: clean(course, 80) || 'General',
      subject: clean(course, 80) || 'General',
      code: c,
      academicYear: clean(academicYear, 20) || '',
      examType: type,
      durationMinutes: dur,
      totalMarks: 100,
      passingMarks: 40,
      instructions: clean(instructions, 3000),
      institutionId: tenantId,
      examUrl: targetUrl,
      allowedOrigins: allowedOrigins.join(','),
      examConfig: backendExamConfig(ex),
    });
    if (!backendRes?.exam_id) fail('Backend did not return an exam ID. Cannot create exam without server confirmation.');
    ex.id = backendRes.exam_id;
  } catch (err) {
    fail(err.message || 'Backend exam creation failed. Exam not saved.');
  }
  await put('exams', ex);
  await log(a, 'EXAM_CREATED', `${c} url=${targetUrl}`);
  return `Exam ${c} saved as draft with assessment URL ${targetUrl}.`;
}

export async function updateExam(a, ex, patch) {
  need(a, 'exam.manage'); assertScope(a, ex.tenantId);
  if (['live', 'closed'].includes(ex.status)) fail('Critical settings are locked while the exam is live or closed.');
  const next = { ...ex };
  const set = (k, v) => { next[k] = v; };
  if (patch.code !== undefined) {
    const c = clean(patch.code, 20).toUpperCase();
    if (!/^[A-Z0-9-]{4,20}$/.test(c)) fail('Code: 4–20 letters, digits or -.');
    /* Duplicate code check enforced server-side (409 on duplicate). */
    set('code', c);
  }
  if (patch.title !== undefined) { const t = clean(patch.title, 100); if (t.length < 4) fail('Title needs 4+ characters.'); set('title', t); }
  if (patch.type !== undefined) { if (!TYPES.includes(patch.type)) fail('Choose a valid exam type.'); set('type', patch.type); }
  if (patch.startAt !== undefined) { const st = startOf(patch.startAt); if (!Number.isFinite(st) || st <= 0) fail('Set a valid exam start date and time before saving.'); set('startAt', st); }
  if (patch.durationMin !== undefined) { const d = Number(patch.durationMin); if (!(d >= 15 && d <= 300)) fail('Duration must be 15–300 minutes.'); set('durationMin', d); }
  if (patch.authMode !== undefined && !AUTH_MODES.some((mode) => mode.v === patch.authMode)) fail('Choose a valid candidate authentication mode.');
  for (const k of ['description', 'course', 'academicYear', 'instructions', 'resources', 'accommodations', 'timeZone', 'compatibilityProfile', 'authMode', 'submissionMode', 'reconnectPolicy']) if (patch[k] !== undefined) set(k, clean(patch[k], k === 'instructions' ? 3000 : 1000));
  for (const k of ['departmentId', 'policyId', 'navigation', 'attestationLevel', 'lateEntryMin', 'capacity', 'sessionTimeoutMin', 'identityRequired']) if (patch[k] !== undefined) set(k, patch[k]);
  if (patch.centerIds !== undefined) {
    const ids = patch.centerIds;
    /* Center scope is validated server-side on exam assignment. */
    set('centerIds', ids);
  }
  if (patch.origins !== undefined) set('origins', (Array.isArray(patch.origins) ? patch.origins : String(patch.origins).split(/[\s,]+/)).filter(Boolean));
  if (patch.allowedDestinations !== undefined) set('allowedDestinations', (Array.isArray(patch.allowedDestinations) ? patch.allowedDestinations : String(patch.allowedDestinations).split(/[\s,]+/)).filter(Boolean));
  if (patch.requiredChecks !== undefined) set('requiredChecks', patch.requiredChecks);
  if (patch.examUrl !== undefined) set('examUrl', clean(patch.examUrl, 500));
  if (patch.instructions !== undefined && !String(patch.instructions).trim()) fail('Candidate instructions are required.');
  if (!validHttps(next.examUrl)) fail('Exam URL must be a valid HTTPS URL.');
  if (typeof next.identityRequired !== 'boolean') fail('Identity verification selection is invalid.');
  next.departmentId = clean(next.departmentId, 64);
  next.examUrl = new URL(next.examUrl).href;
  next.durationMin = integerInRange(next.durationMin, 15, 300, 'Duration');
  next.lateEntryMin = integerInRange(next.lateEntryMin, 0, 60, 'Late entry');
  next.capacity = integerInRange(next.capacity, 0, 1000000, 'Planned capacity');
  next.sessionTimeoutMin = integerInRange(next.sessionTimeoutMin, 5, 120, 'Session timeout');
  next.timeZone = validateTimezone(next.timeZone);
  {
    const targetOrigin = new URL(next.examUrl).origin;
    const currentOrigins = Array.isArray(next.origins) ? next.origins : [];
    next.origins = normalizeOrigins([...currentOrigins, targetOrigin]);
    next.allowedDestinations = normalizeOrigins(next.allowedDestinations || []);
    validateDelivery(next);
    if (next.policyId) {
      const policy = (await all('policies')).find((candidate) => candidate.id === next.policyId);
      if (!policy || policy.tenantId !== ex.tenantId || policy.status !== 'published') {
        fail('Select a published policy belonging to this institution.');
      }
      if (!(Array.isArray(policy.config?.origins) ? policy.config.origins : []).some((value) => {
        try { return new URL(value).origin === targetOrigin; } catch { return value === targetOrigin; }
      })) fail(`The selected policy does not allow the exam URL origin ${targetOrigin}.`);
    }
  }
  next.updatedAt = Date.now(); next.version = (ex.version || 1) + 1;
  next.history = [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, note: 'Configuration updated' }];
  // Backend-first: update on server before writing locally.
  try {
    await Api.updateExamination(ex.id, {
      name: next.title,
      code: next.code,
      subject: next.course || '',
      academic_year: next.academicYear || '',
      exam_type: next.type,
      instructions: next.instructions || '',
      exam_url: next.examUrl || '',
      duration_minutes: next.durationMin,
      total_marks: next.totalMarks,
      passing_marks: next.passingMarks,
      allowed_origins: next.origins.join(','),
      policy_id: next.policyId || '',
      exam_config_json: JSON.stringify(backendExamConfig(next)),
    });
  } catch (err) {
    fail(err.message || 'Backend exam update failed. Changes not saved.');
  }
  await put('exams', next);
  await log(a, 'EXAM_UPDATED', `${next.code} v${next.version}`);
  return 'Exam configuration saved.';
}

export async function duplicateExam(a, ex) {
  need(a, 'exam.manage'); assertScope(a, ex.tenantId);
  const code = `${ex.code}-C${Math.floor(Math.random() * 90 + 10)}`.slice(0, 20).toUpperCase();
  const now = Date.now();
  const copy = {
    ...ex, code, title: `${ex.title} (copy)`.slice(0, 100), status: 'draft',
    questions: (ex.questions || []).map((q) => ({ ...q })), createdBy: a.id,
    createdAt: now, updatedAt: now, version: 1, publishedAt: null, publishedBy: null,
    approvedBy: null, liveAt: null, closedAt: null, summary: null, locked: false,
    history: [{ at: now, by: a.id, to: 'draft', note: `Duplicated from ${ex.code}` }],
  };
  // Backend-first: create duplicate on server.
  try {
    const res = await Api.createExamination({
      title: copy.title, name: copy.title, code,
      subject: copy.course || 'General', course: copy.course || 'General',
      academicYear: copy.academicYear || '',
      examType: copy.type, durationMinutes: copy.durationMin,
      totalMarks: 100, passingMarks: 40,
      instructions: copy.instructions || '',
      institutionId: ex.tenantId,
      examUrl: copy.examUrl || '',
      allowedOrigins: (copy.origins || []).join(','),
      examConfig: backendExamConfig(copy),
    });
    if (!res?.exam_id) fail('Backend did not return an exam ID for the duplicate.');
    copy.id = res.exam_id;
  } catch (err) {
    fail(err.message || 'Backend duplicate exam creation failed.');
  }
  await put('exams', copy);
  await log(a, 'EXAM_DUPLICATED', `${ex.code} -> ${code}`);
  return copy;
}

const FLOW = {
  draft: ['configured', 'review', 'pending_approval', 'cancelled'],
  configured: ['draft', 'pending_approval', 'review', 'cancelled'],
  pending_approval: ['configured', 'approved', 'draft', 'cancelled'],
  review: ['draft', 'pending_approval', 'approved', 'cancelled'],
  approved: ['scheduled', 'published', 'draft', 'cancelled'],
  scheduled: ['ready', 'in_progress', 'live', 'approved', 'cancelled'],
  published: ['ready', 'in_progress', 'live', 'approved', 'cancelled'],
  ready: ['in_progress', 'live', 'cancelled'],
  in_progress: ['closed'],
  live: ['closed'],
  closed: ['finalized'],
  finalized: [],
  cancelled: [],
};
const PERM = {
  draft: 'exam.manage',
  configured: 'exam.manage',
  pending_approval: 'exam.manage',
  review: 'exam.manage',
  approved: 'exam.approve',
  scheduled: 'exam.manage',
  published: 'exam.manage',
  ready: 'exam.operate',
  in_progress: 'exam.operate',
  live: 'exam.operate',
  closed: 'exam.operate',
  finalized: 'exam.manage',
  cancelled: 'exam.manage'
};
export const nextSteps = (s) => FLOW[s] || [];

export function conflicts(exams, ex) {
  const end = ex.startAt + ex.durationMin * 60000;
  return exams.find((o) => o.id !== ex.id && ['published', 'live'].includes(o.status) && o.centerIds.some((c) => ex.centerIds.includes(c)) && o.startAt < end && ex.startAt < o.startAt + o.durationMin * 60000);
}

export async function readiness(ex, ctx = {}) {
  // Try to get live data from backend for accuracy; fall back to local collections.
  let backendStatus = null;
  try {
    backendStatus = await Api.getExaminationStatus(ex.id);
  } catch { /* offline fallback */ }

  const [liveCenters, assignments, studentResponse, examinationResponse, deviceResponse] = await Promise.all([
    ctx.centers ? Promise.resolve(ctx.centers) : listBackendCenters(ex.tenantId),
    Api.listExaminationStudents(ex.id),
    Api.listStudents(),
    Api.listExaminations(),
    Api.listRegisteredDevices(),
  ]);
  const policies = ctx.policies || await all('policies');
  const rawExams = examinationResponse?.examinations || examinationResponse?.exams || [];
  const exams = ctx.exams || rawExams.map((exam) => {
    let config = exam.exam_config || {};
    if (typeof config === 'string') {
      try { config = JSON.parse(config); } catch { config = {}; }
    }
    return {
      ...exam,
      id: exam.id || exam.exam_id,
      tenantId: exam.institution_id,
      centerIds: Array.isArray(config.centerIds) ? config.centerIds : [],
      startAt: config.startAt || exam.scheduled_start || 0,
      durationMin: config.durationMin || exam.duration_minutes || 60,
    };
  });
  if (!Array.isArray(studentResponse?.students) || !Array.isArray(rawExams) ||
      !Array.isArray(deviceResponse?.devices)) {
    throw new Error('Readiness data returned an invalid student, exam, or device list.');
  }
  const devices = deviceResponse.devices;
  const scopedDevices = devices.filter((device) =>
    (device.institution_id || device.tenantId) === ex.tenantId);
  const checksFor = (key, label) => ({ key, label });
  const checks = [];
  const candidatesById = new Map((studentResponse?.students || []).map((student) => [student.id, {
    ...student,
    identity: (student.verification_status || '').toLowerCase() === 'verified' ? 'verified' : 'pending',
  }]));
  const cands = assignments.map((assignment) => ({
    ...candidatesById.get(assignment.student_id),
    id: assignment.student_id,
    examId: ex.id,
    centerId: assignment.center_id,
    seat: assignment.seat_no,
    rollNo: assignment.roll_no,
    name: assignment.name,
  }));
  const centerIds = Array.isArray(ex.centerIds) ? ex.centerIds : [];
  const configuredCenters = centerIds.map((centerId) => liveCenters.find((center) => center.id === centerId));
  const pol = policies.find((p) => p.id === ex.policyId);

  // 1. URL format — is a URL present at all?
  const urlPresent = !!ex.examUrl?.trim();
  checks.push({ ...checksFor('examUrl', 'Assessment URL present'), status: urlPresent ? 'PASS' : 'FAIL', detail: urlPresent ? ex.examUrl.slice(0, 45) : 'No URL assigned — required before publication' });

  // 2. URL vs policy — QA-E2E-001: a URL that passes format check can still be
  //    blocked by the kiosk firewall default-deny rule if the policy does not list
  //    the origin explicitly. Check both here so readiness and policy agree.
  if (urlPresent && pol) {
    let urlOriginPermitted = false;
    try {
      const urlObj = new URL(ex.examUrl);
      const urlOrigin = urlObj.origin; // e.g. https://exam.university.edu
      const policyOrigins = pol.config?.origins || [];
      urlOriginPermitted = policyOrigins.some((o) => {
        try { return new URL(o).origin === urlOrigin; } catch { return o === urlOrigin; }
      });
    } catch { /* malformed URL */ }
    checks.push({
      ...checksFor('urlOriginPolicy', 'Assessment URL permitted by policy'),
      status: urlOriginPermitted ? 'PASS' : 'FAIL',
      detail: urlOriginPermitted
        ? 'Origin is listed in the policy allowed-origins — kiosk will permit navigation'
        : `Origin is NOT in policy allowed-origins — the kiosk firewall will block this URL. Add ${ex.examUrl ? (() => { try { return new URL(ex.examUrl).origin; } catch { return ex.examUrl; } })() : '(URL)'} to the policy.`,
    });
  } else if (urlPresent && !pol) {
    checks.push({ ...checksFor('urlOriginPolicy', 'Assessment URL permitted by policy'), status: 'FAIL', detail: 'No policy selected — cannot verify kiosk firewall permission for this URL' });
  }

  const centersReady = centerIds.length > 0 && configuredCenters.every((center) => center?.status === 'active');
  const centerDetail = centerIds.length
    ? configuredCenters.map((center, index) => center ? `${center.code} (${center.status})` : `${centerIds[index]} not found`).join(', ')
    : 'No active centre is mapped to this exam.';
  checks.push({ ...checksFor('centers', 'Exam centres'), status: centersReady ? 'PASS' : 'FAIL', detail: centerDetail });
  checks.push({ ...checksFor('candidates', 'Candidate list'), status: cands.length ? 'PASS' : 'FAIL', detail: `${cands.length} assigned` });
  checks.push({ ...checksFor('identity', 'Identity verification'), status: cands.length && cands.every((c) => c.identity === 'verified') ? 'PASS' : cands.some((c) => c.identity === 'verified') ? 'WARN' : 'NOT_RUN', detail: `${cands.filter((c) => c.identity === 'verified').length}/${cands.length} verified` });
  const policyReady = !!pol && pol.status === 'published' && await verifyPolicy(pol);
  checks.push({ ...checksFor('policy', 'Published policy'), status: policyReady ? 'PASS' : 'FAIL', detail: pol ? `${pol.name} v${pol.version} (${pol.status})` : 'No policy selected' });
  checks.push({ ...checksFor('instructions', 'Candidate instructions'), status: ex.instructions?.trim() ? 'PASS' : 'WARN', detail: ex.instructions?.trim() ? 'Provided' : 'Not written — required before publication' });
  checks.push({ ...checksFor('schedule', 'Schedule conflict'), status: conflicts(exams, ex) ? 'FAIL' : 'PASS', detail: conflicts(exams, ex) ? `Conflicts with ${conflicts(exams, ex).code}` : 'No conflict' });
  const examCampusIds = new Set(liveCenters
    .filter((center) => centerIds.includes(center.id))
    .flatMap((center) => [center.id, center.campusId].filter(Boolean)));
  const devicesInScope = scopedDevices.filter((device) =>
    examCampusIds.has(device.centerId || device.center_id || device.campusId || device.campus_id));
  checks.push({
    ...checksFor('devices', 'Device readiness'),
    status: 'NOT_RUN',
    detail: `${devicesInScope.length} device(s) are registered in the exam centre scope; the device inventory does not establish current attestation trust.`,
  });
  // Live session monitoring from backend if available
  if (backendStatus?.attempts) {
    const a = backendStatus.attempts;
    checks.push({ ...checksFor('sessions', 'Live sessions'), status: 'INFO', detail: `in_progress: ${a.in_progress || 0}, submitted: ${a.submitted || 0}, interrupted: ${a.interrupted || 0}` });
  }
  return checks;
}

export async function transition(a, ex, to, reason = '') {
  need(a, PERM[to]);
  assertScope(a, ex.tenantId);
  await assertCurrent(ex);
  if (!FLOW[ex.status]?.includes(to)) fail(`Cannot move from ${ex.status} to ${to}.`);
  const next = { ...ex };
  if (to === 'review') {
    if (!ex.examUrl?.trim()) fail('Assign a valid Exam URL before submitting for review.');
    if (!ex.centerIds?.length) fail('Select at least one center.');
    if (!ex.policyId) fail('Select an exam policy.');
    if (ex.startAt && ex.startAt < Date.now() - 24 * 3600e3) fail('Start time is in the past.');
  }
  if (to === 'approved' && ex.createdBy === a.id) fail('The creator cannot approve their own exam (separation of duties).');
  if (to === 'published') {
    if (!ex.instructions?.trim()) fail('Candidate instructions are required before publication.');
    /* Policy and candidate validation is enforced server-side. */
    next.publishedAt = Date.now(); next.publishedBy = a.id;
  }
  if (to === 'live') {
    if (!next.publishedAt) fail('Publish the exam before going live.');
    const early = Date.now() < (ex.startAt || 0) - 30 * 60000;
    if (early && reason.length < 8) fail('The window opens 30 minutes before start. Give a reason (8+ chars) to start early.');
    next.liveAt = Date.now(); if (early) next.earlyReason = clean(reason, 200); next.locked = true;
  }
  if (to === 'closed') {
    /* Session collection and scoring is handled server-side via closeExamination. */
    next.closedAt = Date.now(); next.locked = true;
  }
  if (to === 'cancelled') {
    if ((reason || '').length < 8) fail('Cancelling an exam needs a recorded reason of 8+ characters.');
    next.cancelledAt = Date.now(); next.cancelReason = clean(reason, 300);
  }
  if (to === 'draft') next.locked = false;
  next.approvedBy = to === 'approved' ? a.id : next.approvedBy;
  next.status = to; next.updatedAt = Date.now();
  next.history = [...(ex.history || []), { at: Date.now(), by: a.id, to, reason: clean(reason, 300) }];

  // Backend-first: lifecycle transition must succeed on the server before local state advances.
  try {
    if (to === 'configured') {
      await Api.updateExamination(ex.id, { status: 'configured' });
    } else if (to === 'pending_approval' || to === 'review') {
      await Api.submitExaminationForApproval(ex.id);
    } else if (to === 'approved') {
      await Api.approveExamination(ex.id);
    } else if (to === 'scheduled' || to === 'published') {
      await Api.publishExamination(ex.id);
    } else if (to === 'ready') {
      await Api.readyExamination(ex.id);
    } else if (to === 'in_progress' || to === 'live') {
      await Api.startExamination(ex.id);
    } else if (to === 'closed') {
      await Api.closeExamination(ex.id);
    } else if (to === 'finalized') {
      await Api.finalizeExamination(ex.id);
    } else if (to === 'cancelled') {
      await Api.cancelExamination(ex.id, reason);
    } else if (to === 'draft') {
      await Api.updateExamination(ex.id, { status: 'draft' });
    }
  } catch (err) {
    fail(err.message || `Backend rejected lifecycle transition to '${to}'.`);
  }

  await put('exams', next);
  await log(a, 'EXAM_' + to.toUpperCase(), `${ex.code}${reason ? ': ' + reason : ''}`);
  await notifyExam(a, next, to, reason);
  return `${ex.code} is now ${to}.`;
}

async function assertCurrent(ex) {
  /* Check current status from backend to prevent stale-state transitions. */
  try {
    const res = await Api.getExaminationStatus(ex.id);
    const liveStatus = res?.status || (await Api.getExamination(ex.id))?.examination?.status;
    if (liveStatus && liveStatus !== ex.status) fail(`The exam status changed to ${liveStatus}. Reload and try again.`);
  } catch (err) {
    if (err?.message?.includes('status changed')) throw err;
    /* If the backend is unreachable, proceed — server will reject if state is wrong */
  }
}
async function notifyExam(a, ex, to, reason) {
  try {
    const n = await import('../notifications/service');
    await n.broadcast({ tenantId: ex.tenantId, title: `Exam ${ex.code} is now ${LIFECYCLE_LABEL[to] || to}`, body: `${ex.title}${reason ? ' · ' + reason : ''}`, link: `/college/exams/${ex.id}`, role: 'student', tone: to === 'cancelled' ? 'danger' : 'info' });
  } catch { /* notifications are best-effort */ }
}

export async function postponeExam(a, ex, startAt, reason) {
  need(a, 'exam.manage'); assertScope(a, ex.tenantId);
  if (!['review', 'approved', 'published'].includes(ex.status)) fail('Only draft-review, approved or published exams can be postponed.');
  const st = startOf(startAt); if (!Number.isFinite(st)) fail('Choose a new start time.');
  if (st < Date.now()) fail('The new start time must be in the future.');
  const r = requireReason(reason, 8);
  // Backend-first: update schedule on server.
  try {
    await Api.updateExamination(ex.id, { scheduled_start: st, start_time: st });
  } catch (err) {
    fail(err.message || 'Backend postpone failed. Schedule not updated.');
  }
  const next = { ...ex, startAt: st, updatedAt: Date.now(), history: [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, reason: `Postponed: ${r}` }] };
  await put('exams', next);
  await log(a, 'EXAM_POSTPONED', `${ex.code} -> ${new Date(st).toISOString()}: ${r}`);
  await notifyExam(a, next, 'postponed', r);
  return `Exam moved to ${new Date(st).toLocaleString('en-IN')}. Candidates should be notified.`;
}

export async function configureExamPolicy(a, ex, config, publish = false, reason = '') {
  need(a, 'exam.policy'); assertScope(a, ex.tenantId);
  const publicationReason = publish ? requireReason(reason, 8) : '';
  const { createPolicy, requestPolicyPublication, validateConfig } = await import('../policies/service');
  const rules = (await all('rules')).filter((r) => r.tenantId === ex.tenantId);
  const normalized = {
    requireTpm: !!config.requireTpm, kioskLockdown: !!config.kioskLockdown, allowUsb: !!config.allowUsb,
    onViolation: config.onViolation || 'Warn candidate & log',
    origins: (Array.isArray(config.origins) ? config.origins : String(config.origins || '').split(/[\s,]+/)).filter(Boolean),
  };
  const errs = validateConfig(normalized, rules);
  if (errs.length) fail(errs.join(' '));
  for (const o of normalized.origins) if (!validHttps(o)) fail(`${o} is not a valid https origin.`);
  const name = `exam-${ex.code.toLowerCase()}-policy`;
  const draft = await createPolicy(a, { tenantId: ex.tenantId, name, ...normalized });
  if (!publish) {
    const next = { ...ex, draftPolicyId: draft.id, updatedAt: Date.now(), history: [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, note: `Exam policy draft v${draft.version}` }] };
    await put('exams', next); await log(a, 'EXAM_POLICY_DRAFTED', `${ex.code} ${name} v${draft.version}`);
    return draft;
  }
  const request = await requestPolicyPublication(a, draft.id, publicationReason);
  const next = { ...ex, draftPolicyId: draft.id, policyApprovalRequestId: request.id, updatedAt: Date.now(), history: [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, note: `Exam policy v${draft.version} publication requested`, reason: clean(reason, 200) }] };
  await put('exams', next); await log(a, 'EXAM_POLICY_PUBLICATION_REQUESTED', `${ex.code} ${name} v${draft.version}: ${request.id}`);
  return { ...draft, status: 'pending_approval', approvalRequestId: request.id };
}

export async function policyPreview(ex, draft) {
  if (!draft?.config && !ex?.policyId) return null;
  const cfg = draft?.config || (await get('policies', ex.policyId))?.config;
  if (!cfg) return null;
  return {
    browser: {
      'allowed_origins': cfg.origins,
      'navigation': ex.navigation,
      'clipboard': cfg.kioskLockdown ? 'blocked' : 'allowed',
      'screen_capture': cfg.kioskLockdown ? 'blocked' : 'allowed',
      'usb_storage': cfg.allowUsb ? 'allowed' : 'blocked',
      'attestation': cfg.requireTpm ? ex.attestationLevel : 'none',
    },
    network: { default: 'drop', allow: cfg.origins.map((o) => { try { const u = new URL(o); return `${u.hostname}:${u.port || 443}/tcp`; } catch { return o; } }) },
  };
}

export function examCounts(exams) {
  return LIFECYCLE.reduce((o, s) => ({ ...o, [s]: exams.filter((e) => e.status === s).length }), {});
}
export { score };
