import { all, get, put } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, genQuestions, score, assertScope, requireReason, validHttps, inScope } from '../../core/services/common';
import { verifyPolicy } from '../policies/service';
import { submitSession } from '../submissions/service';
import * as Api from '../../core/api/services';

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
  { v: 'candidate-login', l: 'Candidate account sign-in' },
  { v: 'exam-token', l: 'Exam token issued at the desk' },
  { v: 'proctor-verify', l: 'Invigilator identity confirmation' },
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
  const c = clean(code, 20).toUpperCase(); const t = clean(title, 100);
  if (!/^[A-Z0-9-]{4,20}$/.test(c)) fail('Code: 4–20 letters, digits or -.');
  if (t.length < 4) fail('Title needs 4+ characters.');
  if (!TYPES.includes(type)) fail('Choose a valid exam type.');
  /* Duplicate code check is enforced server-side (409 on duplicate code). */
  const ids = Array.isArray(centerIds) ? centerIds.filter(Boolean) : [];
  const st = startOf(startAt);
  const dur = Number(durationMin);
  if (!Number.isFinite(st)) fail('Choose a start date and time.');
  if (!(dur >= 15 && dur <= 300)) fail('Duration must be 15–300 minutes.');
  const targetUrl = clean(examUrl || input.examUrl, 500) || `https://assessment.sppio.io/exam/${c.toLowerCase()}`;
  const now = Date.now();
  const ex = {
    id: id('exm'), tenantId, code: c, title: t, description: clean(description, 1000), course: clean(course, 80), departmentId, academicYear: clean(academicYear, 20),
    type, centerIds: ids, startAt: st, durationMin: dur, timeZone, lateEntryMin: Math.max(0, Math.min(60, Number(lateEntryMin) || 0)), capacity: Number(capacity) || 0,
    instructions: clean(instructions, 3000), resources: clean(resources, 1000), accommodations: clean(accommodations, 1000),
    examUrl: targetUrl,
    authMode, identityRequired: !!identityRequired, origins: (origins || []).map((o) => clean(o, 200)).filter(Boolean),
    navigation: navigation === 'allowlist' ? 'allowlist' : 'locked', allowedDestinations: (allowedDestinations || []).map((o) => clean(o, 200)).filter(Boolean),
    compatibilityProfile: clean(compatibilityProfile, 40), attestationLevel, sessionTimeoutMin: Number(sessionTimeoutMin) || 15,
    reconnectPolicy, submissionMode, requiredChecks,
    policyId: policyId || null, questions: [], status: 'draft', createdBy: a.id, createdAt: now, updatedAt: now,
    version: 1, locked: false,
    history: [{ at: now, by: a.id, to: 'draft', note: 'Exam created with assessment URL' }],
  };
  let backendId = null;
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
      allowedOrigins: (origins || []).join(','),
      timezone: timeZone || '',
    });
    if (!backendRes?.exam_id) fail('Backend did not return an exam ID. Cannot create exam without server confirmation.');
    backendId = backendRes.exam_id;
  } catch (err) {
    fail(err.message || 'Backend exam creation failed. Exam not saved.');
  }
  ex.id = backendId;
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
  if (patch.startAt !== undefined) { const st = startOf(patch.startAt); if (!Number.isFinite(st)) fail('Choose a valid start time.'); set('startAt', st); }
  if (patch.durationMin !== undefined) { const d = Number(patch.durationMin); if (!(d >= 15 && d <= 300)) fail('Duration must be 15–300 minutes.'); set('durationMin', d); }
  for (const k of ['description', 'course', 'academicYear', 'instructions', 'resources', 'accommodations', 'timeZone', 'compatibilityProfile', 'authMode', 'submissionMode', 'reconnectPolicy']) if (patch[k] !== undefined) set(k, clean(patch[k], k === 'instructions' ? 3000 : 1000));
  for (const k of ['departmentId', 'policyId', 'navigation', 'attestationLevel', 'lateEntryMin', 'capacity', 'sessionTimeoutMin', 'identityRequired']) if (patch[k] !== undefined) set(k, patch[k]);
  if (patch.centerIds !== undefined) {
    const ids = patch.centerIds.filter(Boolean);
    /* Center scope is validated server-side on exam assignment. */
    set('centerIds', ids);
  }
  if (patch.origins !== undefined) set('origins', (Array.isArray(patch.origins) ? patch.origins : String(patch.origins).split(/[\s,]+/)).filter(Boolean));
  if (patch.allowedDestinations !== undefined) set('allowedDestinations', (Array.isArray(patch.allowedDestinations) ? patch.allowedDestinations : String(patch.allowedDestinations).split(/[\s,]+/)).filter(Boolean));
  if (patch.requiredChecks !== undefined) set('requiredChecks', patch.requiredChecks);
  if (patch.examUrl !== undefined) set('examUrl', clean(patch.examUrl, 500));
  next.updatedAt = Date.now(); next.version = (ex.version || 1) + 1;
  next.history = [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, note: 'Configuration updated' }];
  // Backend-first: update on server before writing locally.
  try {
    await Api.updateExamination(ex.id, {
      name: next.title,
      subject: next.course || '',
      instructions: next.instructions || '',
      exam_url: next.examUrl || '',
      duration_minutes: next.durationMin,
      total_marks: next.totalMarks,
      passing_marks: next.passingMarks,
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

  const { policies = await all('policies'), centers = await all('centers'),
          exams = await all('exams'), candidates = await all('candidates'),
          devices = await all('devices') } = ctx;
  const checksFor = (key, label) => ({ key, label });
  const checks = [];
  const cands = candidates.filter((c) => c.examId === ex.id);
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

  checks.push({ ...checksFor('centers', 'Exam centres'), status: ex.centerIds.length && ex.centerIds.every((cid) => centers.find((c) => c.id === cid)?.status === 'active') ? 'PASS' : 'FAIL', detail: `${ex.centerIds.length} centre(s)` });
  checks.push({ ...checksFor('candidates', 'Candidate list'), status: cands.length ? 'PASS' : 'FAIL', detail: `${cands.length} assigned` });
  checks.push({ ...checksFor('identity', 'Identity verification'), status: cands.length && cands.every((c) => c.identity === 'verified') ? 'PASS' : cands.some((c) => c.identity === 'verified') ? 'WARN' : 'NOT_RUN', detail: `${cands.filter((c) => c.identity === 'verified').length}/${cands.length} verified` });
  checks.push({ ...checksFor('policy', 'Published policy'), status: pol && pol.status === 'published' && (await verifyPolicy(pol)) ? 'PASS' : 'FAIL', detail: pol ? `${pol.name} v${pol.version} (${pol.status})` : 'No policy selected' });
  checks.push({ ...checksFor('instructions', 'Candidate instructions'), status: ex.instructions?.trim() ? 'PASS' : 'WARN', detail: ex.instructions?.trim() ? 'Provided' : 'Not written — required before publication' });
  checks.push({ ...checksFor('schedule', 'Schedule conflict'), status: conflicts(exams, ex) ? 'FAIL' : 'PASS', detail: conflicts(exams, ex) ? `Conflicts with ${conflicts(exams, ex).code}` : 'No conflict' });
  checks.push({ ...checksFor('devices', 'Device readiness'), status: devices.length ? 'PASS' : 'NOT_RUN', detail: `${devices.filter((d) => ex.centerIds.includes(d.centerId)).length} devices in scope` });
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
  const { createPolicy, publishPolicy, validateConfig } = await import('../policies/service');
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
  const pub = await publishPolicy(a, draft.id);
  const next = { ...ex, policyId: pub.id, updatedAt: Date.now(), history: [...(ex.history || []), { at: Date.now(), by: a.id, to: ex.status, note: `Exam policy v${pub.version} published`, reason: clean(reason, 200) }] };
  await put('exams', next); await log(a, 'EXAM_POLICY_PUBLISHED', `${ex.code} ${name} v${pub.version}`);
  return pub;
}

export async function policyPreview(ex, draft) {
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
