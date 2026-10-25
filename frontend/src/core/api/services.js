// ExamOS Console — Backend API service layer.
// Every function calls the real ExamOS C server (server/main.c) over HTTP.
// Responses are validated and shaped for the console UI. IndexedDB remains
// as an offline cache / fallback when the backend is unreachable.

import { api, setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens, ApiError } from './client';
import { ENDPOINTS, AUTH_TOKEN_KEY, CANDIDATE_TOKEN_KEY, CANDIDATE_ID_KEY } from '../../config/api';
import { all, get, put, del } from '../db/db';
import { sha256 } from '../security/crypto';
import { record } from '../security/auditChain';
import { audit } from '../security/auditClient';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ACTOR = 'console';

function wrap(fn) {
  return async (...args) => {
    const start = Date.now();
    try {
      const result = await fn(...args);
      try { audit.record({ actor: ACTOR, event: 'API_CALL', detail: 'ok', resource: fn.name, severity: 'info' }); } catch {}
      return result;
    } catch (err) {
      try { audit.record({ actor: ACTOR, event: 'API_CALL_ERROR', detail: String(err.message), resource: fn.name, severity: 'error' }); } catch {}
      throw err;
    }
  };
}

// Map a backend role string to a frontend role key (rbac.js keys).
export function backendRoleToFrontend(role) {
  const map = {
    PLATFORM_OWNER: 'superadmin',
    INSTITUTION_ADMIN: 'inst_admin',
    EXAM_MANAGER: 'exam_controller',
    SECURITY_ADMIN: 'security_engineer',
    INVIGILATOR: 'invigilator',
    TECH_OPERATOR: 'it_admin',
    INCIDENT_INVESTIGATOR: 'auditor',
    READONLY_AUDITOR: 'auditor',
    SUPPORT_ENGINEER: 'support',
  };
  return map[role] || role.toLowerCase();
}

// ---------------------------------------------------------------------------
// Health / status
// ---------------------------------------------------------------------------

export const health = wrap(async () => {
  const res = await api.get(ENDPOINTS.health, { actor: ACTOR, sign: false });
  return res.data;
});

export const status = wrap(async () => {
  const res = await api.get(ENDPOINTS.status, { actor: ACTOR, sign: false });
  return res.data;
});

// ---------------------------------------------------------------------------
// Admin authentication
// ---------------------------------------------------------------------------

export const adminLogin = wrap(async ({ username, password, mfaCode }) => {
  const res = await api.post(ENDPOINTS.adminLogin, {
    username, password, mfa_code: mfaCode || null,
  }, { actor: ACTOR, sign: true });

  const data = res.data;
  if (data.status === 'MFA_REQUIRED') return { mfaRequired: true };
  if (data.status !== 'AUTHENTICATED') throw new ApiError(res.status, data.error || 'Login failed', data);

  setAdminToken(data.token);
  try { sessionStorage.setItem(AUTH_TOKEN_KEY, data.token); } catch {}

  // Fetch profile.
  const profRes = await api.get(ENDPOINTS.adminSession, { actor: ACTOR });
  const profile = profRes.data;
  return {
    ok: true,
    profile: {
      userId: profile.user_id,
      username: profile.username,
      role: backendRoleToFrontend(profile.role),
      backendRole: profile.role,
      institutionId: profile.institution_id,
      expiresAt: profile.session_expires_at,
    },
    token: data.token,
  };
});

export const adminLogout = wrap(async () => {
  try { await api.post(ENDPOINTS.adminLogout, {}, { actor: ACTOR, sign: true }); } catch {}
  setAdminToken(null);
  try { sessionStorage.removeItem(AUTH_TOKEN_KEY); } catch {}
  return { ok: true };
});

export const adminProfile = wrap(async () => {
  const res = await api.get(ENDPOINTS.adminSession, { actor: ACTOR });
  const p = res.data;
  return {
    userId: p.user_id,
    username: p.username,
    role: backendRoleToFrontend(p.role),
    backendRole: p.role,
    institutionId: p.institution_id,
    expiresAt: p.session_expires_at,
  };
});

// ---------------------------------------------------------------------------
// Candidate authentication
// ---------------------------------------------------------------------------

export const candidateLogin = wrap(async ({ candidateId, pin }) => {
  const res = await api.post(ENDPOINTS.candidateLogin, {
    candidate_id: candidateId, pin,
  }, { useCandidateToken: true, actor: ACTOR, sign: true });

  const data = res.data;
  if (data.status !== 'SUCCESS') throw new ApiError(res.status, data.error || 'Candidate login failed', data);

  setCandidateToken(data.token);
  try {
    sessionStorage.setItem(CANDIDATE_TOKEN_KEY, data.token);
    sessionStorage.setItem(CANDIDATE_ID_KEY, candidateId);
  } catch {}

  return {
    ok: true,
    profile: {
      candidateId,
      examName: data.exam_name || null,
      examUrl: data.exam_url || null,
      token: data.token,
    },
  };
});

export const candidateLogout = wrap(async () => {
  setCandidateToken(null);
  try {
    sessionStorage.removeItem(CANDIDATE_TOKEN_KEY);
    sessionStorage.removeItem(CANDIDATE_ID_KEY);
  } catch {}
  return { ok: true };
});

// ---------------------------------------------------------------------------
// Institutions
// ---------------------------------------------------------------------------

export const listInstitutions = wrap(async () => {
  const res = await api.get(ENDPOINTS.institutions, { actor: ACTOR });
  return res.data;
});

export const getInstitution = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.institutionById(id), { actor: ACTOR });
  return res.data;
});

export const createInstitution = wrap(async ({ name, code, contactEmail, retentionDays }) => {
  const res = await api.post(ENDPOINTS.institutions, {
    name, code, contact_email: contactEmail, retention_days: retentionDays, active: 1,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------------

export const listUsers = wrap(async () => {
  const res = await api.get(ENDPOINTS.users, { actor: ACTOR });
  return res.data;
});

export const createUser = wrap(async ({ username, fullName, email, password, institutionId, role }) => {
  const res = await api.post(ENDPOINTS.users, {
    username, full_name: fullName, email, password, institution_id: institutionId, role, active: 1,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

export const listRoles = wrap(async () => {
  const res = await api.get(ENDPOINTS.roles, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Campuses
// ---------------------------------------------------------------------------

export const listCampuses = wrap(async ({ institutionId } = {}) => {
  const qs = institutionId ? `?institution_id=${encodeURIComponent(institutionId)}` : '';
  const res = await api.get(`${ENDPOINTS.campuses}${qs}`, { actor: ACTOR });
  return res.data;
});

export const createCampus = wrap(async ({ institutionId, name, address }) => {
  const res = await api.post(ENDPOINTS.campuses, {
    institution_id: institutionId, name, address,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

export const listRooms = wrap(async ({ campusId } = {}) => {
  const qs = campusId ? `?campus_id=${encodeURIComponent(campusId)}` : '';
  const res = await api.get(`${ENDPOINTS.rooms}${qs}`, { actor: ACTOR });
  return res.data;
});

export const createRoom = wrap(async ({ campusId, institutionId, name, supervisor, capacity }) => {
  const res = await api.post(ENDPOINTS.rooms, {
    campus_id: campusId, institution_id: institutionId, name, supervisor, capacity: Number(capacity),
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Exams (admin platform)
// ---------------------------------------------------------------------------

export const listExams = wrap(async () => {
  const res = await api.get(ENDPOINTS.exams, { actor: ACTOR });
  return res.data;
});

export const createExam = wrap(async (exam) => {
  const res = await api.post(ENDPOINTS.platformExamsCreate, {
    title: exam.title,
    institution_id: exam.institutionId,
    exam_url: exam.examUrl,
    allowed_origins: exam.allowedOrigins,
    timezone: exam.timezone,
    permitted_device_group: exam.permittedDeviceGroup,
    duration_minutes: exam.durationMinutes,
    retention_days: exam.retentionDays,
    scheduled_start: exam.scheduledStart,
    scheduled_end: exam.scheduledEnd,
    browser_policy: exam.browserPolicy,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const validateExam = wrap(async (examId) => {
  const res = await api.post(ENDPOINTS.platformExamValidate(examId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const approveExam = wrap(async (examId) => {
  const res = await api.post(ENDPOINTS.platformExamApprove(examId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateExamState = wrap(async (examId, stateName) => {
  const res = await api.post(ENDPOINTS.platformExamState(examId), { state: stateName }, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateExamUrl = wrap(async (examId, examUrl, allowedOrigins) => {
  const res = await api.post(ENDPOINTS.platformExamUrl(examId), { exam_url: examUrl, allowed_origins: allowedOrigins }, { actor: ACTOR, sign: true });
  return res.data;
});

export const scheduleExam = wrap(async (examId, timezone, startTime, endTime) => {
  const res = await api.post(ENDPOINTS.platformExamSchedule(examId), { timezone, start_time: startTime, end_time: endTime }, { actor: ACTOR, sign: true });
  return res.data;
});

export const rollbackExamPolicy = wrap(async (examId, targetVersion) => {
  const res = await api.post(ENDPOINTS.platformExamPolicyRollback(examId), { target_version: targetVersion }, { actor: ACTOR, sign: true });
  return res.data;
});

export const addRosterEntry = wrap(async (examId, entry) => {
  const res = await api.post(ENDPOINTS.platformExamRoster(examId), {
    candidate_id: entry.candidateId,
    full_name: entry.fullName,
    email: entry.email,
    room_id: entry.roomId,
    assigned_seat: entry.assignedSeat,
    assigned_device_id: entry.assignedDeviceId,
    pin: entry.pin,
    accommodation_extra_time_mins: entry.accommodationExtraTimeMins || 0,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const checkinCandidate = wrap(async (examId, candidateId, deviceId) => {
  const res = await api.post(ENDPOINTS.platformExamCheckin(examId), { candidate_id: candidateId, device_id: deviceId }, { actor: ACTOR, sign: true });
  return res.data;
});

export const recordSubmission = wrap(async (examId, submission) => {
  const res = await api.post(ENDPOINTS.platformExamSubmissions(examId), {
    submission_id: submission.submissionId,
    candidate_id: submission.candidateId,
    session_id: submission.sessionId,
    receipt_hash: submission.receiptHash,
    status: submission.status,
    answers: submission.answers || '',
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const checkReadiness = wrap(async (examId, deviceId) => {
  const res = await api.get(`${ENDPOINTS.platformExamReadiness(examId)}?device_id=${encodeURIComponent(deviceId)}`, { actor: ACTOR });
  return res.data;
});

export const purgeExpiredExams = wrap(async (retentionDays) => {
  const res = await api.post(ENDPOINTS.platformExamPurge, { retention_days: retentionDays }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Exam sessions (platform)
// ---------------------------------------------------------------------------

export const createExamSession = wrap(async ({ candidateId, examCode, maxDurationSeconds }) => {
  const res = await api.post(ENDPOINTS.platformExamSessions, {
    candidate_id: candidateId, exam_code: examCode, max_duration_seconds: maxDurationSeconds,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateExamSessionState = wrap(async (sessionId, state) => {
  const res = await api.post(ENDPOINTS.platformExamSessionState(sessionId), { state }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Roster (admin)
// ---------------------------------------------------------------------------

export const getRoster = wrap(async ({ examId } = {}) => {
  const qs = examId ? `?exam_id=${encodeURIComponent(examId)}` : '';
  const res = await api.get(`${ENDPOINTS.roster}${qs}`, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export const listPolicies = wrap(async ({ examId } = {}) => {
  const qs = examId ? `?exam_id=${encodeURIComponent(examId)}` : '';
  const res = await api.get(`${ENDPOINTS.policies}${qs}`, { actor: ACTOR });
  return res.data;
});

export const listPolicyCatalog = wrap(async () => {
  const res = await api.get(ENDPOINTS.policiesCatalog, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Fleet / devices
// ---------------------------------------------------------------------------

export const listFleet = wrap(async () => {
  const res = await api.get(ENDPOINTS.fleet, { actor: ACTOR });
  return res.data;
});

export const fleetCompliance = wrap(async () => {
  const res = await api.get(ENDPOINTS.fleetCompliance, { actor: ACTOR });
  return res.data;
});

export const bulkDeviceAction = wrap(async ({ actionType, targetGroup, institutionId, targetCampus, targetRoom, parameter, previewOnly = false }) => {
  const res = await api.post(ENDPOINTS.fleetBulk, {
    action_type: actionType, target_group: targetGroup, institution_id: institutionId,
    campus_id: targetCampus, room_id: targetRoom, parameter, preview_only: previewOnly ? 1 : 0,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export const listIncidents = wrap(async () => {
  const res = await api.get(ENDPOINTS.incidents, { actor: ACTOR });
  return res.data;
});

export const createIncident = wrap(async (incident) => {
  const res = await api.post(ENDPOINTS.incidents, {
    title: incident.title, institution_id: incident.institutionId, device_id: incident.deviceId,
    candidate_id: incident.candidateId, exam_id: incident.examId, summary: incident.summary,
    assigned_to: incident.assignedTo, severity: incident.severity,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

export const getTelemetry = wrap(async () => {
  const res = await api.get(ENDPOINTS.telemetry, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

export const attestationNonce = wrap(async ({ deviceId, sessionId, releaseId }) => {
  const res = await api.post(ENDPOINTS.attestationNonce, { device_id: deviceId, session_id: sessionId, release_id: releaseId }, { actor: ACTOR, sign: true });
  return res.data;
});

export const attestationVerify = wrap(async (evidenceBody) => {
  const res = await api.post(ENDPOINTS.attestationVerify, evidenceBody, { actor: ACTOR, sign: true });
  return res.data;
});

export const attestationReAttest = wrap(async ({ sessionId, deviceId }) => {
  const res = await api.post(ENDPOINTS.attestationReAttest, { session_id: sessionId, device_id: deviceId }, { actor: ACTOR, sign: true });
  return res.data;
});

export const attestationStatus = wrap(async (id, type = 'attestation_id') => {
  const endpoint = type === 'session_id' ? ENDPOINTS.attestationStatusBySession(id) : ENDPOINTS.attestationStatus(id);
  const res = await api.get(endpoint, { actor: ACTOR });
  return res.data;
});

export const revokeRelease = wrap(async (releaseId) => {
  const res = await api.post(ENDPOINTS.attestationRevokeRelease, { release_id: releaseId }, { actor: ACTOR, sign: true });
  return res.data;
});

export const revokeDevice = wrap(async (deviceId) => {
  const res = await api.post(ENDPOINTS.attestationRevokeDevice, { device_id: deviceId }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Exam workbench (candidate)
// ---------------------------------------------------------------------------

export const getExamPaper = wrap(async () => {
  const res = await api.get(ENDPOINTS.examPaper, { useCandidateToken: true, actor: ACTOR });
  return res.data;
});

export const saveAnswer = wrap(async ({ questionId, selectedOption, status, textAnswer }) => {
  const res = await api.post(ENDPOINTS.examSaveAnswer, {
    question_id: questionId, selected_option: selectedOption, status, text_answer: textAnswer,
  }, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

export const submitExam = wrap(async () => {
  const res = await api.post(ENDPOINTS.examSubmit, {}, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

export const getAnnouncements = wrap(async () => {
  const res = await api.get(ENDPOINTS.examAnnouncements, { actor: ACTOR, sign: false });
  return res.data;
});

export const getTerminals = wrap(async () => {
  const res = await api.get(ENDPOINTS.examTerminals, { actor: ACTOR });
  return res.data;
});

export const examCommand = wrap(async ({ command, targetCandidateId, payload }) => {
  const res = await api.post(ENDPOINTS.examCommand, { command, target_candidate_id: targetCandidateId, payload }, { actor: ACTOR, sign: true });
  return res.data;
});

export const getKeyReleaseEligibility = wrap(async ({ sessionId, deviceId }) => {
  const qs = `?session_id=${encodeURIComponent(sessionId)}&device_id=${encodeURIComponent(deviceId || '')}`;
  const res = await api.get(`${ENDPOINTS.examKeyReleaseEligibility}${qs}`, { useCandidateToken: true, actor: ACTOR });
  return res.data;
});

export const releaseExamKey = wrap(async ({ sessionId, deviceId }) => {
  const res = await api.post(ENDPOINTS.examKeyRelease, { session_id: sessionId, device_id: deviceId }, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

export const recordConsent = wrap(async ({ sessionId, candidateId }) => {
  const res = await api.post(ENDPOINTS.consent, { session_id: sessionId, candidate_id: candidateId }, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Proctoring events
// ---------------------------------------------------------------------------

export const recordProctoringEvent = wrap(async ({ sessionId, sourceType, eventType, modelName, modelVersion, payload }) => {
  const res = await api.post(ENDPOINTS.proctoringEvents, {
    session_id: sessionId, source_type: sourceType, event_type: eventType,
    model_name: modelName, model_version: modelVersion, payload: payload || {},
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const listProctoringEvents = wrap(async (sessionId) => {
  const res = await api.get(ENDPOINTS.proctoringEventsBySession(sessionId), { actor: ACTOR });
  return res.data;
});

export const proctoringCheckpoint = wrap(async (sessionId) => {
  const res = await api.post(ENDPOINTS.proctoringCheckpoint, { session_id: sessionId }, { actor: ACTOR, sign: true });
  return res.data;
});

export const verifyProctoringChain = wrap(async (sessionId) => {
  const res = await api.post(ENDPOINTS.proctoringVerify, { session_id: sessionId }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Second camera
// ---------------------------------------------------------------------------

export const secondCameraRequest = wrap(async () => {
  const res = await api.post(ENDPOINTS.secondCameraRequest, {}, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

export const secondCameraPair = wrap(async ({ sessionId, token }) => {
  const res = await api.post(ENDPOINTS.secondCameraPair, { session_id: sessionId, token }, { useCandidateToken: true, actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Ledger / audit
// ---------------------------------------------------------------------------

export const getLedger = wrap(async () => {
  const res = await api.get(ENDPOINTS.ledger, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Admin actions
// ---------------------------------------------------------------------------

export const adminReload = wrap(async () => {
  const res = await api.post(ENDPOINTS.adminReload, {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const adminLock = wrap(async () => {
  const res = await api.post(ENDPOINTS.adminLock, {}, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Heartbeat (agent)
// ---------------------------------------------------------------------------

export const sendHeartbeat = wrap(async ({ deviceId, body }) => {
  const res = await api.post(ENDPOINTS.heartbeat, body, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export const saveConfig = wrap(async ({ examUrl, examName, examId, allowedOrigins, examDurationMinutes }) => {
  const res = await api.post(ENDPOINTS.config, { exam_url: examUrl, exam_name: examName, exam_id: examId, allowed_origins: allowedOrigins, exam_duration_minutes: examDurationMinutes }, { actor: ACTOR, sign: true });
  return res.data;
});

// Backend is now CORS-enabled for http://localhost:5173 by default.
// Set EXAMOS_CORS_ALLOWED_ORIGINS env var on the server for production origins.
