// ExamOS Console — Backend API service layer.
// Service functions call the ExamOS C server (server/main.c) over HTTP.
// Application records and protected state are server-backed; no browser database is used.

import { api, setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens, ApiError } from './client';
import { ENDPOINTS } from '../../config/api';
import { all, get, put, del } from '../db/db';
import { sha256 } from '../security/crypto';
import { record } from '../security/auditChain';
import { audit } from '../security/auditClient';
import { normalizeExaminationDetail, normalizeExaminationList } from '../ui/normalizers';

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
    TECH_OPERATOR: 'ops_admin',
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

export const candidateLogin = wrap(async ({ candidateId, pin, examToken }) => {
  const res = await api.post(ENDPOINTS.candidateLogin, {
    candidate_id: candidateId, pin: pin || '', exam_token: examToken || '',
  }, { useCandidateToken: true, actor: ACTOR, sign: true });

  const data = res.data;
  if (data.status === 'PENDING_VERIFICATION') {
    return { pendingVerification: true, pollToken: data.poll_token };
  }
  if (data.status !== 'SUCCESS') throw new ApiError(res.status, data.error || 'Candidate login failed', data);

  setCandidateToken(data.token);

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

export const candidateCheckinStatus = wrap(async (pollToken) => {
  const res = await api.post(ENDPOINTS.candidateCheckinStatus, { poll_token: pollToken }, {
    useCandidateToken: true, actor: ACTOR, sign: true,
  });
  return res.data;
});

export const issueExamCandidateToken = wrap(async (examId, candidateId) => {
  const res = await api.post(ENDPOINTS.examinationCandidateTokens(examId), { candidate_id: candidateId }, {
    actor: ACTOR, sign: true,
  });
  return res.data;
});

export const issueExamCandidatePin = wrap(async (examId, candidateId) => {
  const res = await api.post(ENDPOINTS.examinationCandidatePins(examId), { candidate_id: candidateId }, {
    actor: ACTOR, sign: true,
  });
  return res.data;
});

export const listExamCandidateCheckins = wrap(async (examId) => {
  const res = await api.get(ENDPOINTS.examinationCandidateCheckins(examId), { actor: ACTOR });
  return res.data;
});

export const decideExamCandidateCheckin = wrap(async (examId, checkinId, decision, reason = '') => {
  const res = await api.post(ENDPOINTS.examinationCandidateCheckin(examId, checkinId), { decision, reason }, {
    actor: ACTOR, sign: true,
  });
  return res.data;
});

export const candidateLogout = wrap(async () => {
  setCandidateToken(null);
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

export const createInstitution = wrap(async (data) => {
  const { name, code, contactEmail, contactPhone, region, timezone, plan, maxCenters, maxCandidates, deploymentModel, retentionDays, domains } = data || {};
  const res = await api.post(ENDPOINTS.institutions, {
    name,
    code: code || '',
    contact_email: contactEmail || '',
    contact_phone: contactPhone || '',
    region: region || '',
    timezone: timezone || '',
    plan: plan || '',
    max_centers: Number(maxCenters) || 0,
    max_candidates: Number(maxCandidates) || 0,
    deployment_model: deploymentModel || '',
    /* M2 fix: send snake_case retention_days to match the backend's ctrl_json_int key. */
    ...(Number(retentionDays) ? { retention_days: Number(retentionDays) } : {}),
    domains: domains || [],
    active: 1,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateInstitution = wrap(async (id, patch) => {
  const res = await api.put(ENDPOINTS.institutionById(id), patch, { actor: ACTOR, sign: true });
  return res.data;
});

export const setInstitutionStatus = wrap(async (id, status, reason) => {
  const res = await api.post(ENDPOINTS.institutionStatus(id), { status, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const saveInstitutionExamDefaults = wrap(async (id, defaults) => {
  const res = await api.post(ENDPOINTS.institutionExamDefaults(id), defaults, { actor: ACTOR, sign: true });
  return res.data;
});

export const saveInstitutionSecurity = wrap(async (id, security) => {
  const res = await api.post(ENDPOINTS.institutionSecurity(id), security, { actor: ACTOR, sign: true });
  return res.data;
});

export const getInstitutionStats = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.institutionStats(id), { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Institution Lifecycle: Applications, Agreements, Licenses & Deployments
// ---------------------------------------------------------------------------

export const applyInstitution = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.institutionApply, data, { actor: ACTOR, retries: 0 });
  return res.data;
});

export const getInstitutionApplyStatus = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.institutionApplyStatus(id), { actor: ACTOR });
  return res.data;
});

export const listInstitutionApplications = wrap(async () => {
  const res = await api.get(ENDPOINTS.institutionApplications, { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Institution Admins — invite, list, per-institution user management
// ---------------------------------------------------------------------------

export const listInstitutionAdmins = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionAdmins(institutionId), { actor: ACTOR });
  const admins = res?.data?.admins;
  if (!Array.isArray(admins)) throw new Error('The institution-admin endpoint returned an unexpected response.');
  return admins;
});

export const listInstitutionUsers = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionUsers(institutionId), { actor: ACTOR });
  const users = res?.data?.users;
  if (!Array.isArray(users)) throw new Error('The institution-user endpoint returned an unexpected response.');
  return users;
});

export const inviteInstitutionAdmin = wrap(async (institutionId, { name, email, role, campusId }) => {
  /* The backend creates the account, generates a cryptographically random
   * one-time credential, and persists the institution scope. The client must
   * never invent a password, username, or user row. */
  const res = await api.post(ENDPOINTS.institutionAdminInvite(institutionId), {
    name,
    email: String(email || '').toLowerCase(),
    role: role || 'inst_admin',
    campusId: campusId || '',
  }, { actor: ACTOR, sign: true });
  return {
    ...res.data,
    id: res.data?.user_id || res.data?.id,
    institutionId,
  };
});

export const removeInstitutionAdmin = wrap(async (institutionId, userId, reason) => {
  const res = await api.post(ENDPOINTS.institutionAdminRemove(institutionId, userId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const getInstitutionApplication = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.institutionApplicationById(id), { actor: ACTOR });
  return res.data;
});

export const reviewInstitutionApplication = wrap(async (id, action, reviewNotes, reviewChecklist) => {
  const res = await api.post(ENDPOINTS.institutionApplicationReview(id), {
    action,
    reviewNotes,
    ...(reviewChecklist ? { reviewChecklist } : {}),
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const provisionInstitutionApplication = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.institutionApplicationProvision(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const listInstitutionAgreements = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionAgreements(institutionId), { actor: ACTOR });
  return res.data;
});

export const createInstitutionAgreement = wrap(async (institutionId, data) => {
  const res = await api.post(ENDPOINTS.institutionAgreements(institutionId), data, { actor: ACTOR, sign: true });
  return res.data;
});

export const signInstitutionAgreement = wrap(async (agreementId, signerData) => {
  const res = await api.post(ENDPOINTS.signAgreement(agreementId), signerData, { actor: ACTOR, sign: true });
  return res.data;
});

export const getInstitutionLicense = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionLicense(institutionId), { actor: ACTOR });
  return res.data;
});

export const updateInstitutionLicense = wrap(async (institutionId, data) => {
  const res = await api.post(ENDPOINTS.institutionLicense(institutionId), data, { actor: ACTOR, sign: true });
  return res.data;
});

export const checkInstitutionEntitlements = wrap(async (institutionId, resource) => {
  const url = `${ENDPOINTS.institutionEntitlementsCheck(institutionId)}?resource=${encodeURIComponent(resource || 'exams')}`;
  const res = await api.get(url, { actor: ACTOR });
  return res.data;
});

export const listInstitutionDeployments = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionDeployments(institutionId), { actor: ACTOR });
  return res.data;
});

export const assignInstitutionDeployment = wrap(async (institutionId, data) => {
  const res = await api.post(ENDPOINTS.institutionDeployments(institutionId), data, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateDeploymentStatus = wrap(async (deploymentId, status, devicesAcknowledged) => {
  const res = await api.post(ENDPOINTS.deploymentStatus(deploymentId), { status, devicesAcknowledged }, { actor: ACTOR, sign: true });
  return res.data;
});

export const pushDeploymentToKiosks = wrap(async (deploymentId) => {
  const res = await api.post(ENDPOINTS.pushDeploymentToKiosks(deploymentId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const getInstitutionOnboarding = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionOnboarding(institutionId), { actor: ACTOR });
  return res.data;
});

export const getInstitutionPilotReadiness = wrap(async (institutionId) => {
  const res = await api.get(ENDPOINTS.institutionPilotReadiness(institutionId), { actor: ACTOR });
  return res.data;
});

export const updateInstitutionOnboardingStep = wrap(async (institutionId, stepKey, completed, notes) => {
  const res = await api.post(ENDPOINTS.institutionOnboardingStep(institutionId), { stepKey, completed, notes }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Campuses, Departments & Staff
// ---------------------------------------------------------------------------

export const listCampuses = wrap(async (institutionId) => {
  const url = institutionId ? `${ENDPOINTS.campuses}?institution_id=${encodeURIComponent(institutionId)}` : ENDPOINTS.campuses;
  const res = await api.get(url, { actor: ACTOR });
  return res.data;
});

export const createCampus = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.campuses, {
    // Send institution_id explicitly in the body so the backend can use it
    // when the session belongs to a platform-owner whose session has no
    // institution scope (sess.institution_id is empty for superadmin).
    institution_id: data.tenantId || data.institution_id || '',
    tenantId: data.tenantId || '',
    name: data.name,
    code: data.code || '',
    address: data.address || '',
    city: data.city || '',
    capacity: Number(data.capacity) || 0,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateCampus = wrap(async (id, patch) => {
  const res = await api.put(ENDPOINTS.campusById(id), patch, { actor: ACTOR, sign: true });
  return res.data;
});

export const setCampusStatus = wrap(async (id, status, reason) => {
  const res = await api.post(ENDPOINTS.campusStatus(id), { status, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const listCenters = wrap(async (institutionId) => {
  const url = institutionId ? `${ENDPOINTS.centers}?institution_id=${encodeURIComponent(institutionId)}` : ENDPOINTS.centers;
  const res = await api.get(url, { actor: ACTOR });
  return res.data;
});

export const createCenter = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.centers, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateCenter = wrap(async (id, patch) => {
  const res = await api.put(ENDPOINTS.centerById(id), patch, { actor: ACTOR, sign: true });
  return res.data;
});

export const setCenterStatus = wrap(async (id, status, reason) => {
  const res = await api.post(ENDPOINTS.centerStatus(id), { status, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const listDepartments = wrap(async (institutionId) => {
  const url = institutionId ? `${ENDPOINTS.departments}?institution_id=${encodeURIComponent(institutionId)}` : ENDPOINTS.departments;
  const res = await api.get(url, { actor: ACTOR });
  return res.data;
});

export const createDepartment = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.departments, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const setDepartmentStatus = wrap(async (id, status, reason) => {
  const res = await api.post(ENDPOINTS.departmentStatus(id), { status, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const listStaff = wrap(async (institutionId) => {
  const url = institutionId ? `${ENDPOINTS.staff}?institution_id=${encodeURIComponent(institutionId)}` : ENDPOINTS.staff;
  const res = await api.get(url, { actor: ACTOR });
  return res.data;
});

export const assignStaff = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.staff, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const removeStaff = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.staffRemove(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------------

const BACKEND_ROLE_TO_INT = {
  superadmin: 1, platform_owner: 1, 1: 1,
  inst_admin: 2, institution_admin: 2, 2: 2,
  exam_controller: 3, exam_manager: 3, 3: 3,
  security_engineer: 4, security_admin: 4, 4: 4,
  invigilator: 5, 5: 5,
  it_admin: 6, tech_operator: 6, ops_admin: 6, 6: 6,
  auditor: 7, incident_investigator: 7, 7: 7,
  readonly_auditor: 8, 8: 8,
  support: 9, support_engineer: 9, 9: 9,
};

export const listUsers = wrap(async (institutionId) => {
  const query = institutionId ? `?institution_id=${encodeURIComponent(institutionId)}` : '';
  const res = await api.get(`${ENDPOINTS.users}${query}`, { actor: ACTOR });
  return res.data;
});

export const createUser = wrap(async ({ username, fullName, email, password, institutionId, role }) => {
  const roleInt = typeof role === 'number' ? role : BACKEND_ROLE_TO_INT[String(role).toLowerCase()];
  if (!roleInt) throw new Error('A valid management role is required.');
  const res = await api.post(ENDPOINTS.users, {
    username,
    full_name: fullName || username,
    email: email || '',
    password,
    institution_id: institutionId || '',
    role: roleInt,
    active: 1,
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateUser = wrap(async (id, data) => {
  const res = await api.put(`${ENDPOINTS.users}/${id}`, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const setUserStatus = wrap(async (id, status, reason) => {
  const res = await api.post(`${ENDPOINTS.users}/${id}/status`, { status, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const setUserRole = wrap(async (id, role, reason) => {
  const res = await api.post(`${ENDPOINTS.users}/${id}/role`, { role, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const resetUserPassword = wrap(async (id, password) => {
  const res = await api.post(`${ENDPOINTS.users}/${id}/reset-password`, { password }, { actor: ACTOR, sign: true });
  return res.data;
});

export const revokeUserSessions = wrap(async (userId, why) => {
  const res = await api.post(`${ENDPOINTS.users}/${userId}/revoke-sessions`, { why }, { actor: ACTOR, sign: true });
  return res.data;
});

export const inviteUser = wrap(async (data) => {
  const res = await api.post(`${ENDPOINTS.users}/invite`, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const acceptInvitation = wrap(async (data) => {
  const res = await api.post(`${ENDPOINTS.users}/accept-invite`, data, { actor: ACTOR });
  return res.data;
});

export const createRole = wrap(async (data) => {
  const res = await api.post(ENDPOINTS.roles, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const updateRole = wrap(async (id, data) => {
  const res = await api.put(`${ENDPOINTS.roles}/${id}`, data, { actor: ACTOR, sign: true });
  return res.data;
});

export const deleteRole = wrap(async (id) => {
  const res = await api.delete(`${ENDPOINTS.roles}/${id}`, { actor: ACTOR, sign: true });
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

// ---------------------------------------------------------------------------
// Module 9: Examination Management (C Server Module 9)
// ---------------------------------------------------------------------------

export const listExaminations = wrap(async () => {
  const res = await api.get(ENDPOINTS.examinations, { actor: ACTOR });
  return normalizeExaminationList(res.data);
});

export const createExamination = wrap(async (exam) => {
  const res = await api.post(ENDPOINTS.examinations, {
    name: exam.name || exam.title,
    subject: exam.subject || exam.course,
    code: exam.code,
    academic_year: exam.academicYear,
    exam_type: exam.examType || exam.type,
    duration_minutes: exam.durationMinutes || exam.durationMin,
    total_marks: exam.totalMarks || 100,
    passing_marks: exam.passingMarks || 40,
    instructions: exam.instructions,
    exam_url: exam.examUrl,
    allowed_origins: exam.allowedOrigins,
    institution_id: exam.institutionId || exam.tenantId,
    exam_config_json: JSON.stringify(exam.examConfig || {}),
  }, { actor: ACTOR, sign: true, retries: 0, timeoutMs: 15000 });
  return res.data;
});

export const getExamination = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.examinationById(id), { actor: ACTOR, useCandidateToken: !!getCandidateToken() });
  return normalizeExaminationDetail(res.data);
});

export const updateExamination = wrap(async (id, patch) => {
  /* The exam update path runs a multi-step transaction with a large
   * validate_exam_config() query on the server. 60 seconds gives the
   * database enough headroom without masking real hangs. */
  const res = await api.patch(ENDPOINTS.examinationById(id), patch, {
    actor: ACTOR, sign: true, timeoutMs: 60000,
  });
  return res.data;
});

export const submitExaminationForApproval = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationSubmitForApproval(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const approveExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationApprove(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const publishExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationPublish(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const readyExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationReady(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const startExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationStart(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const closeExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationClose(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const finalizeExamination = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.examinationFinalize(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const cancelExamination = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.examinationCancel(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const getExaminationStatus = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.examinationStatus(id), { actor: ACTOR });
  return res.data;
});

export const addExaminationSchedule = wrap(async (id, schedule) => {
  const res = await api.post(ENDPOINTS.examinationSchedules(id), schedule, { actor: ACTOR, sign: true });
  return res.data;
});

export const assignExaminationStudent = wrap(async (id, student) => {
  const res = await api.post(ENDPOINTS.examinationStudents(id), student, { actor: ACTOR, sign: true });
  return res.data;
});

export const listExaminationStudents = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.examinationStudents(id), { actor: ACTOR });
  if (!Array.isArray(res?.data?.assignments)) throw new Error('The examination roster endpoint returned an invalid response.');
  return res.data.assignments;
});

export const unassignExaminationStudent = wrap(async (id, studentId) => {
  const res = await api.del(ENDPOINTS.examinationStudent(id, studentId), { actor: ACTOR, sign: true });
  return res.data;
});

export const configureExaminationPolicy = wrap(async (id, policy) => {
  const res = await api.post(ENDPOINTS.examinationPolicy(id), policy, { actor: ACTOR, sign: true });
  return res.data;
});

// ---------------------------------------------------------------------------
// Module 5: Student Management System (C Server Module 5)
// ---------------------------------------------------------------------------

export const createStudent = wrap(async (student) => {
  const res = await api.post(ENDPOINTS.students, student, { actor: ACTOR, sign: true });
  return res.data;
});

export const getStudentById = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentById(id), { actor: ACTOR, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const updateStudentProfile = wrap(async (id, updates) => {
  const res = await api.patch(ENDPOINTS.studentById(id), updates, { actor: ACTOR, sign: true });
  return res.data;
});

export const verifyStudentIdentity = wrap(async (id, verification) => {
  const res = await api.post(ENDPOINTS.studentVerify(id), verification, { actor: ACTOR, sign: true });
  return res.data;
});

export const suspendStudentAccount = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.studentSuspend(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const reactivateStudentAccount = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.studentReactivate(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const archiveStudentAccount = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.studentArchive(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const getStudentAuditHistory = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentHistory(id), { actor: ACTOR });
  return res.data;
});

export const getStudentEnrollments = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentEnrollments(id), { actor: ACTOR });
  return res.data;
});

export const progressStudentSemester = wrap(async (id, enrollment) => {
  const res = await api.post(ENDPOINTS.studentEnrollments(id), enrollment, { actor: ACTOR, sign: true });
  return res.data;
});

export const requestStudentCorrection = wrap(async (id, correction) => {
  const res = await api.post(ENDPOINTS.studentCorrectionRequests(id), correction, { actor: ACTOR, sign: true });
  return res.data;
});

export const reviewStudentCorrection = wrap(async (reqId, decision) => {
  const res = await api.post(ENDPOINTS.studentCorrectionReview(reqId), decision, { actor: ACTOR, sign: true });
  return res.data;
});

export const previewStudentImport = wrap(async (importData) => {
  const res = await api.post(ENDPOINTS.studentImports, importData, { actor: ACTOR, sign: true });
  return res.data;
});

export const confirmStudentImport = wrap(async (jobId) => {
  const res = await api.post(ENDPOINTS.studentImportConfirm(jobId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const getStudentImportResults = wrap(async (jobId) => {
  const res = await api.get(ENDPOINTS.studentImportResults(jobId), { actor: ACTOR });
  return res.data;
});

export const getStudentEligibilityProfile = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentExamEligibility(id), { actor: ACTOR });
  return res.data;
});

export const getStudentAssignedDevices = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentDeviceAssignments(id), { actor: ACTOR });
  return res.data;
});

export const getStudentExamSessions = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.studentExamSessions(id), { actor: ACTOR, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

// ---------------------------------------------------------------------------
// Module 10: Examination Registration & Eligibility Management (C Server Module 10)
// ---------------------------------------------------------------------------

export const upsertStudent = wrap(async (student) => {
  const res = await api.post(ENDPOINTS.students, student, { actor: ACTOR, sign: true });
  return res.data;
});

export const listStudents = wrap(async () => {
  const res = await api.get(ENDPOINTS.students, { actor: ACTOR });
  return res.data;
});

export const configureEligibilityRule = wrap(async (examId, rule) => {
  const res = await api.post(ENDPOINTS.examinationRules(examId), rule, { actor: ACTOR, sign: true });
  return res.data;
});

export const listEligibilityRules = wrap(async (examId) => {
  const res = await api.get(ENDPOINTS.examinationRules(examId), { actor: ACTOR });
  return res.data;
});

export const registerStudentForExam = wrap(async (examId, registration) => {
  const res = await api.post(ENDPOINTS.examinationRegistrations(examId), registration, { actor: ACTOR, sign: true });
  return res.data;
});

export const listExamRegistrations = wrap(async (examId) => {
  const res = await api.get(ENDPOINTS.examinationRegistrations(examId), { actor: ACTOR });
  return res.data;
});

export const getRegistration = wrap(async (id) => {
  const res = await api.get(ENDPOINTS.registrationById(id), { actor: ACTOR });
  return res.data;
});

export const evaluateRegistration = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.registrationEvaluate(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const approveRegistration = wrap(async (id) => {
  const res = await api.post(ENDPOINTS.registrationApprove(id), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const rejectRegistration = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.registrationReject(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const grantRegistrationException = wrap(async (id, reason) => {
  const res = await api.post(ENDPOINTS.registrationException(id), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const importRegistrations = wrap(async (examId, records) => {
  const res = await api.post(ENDPOINTS.examinationRegistrationsImport(examId), { records }, { actor: ACTOR, sign: true });
  return res.data;
});

export const getRegistrationImportStatus = wrap(async (jobId) => {
  const res = await api.get(ENDPOINTS.registrationImportStatus(jobId), { actor: ACTOR });
  return res.data;
});

export const publishExamRoster = wrap(async (examId) => {
  const res = await api.post(ENDPOINTS.examinationRosterPublish(examId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const checkExamStudentEligibility = wrap(async (examId, studentId) => {
  const res = await api.get(ENDPOINTS.examinationStudentEligibility(examId, studentId), { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Module 11: Exam Session Management (C Server Module 11)
// ---------------------------------------------------------------------------

export const authorizeStudentExamSession = wrap(async (authData) => {
  const res = await api.post(ENDPOINTS.examSessionsAuthorize, authData, { actor: ACTOR, sign: true, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const createAuthorizedExamSession = wrap(async (sessionData) => {
  const res = await api.post(ENDPOINTS.examSessions, sessionData, { actor: ACTOR, sign: true, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const getExamSessionDetails = wrap(async (sessionId) => {
  const res = await api.get(ENDPOINTS.examSessionById(sessionId), { actor: ACTOR, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const launchAuthorizedExamUrl = wrap(async (sessionId) => {
  const res = await api.post(ENDPOINTS.examSessionLaunch(sessionId), {}, { actor: ACTOR, sign: true, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const sendExamSessionHeartbeat = wrap(async (sessionId) => {
  const res = await api.post(ENDPOINTS.examSessionHeartbeat(sessionId), {}, { actor: ACTOR, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const recordExamSessionInterruption = wrap(async (sessionId, reason) => {
  const res = await api.post(ENDPOINTS.examSessionInterrupt(sessionId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const resumeInterruptedExamSession = wrap(async (sessionId) => {
  const res = await api.post(ENDPOINTS.examSessionResume(sessionId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const closeAuthorizedExamSession = wrap(async (sessionId, reason) => {
  const res = await api.post(ENDPOINTS.examSessionClose(sessionId), { reason }, { actor: ACTOR, sign: true, useCandidateToken: !!getCandidateToken() });
  return res.data;
});

export const listExaminationSessions = wrap(async (examId) => {
  const res = await api.get(ENDPOINTS.examinationSessions(examId), { actor: ACTOR });
  return res.data;
});

// ---------------------------------------------------------------------------
// Module 13: Device Trust, Registration & Attestation (C Server Module 13)
// ---------------------------------------------------------------------------

export const registerDeviceIdentity = wrap(async (deviceData) => {
  const res = await api.post(ENDPOINTS.devicesRegister, deviceData, { actor: ACTOR, sign: true });
  return res.data;
});

export const listRegisteredDevices = wrap(async () => {
  const res = await api.get(ENDPOINTS.devicesList, { actor: ACTOR });
  return res.data;
});

export const getRegisteredDevice = wrap(async (deviceId) => {
  const res = await api.get(ENDPOINTS.deviceById(deviceId), { actor: ACTOR });
  return res.data;
});

export const approveDeviceRegistration = wrap(async (deviceId) => {
  const res = await api.post(ENDPOINTS.deviceApprove(deviceId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const suspendDevice = wrap(async (deviceId, reason) => {
  const res = await api.post(ENDPOINTS.deviceSuspend(deviceId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const revokeDeviceIdentity = wrap(async (deviceId, reason) => {
  const res = await api.post(ENDPOINTS.deviceRevoke(deviceId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const retireDeviceIdentity = wrap(async (deviceId) => {
  const res = await api.post(ENDPOINTS.deviceRetire(deviceId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const assignDeviceToStudentOrExam = wrap(async (deviceId, assignment) => {
  const res = await api.post(ENDPOINTS.deviceAssign(deviceId), assignment, { actor: ACTOR, sign: true });
  return res.data;
});

export const getDeviceTrustStatus = wrap(async (deviceId) => {
  const res = await api.get(ENDPOINTS.deviceTrustStatus(deviceId), { actor: ACTOR });
  return res.data;
});

export const reportDeviceSecurityEvent = wrap(async (deviceId, event) => {
  const res = await api.post(ENDPOINTS.deviceSecurityEvents(deviceId), event, { actor: ACTOR, sign: true });
  return res.data;
});

export const createDeviceTrustPolicy = wrap(async (policy) => {
  const res = await api.post(ENDPOINTS.deviceTrustPolicies, policy, { actor: ACTOR, sign: true });
  return res.data;
});

export const approveDeviceTrustPolicy = wrap(async (policyId) => {
  const res = await api.post(ENDPOINTS.deviceTrustPolicyApprove(policyId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const activateDeviceTrustPolicy = wrap(async (policyId) => {
  const res = await api.post(ENDPOINTS.deviceTrustPolicyActivate(policyId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const requestExamLaunchAuthorization = wrap(async (launchParams) => {
  const res = await api.post(ENDPOINTS.examLaunchAuthorize, launchParams, { actor: ACTOR, sign: true });
  return res.data;
});

// ============================================================================
// Module 14: Secure OS Release, Updates, Rollback & Deployment Management
// ============================================================================

export const createOsRelease = wrap(async (releaseData) => {
  const res = await api.post(ENDPOINTS.osReleases, releaseData, { actor: ACTOR, sign: true });
  return res.data;
});

export const listOsReleases = wrap(async () => {
  const res = await api.get(ENDPOINTS.osReleases, { actor: ACTOR });
  return res.data;
});

export const getOsReleaseDetails = wrap(async (releaseId) => {
  const res = await api.get(ENDPOINTS.osReleaseById(releaseId), { actor: ACTOR });
  return res.data;
});

export const verifyOsReleaseSignature = wrap(async (releaseId) => {
  const res = await api.post(
    `${ENDPOINTS.osReleaseById(releaseId)}/verify-signature`,
    {},
    { actor: ACTOR, sign: true },
  );
  return res.data;
});

export const validateOsRelease = wrap(async (releaseId, validationData) => {
  const res = await api.post(ENDPOINTS.osReleaseValidate(releaseId), validationData, { actor: ACTOR, sign: true });
  return res.data;
});

export const approveOsRelease = wrap(async (releaseId) => {
  const res = await api.post(ENDPOINTS.osReleaseApprove(releaseId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const activateOsRelease = wrap(async (releaseId, options = {}) => {
  const res = await api.post(ENDPOINTS.osReleaseActivate(releaseId), options, { actor: ACTOR, sign: true });
  return res.data;
});

export const suspendOsRelease = wrap(async (releaseId) => {
  const res = await api.post(ENDPOINTS.osReleaseSuspend(releaseId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const revokeOsRelease = wrap(async (releaseId, reason) => {
  const res = await api.post(ENDPOINTS.osReleaseRevoke(releaseId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const retireOsRelease = wrap(async (releaseId) => {
  const res = await api.post(ENDPOINTS.osReleaseRetire(releaseId), {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const createOsDeploymentGroup = wrap(async (groupData) => {
  const res = await api.post(ENDPOINTS.osDeployments, groupData, { actor: ACTOR, sign: true });
  return res.data;
});

export const listOsDeploymentGroups = wrap(async () => {
  const res = await api.get(ENDPOINTS.osDeployments, { actor: ACTOR });
  return res.data;
});

export const getOsDeploymentGroup = wrap(async (deploymentId) => {
  const res = await api.get(ENDPOINTS.osDeploymentById(deploymentId), { actor: ACTOR });
  return res.data;
});

export const checkDeviceOsUpdate = wrap(async (deviceId) => {
  const res = await api.get(ENDPOINTS.osDeviceUpdateCheck(deviceId), { actor: ACTOR });
  return res.data;
});

export const reportDeviceOsUpdateEvent = wrap(async (deviceId, eventData) => {
  const res = await api.post(ENDPOINTS.osDeviceUpdateEvents(deviceId), eventData, { actor: ACTOR, sign: true });
  return res.data;
});

export const verifyDeviceOsRelease = wrap(async (deviceId, verificationData) => {
  const res = await api.post(ENDPOINTS.osDeviceVerifyRelease(deviceId), verificationData, { actor: ACTOR, sign: true });
  return res.data;
});

export const requestDeviceOsRecovery = wrap(async (deviceId, recoveryData) => {
  const res = await api.post(ENDPOINTS.osDeviceRecovery(deviceId), recoveryData, { actor: ACTOR, sign: true });
  return res.data;
});

// Central approval governance API. The server derives all actor and tenant
// identity from the authenticated session; these values are never sent by callers.
export const listApprovalRequests = wrap(async () => {
  const res = await api.get(ENDPOINTS.approvalRequests, { actor: ACTOR });
  if (!Array.isArray(res.data)) throw new Error('The approval API returned an invalid response.');
  return res.data;
});

export const createApprovalRequest = wrap(async ({ kind, label, targetId, tenantId, reason, data = {} }) => {
  const res = await api.post(ENDPOINTS.approvalRequests, {
    kind, label, target_id: targetId, tenant_id: tenantId || '',
    reason, data_json: JSON.stringify(data),
  }, { actor: ACTOR, sign: true });
  return res.data;
});

export const decideApprovalRequest = wrap(async (requestId, decision, reason) => {
  const res = await api.post(ENDPOINTS.approvalDecision(requestId), { decision, reason }, { actor: ACTOR, sign: true });
  return res.data;
});

export const cancelApprovalRequest = wrap(async (requestId, reason) => {
  const res = await api.post(ENDPOINTS.approvalCancel(requestId), { reason }, { actor: ACTOR, sign: true });
  return res.data;
});

// Backward-compatibility and sync aliases
export const getOsReleaseById = getOsReleaseDetails;
export const listOsDeployments = listOsReleases;
export const createOsDeployment = createOsDeploymentGroup;
export const listDeviceTrustPolicies = listRegisteredDevices;
export const publishExaminationRoster = publishExamRoster;
export const listExaminationRegistrations = listExamRegistrations;
export const importExaminationRegistrations = importRegistrations;
export const launchExamSession = launchAuthorizedExamUrl;
export const heartbeatExamSession = sendExamSessionHeartbeat;
export const interruptExamSession = recordExamSessionInterruption;
export const resumeExamSession = resumeInterruptedExamSession;
export const closeExamSession = closeAuthorizedExamSession;


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

export const rollbackExamPolicy = wrap(async (examId, targetVersion, reason) => {
  const justification = String(reason || '').trim();
  if (!Number.isInteger(Number(targetVersion)) || Number(targetVersion) <= 0)
    throw new Error('A valid target policy version is required.');
  if (justification.length < 8)
    throw new Error('A rollback reason of at least 8 characters is required.');
  const res = await api.post(ENDPOINTS.approvalRequests, {
    kind: 'policy-rollback',
    label: `Rollback exam policy to v${Number(targetVersion)}`,
    target_id: examId,
    reason: justification,
    data_json: JSON.stringify({ targetVersion: Number(targetVersion) }),
  }, { actor: ACTOR, sign: true });
  if (!res.data?.id || res.data.status !== 'pending_review')
    throw new Error('The backend did not confirm that the rollback request was persisted.');
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

export const listAuditTrail = wrap(async ({ examId = '', limit = 200 } = {}) => {
  const qs = new URLSearchParams();
  if (examId) qs.set('exam_id', examId);
  if (limit) qs.set('limit', String(limit));
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  const res = await api.get(`${ENDPOINTS.auditTrail}${suffix}`, { actor: ACTOR });
  return res.data;
});

export const listInstitutionAuditTrail = wrap(async () => {
  const res = await api.get(ENDPOINTS.institutionAuditTrail, { actor: ACTOR });
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

export const adminUnlock = wrap(async () => {
  const res = await api.post(ENDPOINTS.adminUnlock, {}, { actor: ACTOR, sign: true });
  return res.data;
});

export const getKiosks = wrap(async () => {
  const res = await api.get(ENDPOINTS.kioskTerminals, { actor: ACTOR });
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
