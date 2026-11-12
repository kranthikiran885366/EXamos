// ExamOS Console — Backend API configuration
// Integrates with the ExamOS C server (D:\SEB BRO\server) running on port 8895.
// In dev mode, Vite proxies /api/* requests to localhost:8895 so the frontend
// can use same-origin relative paths. Override via VITE_API_BASE if needed.

export const API_BASE = (() => {
  const v = typeof import.meta !== 'undefined' && import.meta.env
    ? import.meta.env.VITE_API_BASE || ''
    : '';
  // Empty string = same-origin (uses Vite proxy in dev, same host in production)
  return (v || '').replace(/\/+$/, '');
})();

// Security headers the console sends on every request so the C server can
// attribute calls to an authenticated console session (admin or operator).
export const CONSOLE_HEADERS = {
  'X-ExamOS-Console': '1',
  'X-ExamOS-Console-Version': '2.18.4',
  'X-Requested-With': 'XMLHttpRequest',
};

// API endpoints mapped to the C server routes (server/main.c).
export const ENDPOINTS = {
  // Health / status
  health: '/api/v1/health',
  status: '/api/v1/status',

  // Auth — admin
  adminLogin: '/api/v1/admin/login',
  adminLogout: '/api/v1/admin/logout',
  adminSession: '/api/v1/admin/session',
  mfaSetup: '/api/v1/admin/mfa/setup',
  mfaConfirm: '/api/v1/admin/mfa/confirm',
  recoveryReset: '/api/v1/admin/recovery/reset',
  passwordChange: '/api/v1/admin/password/change',

  // Auth — candidate
  candidateLogin: '/api/v1/candidate/login',
  candidateLogout: '/api/v1/candidate/logout',
  candidateCheckinStatus: '/api/v1/candidate/checkin/status',

  // Admin platform
  institutions: '/api/v1/admin/institutions',
  institutionById: (id) => `/api/v1/admin/institutions/${id}`,
  institutionStatus: (id) => `/api/v1/admin/institutions/${id}/status`,
  institutionExamDefaults: (id) => `/api/v1/admin/institutions/${id}/exam-defaults`,
  institutionSecurity: (id) => `/api/v1/admin/institutions/${id}/security`,
  institutionStats: (id) => `/api/v1/admin/institutions/${id}/stats`,
  institutionApply: '/api/v1/institutions/apply',
  institutionApplyStatus: (id) => `/api/v1/institutions/apply/${id}`,
  institutionApplications: '/api/v1/admin/institution-applications',
  institutionApplicationById: (id) => `/api/v1/admin/institution-applications/${id}`,
  institutionApplicationReview: (id) => `/api/v1/admin/institution-applications/${id}/review`,
  institutionApplicationProvision: (id) => `/api/v1/admin/institution-applications/${id}/provision`,
  institutionAdmins: (id) => `/api/v1/admin/institutions/${id}/admins`,
  institutionUsers: (id) => `/api/v1/admin/institutions/${id}/users`,
  institutionAdminInvite: (id) => `/api/v1/admin/institutions/${id}/admins/invite`,
  institutionAdminRemove: (id, userId) => `/api/v1/admin/institutions/${id}/admins/${userId}`,
  auditTrail: '/api/v1/admin/audit',
  auditBatch: '/api/v1/audit/batch',
  institutionAgreements: (id) => `/api/v1/admin/institutions/${id}/agreements`,
  signAgreement: (id) => `/api/v1/admin/agreements/${id}/sign`,
  institutionLicense: (id) => `/api/v1/admin/institutions/${id}/license`,
  institutionEntitlementsCheck: (id) => `/api/v1/admin/institutions/${id}/entitlements/check`,
  institutionDeployments: (id) => `/api/v1/admin/institutions/${id}/deployments`,
  deploymentStatus: (id) => `/api/v1/admin/deployments/${id}/status`,
  pushDeploymentToKiosks: (id) => `/api/v1/admin/deployments/${id}/push-kiosk`,
  institutionOnboarding: (id) => `/api/v1/admin/institutions/${id}/onboarding`,
  institutionOnboardingStep: (id) => `/api/v1/admin/institutions/${id}/onboarding/step`,
  institutionPilotReadiness: (id) => `/api/v1/admin/institutions/${id}/readiness`,
  exams: '/api/v1/admin/exams',
  roles: '/api/v1/admin/roles',
  users: '/api/v1/admin/users',
  campuses: '/api/v1/admin/campuses',
  campusById: (id) => `/api/v1/admin/campuses/${id}`,
  campusStatus: (id) => `/api/v1/admin/campuses/${id}/status`,
  centers: '/api/v1/admin/centers',
  centerById: (id) => `/api/v1/admin/centers/${id}`,
  centerStatus: (id) => `/api/v1/admin/centers/${id}/status`,
  departments: '/api/v1/admin/departments',
  departmentById: (id) => `/api/v1/admin/departments/${id}`,
  departmentStatus: (id) => `/api/v1/admin/departments/${id}/status`,
  staff: '/api/v1/admin/staff',
  staffById: (id) => `/api/v1/admin/staff/${id}`,
  staffRemove: (id) => `/api/v1/admin/staff/${id}/remove`,
  rooms: '/api/v1/admin/rooms',
  roster: '/api/v1/admin/roster',
  config: '/api/v1/admin/config',
  telemetry: '/api/v1/admin/telemetry',
  fleet: '/api/v1/admin/fleet',
  fleetCompliance: '/api/v1/admin/fleet/compliance',
  fleetBulk: '/api/v1/admin/fleet/bulk',
  incidents: '/api/v1/admin/incidents',
  policies: '/api/v1/admin/policies',
  policiesCatalog: '/api/v1/admin/policies/catalog',
  consoleData: '/api/v1/console/data',
  approvalRequests: '/api/v1/approvals',
  approvalRequest: (id) => `/api/v1/approvals/${encodeURIComponent(id)}`,
  approvalDecision: (id) => `/api/v1/approvals/${encodeURIComponent(id)}/decision`,
  approvalCancel: (id) => `/api/v1/approvals/${encodeURIComponent(id)}/cancel`,

  // Module 9: Examination Management REST endpoints
  examinations: '/api/v1/examinations',
  examinationById: (id) => `/api/v1/examinations/${id}`,
  examinationSubmitForApproval: (id) => `/api/v1/examinations/${id}/submit-for-approval`,
  examinationApprove: (id) => `/api/v1/examinations/${id}/approve`,
  examinationPublish: (id) => `/api/v1/examinations/${id}/publish`,
  examinationReady: (id) => `/api/v1/examinations/${id}/ready`,
  examinationStart: (id) => `/api/v1/examinations/${id}/start`,
  examinationClose: (id) => `/api/v1/examinations/${id}/close`,
  examinationFinalize: (id) => `/api/v1/examinations/${id}/finalize`,
  examinationCancel: (id) => `/api/v1/examinations/${id}/cancel`,
  examinationStatus: (id) => `/api/v1/examinations/${id}/status`,
  examinationSchedules: (id) => `/api/v1/examinations/${id}/schedules`,
  examinationStudents: (id) => `/api/v1/examinations/${id}/students`,
  examinationStudent: (id, studentId) => `/api/v1/examinations/${id}/students/${encodeURIComponent(studentId)}`,
  examinationPolicy: (id) => `/api/v1/examinations/${id}/policy`,
  examinationCandidateTokens: (id) => `/api/v1/examinations/${id}/candidate-tokens`,
  examinationCandidatePins: (id) => `/api/v1/examinations/${id}/candidate-pins`,
  examinationCandidateCheckins: (id) => `/api/v1/examinations/${id}/candidate-checkins`,
  examinationCandidateCheckin: (examId, checkinId) => `/api/v1/examinations/${examId}/candidate-checkins/${checkinId}`,

  // Module 5: Student Management System REST endpoints
  students: '/api/v1/students',
  adminStudents: '/api/v1/admin/students',
  studentById: (id) => `/api/v1/students/${id}`,
  studentVerify: (id) => `/api/v1/students/${id}/verify`,
  studentSuspend: (id) => `/api/v1/students/${id}/suspend`,
  studentReactivate: (id) => `/api/v1/students/${id}/reactivate`,
  studentArchive: (id) => `/api/v1/students/${id}/archive`,
  studentHistory: (id) => `/api/v1/students/${id}/history`,
  studentEnrollments: (id) => `/api/v1/students/${id}/enrollments`,
  studentCorrectionRequests: (id) => `/api/v1/students/${id}/correction-requests`,
  studentCorrectionReview: (id) => `/api/v1/student-correction-requests/${id}/review`,
  studentImports: '/api/v1/student-imports',
  studentImportConfirm: (id) => `/api/v1/student-imports/${id}/confirm`,
  studentImportResults: (id) => `/api/v1/student-imports/${id}/results`,
  studentExamEligibility: (id) => `/api/v1/students/${id}/exam-eligibility`,
  studentDeviceAssignments: (id) => `/api/v1/students/${id}/device-assignments`,
  studentExamSessions: (id) => `/api/v1/students/${id}/exam-sessions`,

  // Module 10: Examination Registration & Eligibility Management REST endpoints
  examinationRules: (id) => `/api/v1/examinations/${id}/rules`,
  examinationRegistrations: (id) => `/api/v1/examinations/${id}/registrations`,
  registrationById: (id) => `/api/v1/registrations/${id}`,
  registrationEvaluate: (id) => `/api/v1/registrations/${id}/evaluate`,
  registrationApprove: (id) => `/api/v1/registrations/${id}/approve`,
  registrationReject: (id) => `/api/v1/registrations/${id}/reject`,
  registrationException: (id) => `/api/v1/registrations/${id}/exception`,
  examinationRegistrationsImport: (id) => `/api/v1/examinations/${id}/registrations/import`,
  registrationImportStatus: (id) => `/api/v1/registration-imports/${id}`,
  examinationRosterPublish: (id) => `/api/v1/examinations/${id}/roster/publish`,
  examinationStudentEligibility: (examId, studentId) => `/api/v1/examinations/${examId}/eligibility/${studentId}`,

  // Module 11: Exam Session Management REST endpoints
  examSessionsAuthorize: '/api/v1/exam-sessions/authorize',
  examSessions: '/api/v1/exam-sessions',
  examSessionById: (id) => `/api/v1/exam-sessions/${id}`,
  examSessionLaunch: (id) => `/api/v1/exam-sessions/${id}/launch`,
  examSessionHeartbeat: (id) => `/api/v1/exam-sessions/${id}/heartbeat`,
  examSessionInterrupt: (id) => `/api/v1/exam-sessions/${id}/interrupt`,
  examSessionResume: (id) => `/api/v1/exam-sessions/${id}/resume`,
  examSessionClose: (id) => `/api/v1/exam-sessions/${id}/close`,
  examinationSessions: (id) => `/api/v1/examinations/${id}/sessions`,

  // Module 13: Device Trust, Registration & Attestation REST endpoints
  devicesRegister: '/api/v1/devices/register',
  devicesList: '/api/v1/devices',
  deviceById: (id) => `/api/v1/devices/${id}`,
  deviceApprove: (id) => `/api/v1/devices/${id}/approve`,
  deviceSuspend: (id) => `/api/v1/devices/${id}/suspend`,
  deviceRevoke: (id) => `/api/v1/devices/${id}/revoke`,
  deviceRetire: (id) => `/api/v1/devices/${id}/retire`,
  deviceAssign: (id) => `/api/v1/devices/${id}/assign`,
  deviceTrustStatus: (id) => `/api/v1/devices/${id}/trust-status`,
  deviceSecurityEvents: (id) => `/api/v1/devices/${id}/security-events`,
  deviceTrustPolicies: '/api/v1/device-trust-policies',
  deviceTrustPolicyApprove: (id) => `/api/v1/device-trust-policies/${id}/approve`,
  deviceTrustPolicyActivate: (id) => `/api/v1/device-trust-policies/${id}/activate`,
  examLaunchAuthorize: '/api/v1/exam-launch/authorize',

  // Module 14: Secure OS Release, Updates, Rollback & Deployment Management
  osReleases: '/api/v1/os/releases',
  osReleaseById: (id) => `/api/v1/os/releases/${id}`,
  osReleaseValidate: (id) => `/api/v1/os/releases/${id}/validate`,
  osReleaseApprove: (id) => `/api/v1/os/releases/${id}/approve`,
  osReleaseActivate: (id) => `/api/v1/os/releases/${id}/activate`,
  osReleaseSuspend: (id) => `/api/v1/os/releases/${id}/suspend`,
  osReleaseRevoke: (id) => `/api/v1/os/releases/${id}/revoke`,
  osReleaseRetire: (id) => `/api/v1/os/releases/${id}/retire`,
  osDeployments: '/api/v1/os/deployments',
  osDeploymentById: (id) => `/api/v1/os/deployments/${id}`,
  osDeviceUpdateCheck: (id) => `/api/v1/os/devices/${id}/update`,
  osDeviceUpdateEvents: (id) => `/api/v1/os/devices/${id}/update-events`,
  osDeviceVerifyRelease: (id) => `/api/v1/os/devices/${id}/verify-release`,
  osDeviceRecovery: (id) => `/api/v1/os/devices/${id}/recovery`,

  // Platform exam lifecycle
  platformExamsCreate: '/api/v1/platform/exams/create',
  platformExamById: (id) => `/api/v1/platform/exams/${id}`,
  platformExamValidate: (id) => `/api/v1/platform/exams/${id}/validate`,
  platformExamApprove: (id) => `/api/v1/platform/exams/${id}/approve`,
  platformExamState: (id) => `/api/v1/platform/exams/${id}/state`,
  platformExamRoster: (id) => `/api/v1/platform/exams/${id}/roster`,
  platformExamCheckin: (id) => `/api/v1/platform/exams/${id}/checkin`,
  platformExamSubmissions: (id) => `/api/v1/platform/exams/${id}/submissions`,
  platformExamReadiness: (id) => `/api/v1/platform/exams/${id}/readiness`,
  platformExamUrl: (id) => `/api/v1/platform/exams/${id}/url`,
  platformExamSchedule: (id) => `/api/v1/platform/exams/${id}/schedule`,
  platformExamPolicyRollback: (id) => `/api/v1/platform/exams/${id}/policy/rollback`,
  platformExamSessions: '/api/v1/platform/exams/sessions',
  platformExamSessionState: (id) => `/api/v1/platform/exams/sessions/${id}/state`,
  platformExamPurge: '/api/v1/platform/exams/purge',

  // Attestation (device/agent)
  attestationNonce: '/api/v1/attestation/nonce',
  attestationVerify: '/api/v1/attestation/verify',
  attestationReAttest: '/api/v1/attestation/re-attest',
  attestationStatus: (id) => `/api/v1/attestation/status?attestation_id=${id}`,
  attestationStatusBySession: (sid) => `/api/v1/attestation/status?session_id=${sid}`,
  attestationRevokeRelease: '/api/v1/admin/revoke/release',
  attestationRevokeDevice: '/api/v1/admin/revoke/device',

  // Exam workbench (candidate)
  examPaper: '/api/v1/exam/paper',
  examSaveAnswer: '/api/v1/exam/save_answer',
  examSubmit: '/api/v1/exam/submit',
  examAnnouncements: '/api/v1/exam/announcements',
  examTerminals: '/api/v1/exam/terminals',
  examCommand: '/api/v1/exam/command',
  examKeyRelease: '/api/v1/exam/key-release',
  examKeyReleaseEligibility: '/api/v1/exam/key-release/eligibility',

  // Proctoring
  proctoringEvents: '/api/v1/proctoring/events',
  proctoringEventsBySession: (sid) => `/api/v1/proctoring/events?session_id=${sid}`,
  proctoringCheckpoint: '/api/v1/proctoring/checkpoint',
  proctoringVerify: '/api/v1/proctoring/verify',

  // Second camera
  secondCameraRequest: '/api/v1/second-camera/request',
  secondCameraPair: '/api/v1/second-camera/pair',

  // Consent
  consent: '/api/v1/consent',

  // Ledger / audit
  ledger: '/api/v1/ledger',

  // Admin actions
  adminReload: '/api/v1/admin/reload',
  adminLock: '/api/v1/admin/lock',
  adminUnlock: '/api/v1/admin/unlock',
  kioskTerminals: '/api/v1/kiosk/terminals',

  // Heartbeat (agent)
  heartbeat: '/api/v1/heartbeat',
};

// Default request timeout (ms).
export const REQUEST_TIMEOUT = 30000;
// Max automatic retries for idempotent requests.
export const MAX_RETRIES = 2;

export const ROLE_NAMES = {
  PLATFORM_OWNER: 'Platform Owner',
  INSTITUTION_ADMIN: 'Institution Admin',
  EXAM_MANAGER: 'Exam Manager',
  SECURITY_ADMIN: 'Security Admin',
  INVIGILATOR: 'Invigilator',
  TECH_OPERATOR: 'Tech Operator',
  INCIDENT_INVESTIGATOR: 'Incident Investigator',
  READONLY_AUDITOR: 'Readonly Auditor',
  SUPPORT_ENGINEER: 'Support Engineer',
};

export const AUTH_TOKEN_KEY = 'examos_admin_session';
export const CANDIDATE_TOKEN_KEY = 'examos_candidate_session';
export const CANDIDATE_ID_KEY = 'examos_candidate_id';
