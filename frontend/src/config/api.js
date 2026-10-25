// ExamOS Console — Backend API configuration
// Integrates with the ExamOS C server (D:\SEB BRO\server) running on port 8000.
// In dev mode, Vite proxies /api/* requests to localhost:8000 so the frontend
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

  // Auth — candidate
  candidateLogin: '/api/v1/candidate/login',

  // Admin platform
  institutions: '/api/v1/admin/institutions',
  institutionById: (id) => `/api/v1/admin/institutions/${id}`,
  exams: '/api/v1/admin/exams',
  roles: '/api/v1/admin/roles',
  users: '/api/v1/admin/users',
  campuses: '/api/v1/admin/campuses',
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
