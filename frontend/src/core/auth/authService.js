// ExamOS Console — Backend auth service.
// Real authentication against the ExamOS C server (server/main.c):
//   POST /api/v1/admin/login    -> admin session (Bearer + admin_session cookie)
//   POST /api/v1/admin/logout   -> revoke admin session
//   GET  /api/v1/admin/session  -> current admin profile
//   POST /api/v1/candidate/login -> candidate session
import { api, setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens, ApiError } from '../api/client';
import { ENDPOINTS, AUTH_TOKEN_KEY, CANDIDATE_TOKEN_KEY, CANDIDATE_ID_KEY } from '../../config/api';
import { put } from '../db/db';
import { sha256 } from '../security/crypto';
import { audit } from '../security/auditClient';

const STORAGE_PREFIX = 'examos_';

function loadStored(key) {
  try { return sessionStorage.getItem(`${STORAGE_PREFIX}${key}`); } catch { return null; }
}
function storeItem(key, value) {
  try { sessionStorage.setItem(`${STORAGE_PREFIX}${key}`, value); } catch {}
}
function removeItem(key) {
  try { sessionStorage.removeItem(`${STORAGE_PREFIX}${key}`); } catch {}
}

export class AuthService {
  constructor() {
    this.adminToken = loadStored(AUTH_TOKEN_KEY) || null;
    this.candidateToken = loadStored(CANDIDATE_TOKEN_KEY) || null;
    this.candidateId = loadStored(CANDIDATE_ID_KEY) || null;
    this.adminProfile = null;
    this.candidateProfile = null;
    if (this.adminToken) setAdminToken(this.adminToken);
    if (this.candidateToken) setCandidateToken(this.candidateToken);
  }

  /* ---------- Admin auth ---------- */

  async adminLogin({ username, password, mfaCode }) {
    const res = await api.post(ENDPOINTS.adminLogin, {
      username,
      password,
      mfa_code: mfaCode || null,
    }, { actor: 'admin', sign: true });

    const data = res.data;
    if (data.status === 'MFA_SETUP_REQUIRED' || data.mfa_setup_required) {
      return { mfaSetupRequired: true, username: data.username || username, message: data.message };
    }
    if (data.status === 'MFA_REQUIRED') {
      return { mfaRequired: true, username: data.username || username };
    }
    if (data.status !== 'AUTHENTICATED') {
      throw new ApiError(res.status, data.error || 'Login failed', data);
    }

    this.adminToken = data.token;
    setAdminToken(this.adminToken);
    storeItem(AUTH_TOKEN_KEY, this.adminToken);

    // Fetch profile to populate role/institution.
    try {
      const prof = await api.get(ENDPOINTS.adminSession, { actor: 'admin' });
      this.adminProfile = prof.data;
    } catch (e) {
      this.adminProfile = {
        username: data.username || username,
        role: data.role || 'PLATFORM_OWNER',
        institution_id: data.institution_id || '',
        name: data.name || username,
        user_id: data.user_id,
      };
    }

    await audit.record({
      actor: 'admin', event: 'ADMIN_LOGIN', detail: `user=${username}`,
      resource: '/api/v1/admin/login', severity: 'info',
    });
    return { ok: true, profile: this.adminProfile };
  }

  async adminLogout() {
    try {
      await api.post(ENDPOINTS.adminLogout, {}, { actor: 'admin', sign: true });
    } catch { /* ignore logout errors */ }
    this.adminToken = null;
    this.adminProfile = null;
    setAdminToken(null);
    removeItem(AUTH_TOKEN_KEY);
    await audit.record({ actor: 'admin', event: 'ADMIN_LOGOUT', resource: '/api/v1/admin/logout', severity: 'info' });
    return { ok: true };
  }

  async getAdminProfile() {
    if (!this.adminToken) return null;
    const prof = await api.get(ENDPOINTS.adminSession, { actor: 'admin' });
    this.adminProfile = prof.data;
    return prof.data;
  }

  /* ---------- MFA Enrollment & Recovery ---------- */

  async mfaSetup(username) {
    const res = await api.post(ENDPOINTS.mfaSetup, {
      username: username || (this.adminProfile?.username || ''),
    }, { actor: 'admin', sign: true });
    return res.data;
  }

  async mfaConfirm({ username, secret, code, recoveryCodes }) {
    const res = await api.post(ENDPOINTS.mfaConfirm, {
      username: username || (this.adminProfile?.username || ''),
      secret,
      code,
      recovery_codes: recoveryCodes || [],
    }, { actor: 'admin', sign: true });
    return res.data;
  }

  async recoveryReset({ username, code, newPassword }) {
    const res = await api.post(ENDPOINTS.recoveryReset, {
      username,
      code,
      new_password: newPassword,
    }, { actor: 'admin', sign: true });
    return res.data;
  }

  getAdminToken() { return this.adminToken; }
  isAdminAuthenticated() { return !!this.adminToken; }

  /* ---------- Candidate auth ---------- */

  async candidateLogin({ candidateId, pin }) {
    const res = await api.post(ENDPOINTS.candidateLogin, {
      candidate_id: candidateId,
      pin,
    }, { useCandidateToken: true, actor: 'candidate', sign: true });

    const data = res.data;
    if (data.status !== 'SUCCESS') {
      throw new ApiError(res.status, data.error || 'Candidate login failed', data);
    }

    this.candidateToken = data.token;
    this.candidateId = candidateId;
    setCandidateToken(this.candidateToken);
    storeItem(CANDIDATE_TOKEN_KEY, this.candidateToken);
    storeItem(CANDIDATE_ID_KEY, candidateId);

    this.candidateProfile = {
      candidateId,
      examName: data.exam_name || null,
      examUrl: data.exam_url || null,
    };

    await audit.record({
      actor: 'candidate', event: 'CANDIDATE_LOGIN', detail: `candidate=${candidateId}`,
      resource: '/api/v1/candidate/login', severity: 'info',
    });
    return { ok: true, profile: this.candidateProfile };
  }

  async candidateLogout() {
    this.candidateToken = null;
    this.candidateId = null;
    this.candidateProfile = null;
    setCandidateToken(null);
    removeItem(CANDIDATE_TOKEN_KEY);
    removeItem(CANDIDATE_ID_KEY);
    await audit.record({ actor: 'candidate', event: 'CANDIDATE_LOGOUT', resource: '/api/v1/candidate/login', severity: 'info' });
    return { ok: true };
  }

  getCandidateToken() { return this.candidateToken; }
  getCandidateId() { return this.candidateId; }
  isCandidateAuthenticated() { return !!this.candidateToken; }

  /* ---------- Utilities ---------- */

  async health() {
    return api.get(ENDPOINTS.health, { actor: 'console', sign: false });
  }

  async status() {
    return api.get(ENDPOINTS.status, { actor: 'console', sign: false });
  }

  clearAll() {
    clearTokens();
    this.adminToken = null;
    this.candidateToken = null;
    this.candidateId = null;
    this.adminProfile = null;
    this.candidateProfile = null;
    removeItem(AUTH_TOKEN_KEY);
    removeItem(CANDIDATE_TOKEN_KEY);
    removeItem(CANDIDATE_ID_KEY);
  }
}

export const authService = new AuthService();
