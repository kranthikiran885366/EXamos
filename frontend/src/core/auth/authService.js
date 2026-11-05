// ExamOS Console — Backend auth service.
//
// ALL authentication state is owned exclusively by the ExamOS C server.
// Nothing is stored in localStorage, sessionStorage, or IndexedDB:
//
//   • Admin session   — durable via HttpOnly admin_session cookie (server-set).
//                       Bearer token held in JS heap only; cleared on page unload.
//   • Candidate session — Bearer token held in JS heap only.
//                         The kiosk tab is short-lived; no persistence needed.
//   • Credentials, TOTP secrets, password hashes, recovery codes — never in browser.
//
// C server routes:
//   POST /api/v1/admin/login         -> admin session
//   POST /api/v1/admin/logout        -> revoke admin session
//   GET  /api/v1/admin/session       -> current admin profile (validates cookie)
//   POST /api/v1/admin/mfa/setup     -> TOTP enrollment
//   POST /api/v1/admin/mfa/confirm   -> confirm enrollment
//   POST /api/v1/admin/recovery/reset -> account recovery with recovery code
//   POST /api/v1/admin/password/change -> change password
//   POST /api/v1/candidate/login     -> candidate session
//   POST /api/v1/candidate/logout    -> revoke candidate session
import { api, setAdminToken, setCandidateToken, clearTokens, ApiError } from '../api/client';
import { ENDPOINTS } from '../../config/api';
import { audit } from '../security/auditClient';

export class AuthService {
  constructor() {
    // Tokens live in JS heap only — never read back from any storage.
    this.adminToken     = null;
    this.candidateToken = null;
    this.candidateId    = null;
    this.adminProfile   = null;
    this.candidateProfile = null;
  }

  /* ─────────────────────────── Admin auth ──────────────────────────── */

  async adminLogin({ username, password, mfaCode }) {
    const res = await api.post(ENDPOINTS.adminLogin, {
      username,
      password,
      mfa_code: mfaCode || null,
    }, { actor: 'admin', sign: true });

    const data = res.data;

    if (data.status === 'MFA_SETUP_REQUIRED' || data.mfa_setup_required) {
      return {
        mfaSetupRequired: true,
        username: data.username || username,
        enrollmentToken: data.enrollment_token || null,
        message: data.message,
      };
    }

    if (data.status === 'MFA_REQUIRED') {
      return { mfaRequired: true, username: data.username || username };
    }

    if (data.status !== 'AUTHENTICATED') {
      throw new ApiError(res.status, data.error || 'Login failed', data);
    }

    // Keep token in memory only — HttpOnly cookie provides durable continuity.
    this.adminToken = data.token;
    setAdminToken(this.adminToken);

    // Fetch full profile from server (role, institution, name).
    try {
      const prof = await api.get(ENDPOINTS.adminSession, { actor: 'admin' });
      this.adminProfile = prof.data;
    } catch {
      this.adminProfile = {
        user_id: data.user_id,
        username: data.username || username,
        role: data.role,
        institution_id: data.institution_id || '',
        name: data.name || username,
      };
    }

    await audit.record({
      actor: 'admin', event: 'ADMIN_LOGIN',
      detail: `user=${username}`, resource: ENDPOINTS.adminLogin, severity: 'info',
    });
    return { ok: true, profile: this.adminProfile };
  }

  async adminLogout() {
    try {
      await api.post(ENDPOINTS.adminLogout, {}, { actor: 'admin', sign: true });
    } catch { /* best-effort — server revokes the cookie regardless */ }
    this.adminToken   = null;
    this.adminProfile = null;
    setAdminToken(null);
    await audit.record({
      actor: 'admin', event: 'ADMIN_LOGOUT',
      resource: ENDPOINTS.adminLogout, severity: 'info',
    });
    return { ok: true };
  }

  // Called on page load to restore session from the HttpOnly cookie.
  // Returns the profile object if a valid session exists, null otherwise.
  async getAdminProfile() {
    try {
      const prof = await api.get(ENDPOINTS.adminSession, { actor: 'admin' });
      this.adminProfile = prof.data;
      return prof.data;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return null;
      if (!this.adminToken) return null;
      throw err;
    }
  }

  /* ─────────────────────── MFA enrollment & recovery ───────────────── */

  async mfaSetup(enrollmentToken) {
    const headers = enrollmentToken ? { 'X-Enrollment-Token': enrollmentToken } : undefined;
    const res = await api.post(ENDPOINTS.mfaSetup, {}, { actor: 'admin', sign: true, headers });
    return res.data;
  }

  async mfaConfirm({ enrollmentToken, code }) {
    const headers = enrollmentToken ? { 'X-Enrollment-Token': enrollmentToken } : undefined;
    const res = await api.post(ENDPOINTS.mfaConfirm, { code }, { actor: 'admin', sign: true, headers });
    return res.data;
  }

  async recoveryReset({ username, code, newPassword }) {
    const res = await api.post(ENDPOINTS.recoveryReset, {
      username, code, new_password: newPassword,
    }, { actor: 'admin', sign: true });
    return res.data;
  }

  async changePassword({ currentPassword, newPassword }) {
    const res = await api.post(ENDPOINTS.passwordChange, {
      current_password: currentPassword,
      new_password: newPassword,
    }, { actor: 'admin', sign: true });
    return res.data;
  }

  /* ─────────────────────── Server-side session management ──────────── */

  async listSessions() {
    const path = ENDPOINTS.adminSessions || '/api/v1/admin/sessions';
    const res = await api.get(path, { actor: 'admin' });
    return res.data?.sessions || res.data || [];
  }

  async revokeSession(sid) {
    const base = ENDPOINTS.adminSessions || '/api/v1/admin/sessions';
    const res = await api.del(`${base}/${encodeURIComponent(sid)}`, { actor: 'admin', sign: true });
    return res.data;
  }

  async revokeOtherSessions() {
    const path = ENDPOINTS.revokeOtherSessions || '/api/v1/admin/sessions/others';
    const res = await api.post(path, {}, { actor: 'admin', sign: true });
    return res.data;
  }

  /* ─────────────────────────── Candidate auth ──────────────────────── */

  async candidateLogin({ candidateId, pin }) {
    const res = await api.post(ENDPOINTS.candidateLogin, {
      candidate_id: candidateId, pin,
    }, { useCandidateToken: true, actor: 'candidate', sign: true });

    const data = res.data;
    if (data.status !== 'SUCCESS') {
      throw new ApiError(res.status, data.error || 'Candidate login failed', data);
    }

    // Memory only — candidate kiosk tab is intentionally short-lived.
    this.candidateToken   = data.token;
    this.candidateId      = candidateId;
    this.candidateProfile = {
      candidateId: data.candidate_id || candidateId,
      name:     data.name     || candidateId,
      examId:   data.exam_id  || null,
      examName: data.exam_name || null,
      examUrl:  data.exam_url  || null,
    };
    setCandidateToken(this.candidateToken);

    await audit.record({
      actor: 'candidate', event: 'CANDIDATE_LOGIN',
      detail: `candidate=${candidateId}`, resource: ENDPOINTS.candidateLogin, severity: 'info',
    });
    return { ok: true, profile: this.candidateProfile };
  }

  async candidateLogout() {
    try {
      await api.post(ENDPOINTS.candidateLogout, {}, {
        useCandidateToken: true, actor: 'candidate', sign: true,
      });
    } catch { /* best-effort */ }
    this.candidateToken   = null;
    this.candidateId      = null;
    this.candidateProfile = null;
    setCandidateToken(null);
    await audit.record({
      actor: 'candidate', event: 'CANDIDATE_LOGOUT',
      resource: ENDPOINTS.candidateLogout, severity: 'info',
    });
    return { ok: true };
  }

  /* ─────────────────────────── Utilities ───────────────────────────── */

  async health() {
    return api.get(ENDPOINTS.health, { actor: 'console', sign: false });
  }

  async status() {
    return api.get(ENDPOINTS.status, { actor: 'console', sign: false });
  }

  getAdminToken()           { return this.adminToken; }
  isAdminAuthenticated()    { return !!this.adminToken; }
  getCandidateToken()       { return this.candidateToken; }
  getCandidateId()          { return this.candidateId; }
  isCandidateAuthenticated(){ return !!this.candidateToken; }

  clearAll() {
    clearTokens();
    this.adminToken       = null;
    this.candidateToken   = null;
    this.candidateId      = null;
    this.adminProfile     = null;
    this.candidateProfile = null;
  }
}

export const authService = new AuthService();
