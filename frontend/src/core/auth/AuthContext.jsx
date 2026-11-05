// ExamOS Console — Auth context (100% backend-driven, zero local storage).
//
// ┌─ Auth realms ────────────────────────────────────────────────────────────┐
// │  Admin / operator  →  POST /api/v1/admin/login                           │
// │                        Bearer token (in-memory) + HttpOnly cookie        │
// │  Candidate exam    →  POST /api/v1/candidate/login                       │
// │                        Bearer token (in-memory only)                     │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Storage policy (STRICT):
//   • Credentials, passwords, TOTP secrets, recovery codes → server only.
//   • Session tokens → JS heap only (never localStorage / sessionStorage / IDB).
//   • Admin session continuity → HttpOnly admin_session cookie (server-set).
//   • Profile / role data → fetched live from /api/v1/admin/session on load.
//   • Audit events → sent to server /api/v1/ledger via auditClient.
//   • IndexedDB is NOT used anywhere in this file.

import { createContext, useContext, useState, useRef, useCallback, useEffect } from 'react';
import { record } from '../security/auditChain';
import { roleLabel } from '../security/rbac';
import { pwIssues } from '../../modules/users/service';
import { authService } from './authService';
import { ApiError, clearTokens } from '../api/client';

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

const BACKEND_ROLE_MAP = {
  PLATFORM_OWNER:         'superadmin',
  INSTITUTION_ADMIN:      'inst_admin',
  EXAM_MANAGER:           'exam_controller',
  SECURITY_ADMIN:         'security_engineer',
  INVIGILATOR:            'invigilator',
  TECH_OPERATOR:          'ops_admin',
  INCIDENT_INVESTIGATOR:  'auditor',
  READONLY_AUDITOR:       'auditor',
  SUPPORT_ENGINEER:       'support',
};

function normalizeRole(r) {
  if (!r) return 'auditor';
  const up = String(r).toUpperCase();
  return BACKEND_ROLE_MAP[up] || String(r).toLowerCase();
}

function publicUser(u) {
  const role = normalizeRole(u.role);
  const isCandidate = role === 'student' || role === 'candidate' || !!u.candidateId;
  return {
    id:          u.id,
    username:    u.username  || u.id,
    name:        u.name      || u.username || 'User',
    initials:   (u.name || u.username || 'US').slice(0, 2).toUpperCase(),
    role,
    rawRole:     u.role,
    title:       u.title || roleLabel(role),
    tenantId:    u.tenantId || u.institution_id || null,
    candidateId: u.candidateId || null,
    mfaEnabled:  isCandidate ? false : (u.mfaEnabled !== false),
    email:       u.email || '',
    lastLogin:   u.lastLogin || null,
  };
}

export function AuthProvider({ children }) {
  // ── React state (in-memory only, no persistence) ──────────────────────────
  const [user,               setUser]               = useState(null);
  const [pending,            setPending]            = useState(null);   // username waiting for MFA
  const [pendingCredentials, setPendingCredentials] = useState(null);   // {username,password} during MFA
  const enrollmentRef                               = useRef(null);     // single-use enrollment token
  const [locked,             setLocked]             = useState(false);
  const [backendMode,        setBackendMode]        = useState('none'); // 'none'|'admin'|'candidate'
  const [backendReady,       setBackendReady]       = useState(false);
  const fails                                       = useRef({ n: 0, until: 0 });

  // ── Client-side request throttle (supplements server brute-force lockout) ─
  const throttle = () => {
    const wait = fails.current.until - Date.now();
    return wait > 0
      ? `Too many attempts. Try again in ${Math.ceil(wait / 1000)}s.`
      : null;
  };
  const failAttempt = (who, why) => {
    const n = ++fails.current.n;
    if (n >= 5) fails.current.until = Date.now() + Math.min(300000, 30000 * 2 ** (n - 5));
    record(who, why);
  };

  // ── Establish session state after the server returns a valid profile ───────
  const beginSession = useCallback((u) => {
    setUser(publicUser(u));
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    record(u.id, 'LOGIN_SUCCESS', `backend=${backendMode || 'admin'}`);
    return publicUser(u);
  }, [backendMode]);

  // ── On mount: probe server health and restore session from HttpOnly cookie ─
  useEffect(() => {
    let cancelled = false;
    let restored  = false;

    const probe = async () => {
      try {
        await authService.health();
        if (cancelled) return;
        setBackendReady(true);

        if (!restored) {
          restored = true;
          authService.getAdminProfile().then((profile) => {
            if (profile?.username && !cancelled) {
              setUser(publicUser({
                id:           profile.user_id || profile.username,
                username:     profile.username,
                name:         profile.name || profile.full_name || profile.username,
                role:         profile.role || '',
                tenantId:     profile.institution_id || null,
                email:        profile.email || '',
                mfaEnabled:   profile.mfa_enabled !== false,
              }));
              setBackendMode('admin');
            }
          }).catch(() => {});
        }
      } catch {
        if (!cancelled) setBackendReady(false);
      }
    };

    probe();
    const interval = setInterval(probe, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // ── MFA verification — server only ────────────────────────────────────────
  // Only called after backendLogin returns { mfa: true }.
  // pendingCredentials is guaranteed to be set at this point.
  const verifyMfa = useCallback(async (code) => {
    const err = throttle(); if (err) return { error: err };
    if (!pending || !pendingCredentials) return { error: 'Session expired. Sign in again.' };

    try {
      const result = await authService.adminLogin({
        username: pendingCredentials.username,
        password: pendingCredentials.password,
        mfaCode:  code,
      });

      if (result.mfaRequired) {
        failAttempt(pendingCredentials.username, 'MFA_FAILED');
        return { error: 'The verification code was not accepted. Check the latest code in your authenticator app, or use a valid unused recovery code.' };
      }

      const profile = result.profile || {};
      fails.current = { n: 0, until: 0 };
      setBackendMode('admin');
      setPendingCredentials(null);
      setPending(null);
      beginSession({
        id:       profile.user_id || pendingCredentials.username,
        username: profile.username || pendingCredentials.username,
        name:     profile.name || profile.full_name || pendingCredentials.username,
        role:     profile.role || '',
        tenantId: profile.institution_id || null,
        email:    profile.email || '',
      });
      return { ok: true, profile };
    } catch (e) {
      failAttempt(pendingCredentials?.username || pending, 'MFA_FAILED');
      return { error: e.message || 'MFA verification failed' };
    }
  }, [pending, pendingCredentials, beginSession]);

  const cancelPending = useCallback(() => {
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
  }, []);

  // ── Admin login — server only ─────────────────────────────────────────────
  const backendLogin = useCallback(async ({ username, password, mfaCode }) => {
    let ready = backendReady;
    if (!ready) {
      try { await authService.health(); ready = true; setBackendReady(true); }
      catch { return { error: 'ExamOS server is unreachable. Check that the backend is running on port 8895.' }; }
    }
    try {
      const result = await authService.adminLogin({ username, password, mfaCode });

      if (result.mfaSetupRequired) {
        enrollmentRef.current = result.enrollmentToken || null;
        setPendingCredentials({ username, password });
        setPending(username);
        return { mfaSetupRequired: true, username: result.username || username, enrollmentToken: result.enrollmentToken || null };
      }
      if (result.mfaRequired) {
        enrollmentRef.current = null;
        setPendingCredentials({ username, password });
        setPending(username);
        return { mfa: true };
      }

      setPendingCredentials(null);
      setPending(null);
      enrollmentRef.current = null;
      const profile = result.profile || {};
      fails.current = { n: 0, until: 0 };
      setBackendMode('admin');
      beginSession({
        id:       profile.user_id || username,
        username: profile.username || username,
        name:     profile.name || profile.full_name || username,
        role:     profile.role || '',
        tenantId: profile.institution_id || null,
        email:    profile.email || '',
      });
      return { ok: true, profile };
    } catch (e) {
      setPendingCredentials(null);
      setPending(null);
      enrollmentRef.current = null;
      failAttempt(username, 'LOGIN_FAILED');
      return { error: e.message || 'Authentication failed' };
    }
  }, [backendReady, beginSession]);

  const backendLogout = useCallback(async () => {
    try { await authService.adminLogout(); } catch {}
    setBackendMode('none');
    setUser(null);
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    clearTokens();
  }, []);

  // ── Candidate login — server only ─────────────────────────────────────────
  const backendCandidateLogin = useCallback(async ({ candidateId, pin, examToken, onPending }) => {
    let ready = backendReady;
    if (!ready) {
      try { await authService.health(); ready = true; setBackendReady(true); }
      catch { return { error: 'ExamOS server is unreachable. Check that the backend is running on port 8895.' }; }
    }
    try {
      const result = await authService.candidateLogin({ candidateId, pin, examToken, onPending });
      setBackendMode('candidate');
      const profile = result.profile || {};
      setUser(publicUser({
        id:          profile.candidateId || candidateId,
        username:    candidateId,
        name:        profile.name || candidateId,
        role:        'student',
        candidateId,
        examId:      profile.examId,
        examName:    profile.examName,
        examUrl:     profile.examUrl,
      }));
      return { ok: true, profile };
    } catch (e) {
      failAttempt(candidateId, 'CANDIDATE_LOGIN_FAILED');
      return { error: e.message || 'Candidate authentication failed' };
    }
  }, [backendReady]);

  const backendCandidateLogout = useCallback(async () => {
    try { await authService.candidateLogout(); } catch {}
    setBackendMode('none');
    setUser(null);
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    clearTokens();
  }, []);

  // ── Re-authentication (screen lock / sensitive action) ────────────────────
  const reauth = useCallback(async (password) => {
    const err = throttle(); if (err) return { error: err };
    if (!user) return { error: 'Not signed in.' };
    if (backendMode !== 'admin') {
      failAttempt(user?.id || 'unknown', 'REAUTH_FAILED');
      return { error: 'This session cannot be re-authenticated. Sign in again.' };
    }
    try {
      const r = await authService.adminLogin({ username: user.username || user.id, password });
      if (r.ok || r.mfaRequired || r.mfaSetupRequired) {
        fails.current = { n: 0, until: 0 };
        record(user.id, 'REAUTH_OK');
        return { ok: true };
      }
    } catch {}
    failAttempt(user.id, 'REAUTH_FAILED');
    return { error: 'Password verification failed.' };
  }, [user, backendMode]);

  const logout = useCallback(async (why = 'LOGOUT') => {
    if (backendMode === 'admin')     { await backendLogout();          return; }
    if (backendMode === 'candidate') { await backendCandidateLogout(); return; }
    if (user) record(user.id, why);
    setUser(null);
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    clearTokens();
  }, [user, backendMode, backendLogout, backendCandidateLogout]);

  const lock   = useCallback(() => { if (user) record(user.id, 'SESSION_LOCKED'); setLocked(true); }, [user]);
  const unlock = useCallback(async (password) => {
    const r = await reauth(password);
    if (r.ok) setLocked(false);
    return r;
  }, [reauth]);

  // ── Password change — server only ─────────────────────────────────────────
  const changePassword = useCallback(async (current, next) => {
    if (!user) return { error: 'Not signed in.' };
    const bad = pwIssues(next || '');
    if (bad.length) return { error: 'New password needs ' + bad.join(', ') + '.' };
    if (backendMode !== 'admin') return { error: 'Password changes require an active admin session.' };
    try {
      const res = await authService.changePassword({ currentPassword: current, newPassword: next });
      if (res?.status === 'SUCCESS' || res?.ok) {
        record(user.id, 'PASSWORD_CHANGED');
        return { ok: true };
      }
      return { error: res?.error || 'Password change failed.' };
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        record(user.id, 'PASSWORD_CHANGE_FAILED');
        return { error: 'Current password is incorrect.' };
      }
      return { error: e.message || 'Password change failed.' };
    }
  }, [user, backendMode]);

  // ── Recovery / MFA rotation — server only ────────────────────────────────
  const regenerateRecovery = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    return { error: 'Recovery codes are managed server-side. Use Authenticator setup or account recovery to rotate them.' };
  }, [user]);

  const rotateMfa = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    return { error: 'Authenticator rotation must be completed through the server enrollment flow.' };
  }, [user]);

  const resetWithRecovery = useCallback(async (username, code, next) => {
    const err = throttle(); if (err) return { error: err };
    if (!backendReady) return { error: 'ExamOS server is unreachable. Account recovery requires a live server connection.' };
    try {
      const res = await authService.recoveryReset({ username, code, newPassword: next });
      if (res.status === 'SUCCESS' || res.ok) {
        fails.current = { n: 0, until: 0 };
        return { ok: true, message: res.message };
      }
      failAttempt(username || 'anonymous', 'RECOVERY_FAILED');
      return { error: res.error || 'Password recovery failed' };
    } catch (e) {
      failAttempt(username || 'anonymous', 'RECOVERY_FAILED');
      return { error: e.message || 'Failed to reset password via recovery code' };
    }
  }, [backendReady]);

  // ── MFA enrollment — server only ─────────────────────────────────────────
  const mfaSetup = useCallback(async () => {
    if (!backendReady) return { error: 'ExamOS server is unreachable. Authenticator enrollment cannot complete offline.' };
    try {
      const res = await authService.mfaSetup(enrollmentRef.current);
      if (res?.error) return { error: res.error };
      if (!res?.secret || !res?.otpauth_url) return { error: 'Server did not return an authenticator secret. Sign in again.' };
      if (res.enrollment_token) enrollmentRef.current = res.enrollment_token;
      return res;
    } catch (e) {
      return { error: e.message || 'Failed to initialize Google Authenticator' };
    }
  }, [backendReady]);

  const mfaConfirm = useCallback(async ({ code }) => {
    if (!backendReady) return { error: 'ExamOS server is unreachable. Authenticator enrollment cannot complete offline.' };
    try {
      const res = await authService.mfaConfirm({ enrollmentToken: enrollmentRef.current, code });
      if (res?.status === 'SUCCESS' || res?.ok) return { ok: true, status: 'SUCCESS' };
      return { error: res?.error || 'Invalid authenticator code. Check your device clock.' };
    } catch (e) {
      return { error: e.message || 'Failed to activate Google Authenticator' };
    }
  }, [backendReady]);

  // ── Session management — server-authoritative ─────────────────────────────
  const listSessions = useCallback(async () => {
    if (!user) return [];
    try {
      const res = await authService.listSessions();
      return Array.isArray(res) ? res : (res?.sessions || []);
    } catch { return []; }
  }, [user]);

  const revokeSession = useCallback(async (sid) => {
    if (!user) return { error: 'Not signed in.' };
    try {
      await authService.revokeSession(sid);
      record(user.id, 'SESSION_REVOKED', sid);
      return { ok: true };
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return { ok: true }; // already gone
      return { error: e.message || 'Failed to revoke session.' };
    }
  }, [user]);

  const revokeOthers = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    try {
      const res = await authService.revokeOtherSessions();
      const count = res?.count ?? 0;
      record(user.id, 'SESSIONS_REVOKED_ALL', `count=${count}`);
      return { ok: true, count };
    } catch (e) {
      return { error: e.message || 'Failed to revoke sessions.' };
    }
  }, [user]);

  // touchSession pings the server to confirm the session is still valid.
  const touchSession = useCallback(async () => {
    if (!user || backendMode !== 'admin') return;
    try { await authService.getAdminProfile(); } catch {}
  }, [user, backendMode]);

  return (
    <Ctx.Provider value={{
      user, pending, pendingCredentials, locked, backendMode, backendReady,
      verifyMfa, cancelPending,
      backendLogin, backendLogout,
      backendCandidateLogin, backendCandidateLogout,
      reauth, logout, lock, unlock,
      changePassword, regenerateRecovery, rotateMfa,
      mfaSetup, mfaConfirm, resetWithRecovery,
      touchSession, listSessions, revokeSession, revokeOthers,
    }}>
      {children}
    </Ctx.Provider>
  );
}
