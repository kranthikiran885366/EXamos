// ExamOS Console — Auth context (hybrid: real backend + local IndexedDB fallback).
//
// Supports two authentication realms against the ExamOS C server:
//   • Admin/operator console login  -> POST /api/v1/admin/login  (Bearer + admin_session cookie)
//   • Candidate exam login          -> POST /api/v1/candidate/login (Bearer token)
// Falls back to local IndexedDB users when the backend is unreachable (demo mode).
import { createContext, useContext, useState, useRef, useCallback, useEffect } from 'react';
import { all, get, put } from '../db/db';
import { sha256, randomId } from '../security/crypto';
import { verifyTotp } from '../security/totp';
import { clean } from '../security/sanitize';
import { record } from '../security/auditChain';
import { roleLabel } from '../security/rbac';
import { pwIssues } from '../../modules/users/service';
import { authService } from './authService';
import { ApiError, setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens } from '../api/client';
import { AUTH_TOKEN_KEY, CANDIDATE_TOKEN_KEY, CANDIDATE_ID_KEY } from '../../config/api';
import { syncAll } from '../api/sync';

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

const GENERIC = 'Invalid username or password, or the account is not active.';
const normCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

const BACKEND_ROLE_MAP = {
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

function normalizeRole(r) {
  if (!r) return 'auditor';
  const up = String(r).toUpperCase();
  if (BACKEND_ROLE_MAP[up]) return BACKEND_ROLE_MAP[up];
  return String(r).toLowerCase();
}

function publicUser(u) {
  const role = normalizeRole(u.role);
  const isStudent = role === 'student' || role === 'candidate' || !!u.candidateId;
  return {
    id: u.id,
    username: u.username || u.id,
    name: u.name || u.username || 'User',
    initials: u.initials || (u.name || u.username || 'US').slice(0, 2).toUpperCase(),
    role: role,
    rawRole: u.role,
    title: u.title || roleLabel(role),
    tenantId: u.tenantId || u.institution_id || null,
    candidateId: u.candidateId || null,
    mfaEnabled: isStudent ? false : (u.mfaEnabled !== false),
    email: u.email || '',
    lastLogin: u.lastLogin || null,
  };
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [pending, setPending] = useState(null);
  const [pendingCredentials, setPendingCredentials] = useState(null); // in-memory during MFA challenge
  const enrollmentRef = useRef(null); // single-use token from MFA_SETUP_REQUIRED
  const [locked, setLocked] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [backendMode, setBackendMode] = useState('none'); // 'none' | 'admin' | 'candidate'
  const [backendReady, setBackendReady] = useState(false);
  const fails = useRef({ n: 0, until: 0 });
  const used = useRef(new Set());

  const throttle = () => {
    const w = fails.current.until - Date.now();
    return w > 0 ? `Too many attempts. Try again in ${Math.ceil(w / 1000)}s.` : null;
  };
  const fail = (who, why) => {
    const n = ++fails.current.n;
    if (n >= 5) fails.current.until = Date.now() + Math.min(300000, 30000 * 2 ** (n - 5));
    record(who, why);
  };
  const beginSession = useCallback(async (u) => {
    const sid = 'ase_' + randomId(6);
    const ua = typeof navigator !== 'undefined' ? navigator.userAgent.slice(0, 180) : 'unknown';
    await put('authSessions', {
      id: sid,
      userId: u.id,
      createdAt: Date.now(),
      lastSeen: Date.now(),
      current: true,
      userAgent: ua,
      ip: 'local',
      status: 'active'
    });
    setSessionId(sid);
    const fresh = { ...u, lastLogin: Date.now() };
    await put('users', fresh);
    setUser(publicUser(fresh));
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    record(u.id, 'LOGIN_SUCCESS', 'mfa=verified');
    return publicUser(fresh);
  }, []);

  // Detect backend availability & restore active session on mount + polling
  useEffect(() => {
    let cancelled = false;
    let initialRestored = false;

    const probe = async () => {
      try {
        await authService.health();
        if (cancelled) return;
        setBackendReady(true);
        if (!initialRestored) {
          initialRestored = true;
          authService.getAdminProfile()
            .then((profile) => {
              if (profile && profile.username && !cancelled) {
                const u = {
                  id: profile.user_id || profile.username,
                  username: profile.username,
                  name: profile.name || profile.full_name || profile.username,
                  role: profile.role || '',
                  tenantId: profile.institution_id || null,
                  email: profile.email || '',
                  status: 'active',
                };
                setUser(publicUser(u));
                setBackendMode('admin');
                try { syncAll({ force: false }); } catch {}
              }
            })
            .catch(() => {});
        }
      } catch {
        if (!cancelled) setBackendReady(false);
      }
    };

    probe();
    const interval = setInterval(probe, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  /*
   * There is deliberately no local (IndexedDB) credential login.  Accounts and
   * password verification live in the ExamOS server only; keeping a local copy
   * created a second, weaker authentication realm that survived backend
   * outages and credential revocations.
   */

  /* ---------- Unified MFA verification ---------- */
  const verifyMfa = useCallback(async (code) => {
    const e = throttle(); if (e) return { error: e };
    if (!pending) return { error: 'Session expired. Sign in again.' };

    // 1. Backend verification flow
    if (pendingCredentials) {
      try {
        const result = await authService.adminLogin({
          username: pendingCredentials.username,
          password: pendingCredentials.password,
          mfaCode: code,
        });

        if (result.mfaRequired) {
          return { error: 'Invalid MFA code or recovery code. Try again.' };
        }

        const profile = result.profile || {};
        const u = {
          id: profile.user_id || pendingCredentials.username,
          username: profile.username || pendingCredentials.username,
          name: profile.name || profile.full_name || pendingCredentials.username,
          role: profile.role || '',
          tenantId: profile.institution_id || null,
          email: profile.email || '',
          status: 'active',
        };
        setBackendMode('admin');
        await beginSession(u);
        setPendingCredentials(null);
        setPending(null);
        try { await syncAll({ force: false }); } catch {}
        return { ok: true, profile };
      } catch (err) {
        return { error: err.message || 'MFA verification failed' };
      }
    }

    // 2. Local IndexedDB verification flow
    const c = String(code).trim();
    const u = await get('users', pending);
    if (!u || u.status !== 'active') return { error: GENERIC };

    if (/^\d{6}$/.test(c)) {
      const stamp = pending + c + Math.floor(Date.now() / 30000);
      if (used.current.has(stamp) || !(await verifyTotp(u.totp, c))) {
        fail(pending, 'MFA_FAILED');
        return { error: 'Invalid or reused code.' };
      }
      used.current.add(stamp);
    } else {
      const h = await sha256(normCode(c));
      const idx = (u.recoveryCodes || []).indexOf(h);
      if (idx < 0) {
        fail(pending, 'MFA_RECOVERY_FAILED');
        return { error: 'Invalid recovery code.' };
      }
      const codes = [...u.recoveryCodes];
      codes.splice(idx, 1);
      await put('users', { ...u, recoveryCodes: codes });
      record(pending, 'MFA_RECOVERY_CODE_USED', `remaining=${codes.length}`);
    }

    fails.current = { n: 0, until: 0 };
    const full = await get('users', pending);
    await beginSession(full);
    return { ok: true };
  }, [pending, pendingCredentials, beginSession]);

  const cancelPending = useCallback(() => {
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
  }, []);

  /* ---------- Backend admin login ---------- */
  const backendLogin = useCallback(async ({ username, password, mfaCode }) => {
    let ready = backendReady;
    if (!ready) {
      try {
        await authService.health();
        ready = true;
        setBackendReady(true);
      } catch {
        /*
         * No local credential fallback.  An unreachable server must never
         * downgrade to IndexedDB accounts: that turns a backend outage into a
         * privilege-escalation path.
         */
        return { error: 'ExamOS server is unreachable. Check that the backend is running on port 8895.' };
      }
    }
    try {
      const result = await authService.adminLogin({ username, password, mfaCode });
      if (result.mfaSetupRequired) {
        enrollmentRef.current = result.enrollmentToken || null;
        setPendingCredentials({ username, password });
        setPending(username);
        return {
          mfaSetupRequired: true,
          username: result.username || username,
          enrollmentToken: result.enrollmentToken || null,
        };
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
      const u = {
        id: profile.user_id || username,
        username: profile.username || username,
        name: profile.name || profile.full_name || username,
        role: profile.role || '',
        tenantId: profile.institution_id || null,
        email: profile.email || '',
        status: 'active',
      };
      setBackendMode('admin');
      await beginSession(u);
      try { await syncAll({ force: false }); } catch {}
      return { ok: true, profile };
    } catch (err) {
      setPendingCredentials(null);
      setPending(null);
      enrollmentRef.current = null;
      /* Backend rejected these credentials. Do not retry against local data. */
      return { error: err.message || 'Authentication failed' };
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
    setSessionId(null);
    clearTokens();
  }, []);

  /* ---------- Backend candidate login ---------- */
  const backendCandidateLogin = useCallback(async ({ candidateId, pin }) => {
    let ready = backendReady;
    if (!ready) {
      try {
        await authService.health();
        ready = true;
        setBackendReady(true);
      } catch {
        return { error: 'ExamOS server is unreachable. Check that the backend is running on port 8895.' };
      }
    }
    try {
      const result = await authService.candidateLogin({ candidateId, pin });
      setBackendMode('candidate');
      const profile = result.profile || {};
      const u = {
        id: profile.candidateId || candidateId,
        username: candidateId,
        name: profile.name || candidateId,
        role: 'student',
        candidateId: candidateId,
        examId: profile.examId,
        examName: profile.examName,
        examUrl: profile.examUrl,
        status: 'active',
      };
      setUser(publicUser(u));
      return { ok: true, profile: result.profile };
    } catch (err) {
      return { error: err.message || 'Candidate authentication failed' };
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
    setSessionId(null);
    clearTokens();
  }, []);

  const reauth = useCallback(async (password) => {
    const e = throttle(); if (e) return { error: e };
    if (!user) return { error: 'Not signed in.' };

    if (backendMode === 'admin') {
      try {
        /* user.id is the database row id (e.g. usr_admin); the login endpoint
         * expects the login name, so use the username carried by the profile. */
        const r = await authService.adminLogin({ username: user.username || user.id, password });
        if (r.ok || r.mfaRequired || r.mfaSetupRequired) {
          fails.current = { n: 0, until: 0 };
          record(user.id, 'REAUTH_OK');
          return { ok: true };
        }
      } catch (err) {
        fail(user.id, 'REAUTH_FAILED');
        return { error: 'Password verification failed.' };
      }
      fail(user.id, 'REAUTH_FAILED');
      return { error: 'Password verification failed.' };
    }

    /*
     * There is no local credential realm any more, so a session that was not
     * established by the ExamOS server cannot be re-authenticated at all.
     */
    fail(user?.id || 'unknown', 'REAUTH_FAILED');
    return { error: 'This session cannot be re-authenticated. Sign in again.' };
  }, [user, backendMode]);

  const logout = useCallback(async (why = 'LOGOUT') => {
    if (backendMode === 'admin') { await backendLogout(); return; }
    if (backendMode === 'candidate') { await backendCandidateLogout(); return; }
    if (user) {
      record(user.id, why);
      if (sessionId) {
        const s = await get('authSessions', sessionId);
        if (s) await put('authSessions', { ...s, status: 'ended', endedAt: Date.now(), current: false });
      }
    }
    setUser(null);
    setPending(null);
    setPendingCredentials(null);
    enrollmentRef.current = null;
    setLocked(false);
    setSessionId(null);
    clearTokens();
  }, [user, sessionId, backendMode, backendLogout, backendCandidateLogout]);

  const lock = useCallback(() => {
    if (user) record(user.id, 'SESSION_LOCKED');
    setLocked(true);
  }, [user]);

  const unlock = useCallback(async (password) => {
    const r = await reauth(password);
    if (r.ok) setLocked(false);
    return r;
  }, [reauth]);

  const changePassword = useCallback(async (current, next) => {
    if (!user) return { error: 'Not signed in.' };
    const bad = pwIssues(next || '');
    if (bad.length) return { error: 'New password needs ' + bad.join(', ') + '.' };

    if (backendMode === 'admin') {
      try {
        const res = await authService.changePassword({ currentPassword: current, newPassword: next });
        if (res?.status === 'SUCCESS' || res?.ok) {
          record(user.id, 'PASSWORD_CHANGED');
          return { ok: true };
        }
        return { error: res?.error || 'Password change failed.' };
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          record(user.id, 'PASSWORD_CHANGE_FAILED');
          return { error: 'Current password is incorrect.' };
        }
        return { error: err.message || 'Password change failed.' };
      }
    }

    /* No local credential realm exists: passwords are owned by the server. */
    return { error: 'This session cannot change its password. Sign in through the ExamOS server.' };
  }, [user, backendMode]);

  const regenerateRecovery = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    /*
     * Recovery codes must be generated and stored by the server, otherwise the
     * console would display codes that can never reset the real account.
     */
    return { error: 'Recovery codes are managed by the ExamOS server. Use Authenticator setup or account recovery to rotate them.' };
  }, [user]);

  const rotateMfa = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    /* Never fabricate a local secret that the server does not know about. */
    return { error: 'Authenticator rotation must be completed through the server enrollment flow.' };
  }, [user]);

  const resetWithRecovery = useCallback(async (username, code, next) => {
    const e = throttle(); if (e) return { error: e };

    // Real ExamOS C server recovery only — no local fallback.
    // A local fallback would let an attacker bypass server-side revocation
    // and use a recovery code against a stale IndexedDB copy.
    if (!backendReady) {
      return { error: 'ExamOS server is unreachable. Account recovery requires a live server connection.' };
    }
    try {
      const res = await authService.recoveryReset({ username, code, newPassword: next });
      if (res.status === 'SUCCESS' || res.ok) {
        fails.current = { n: 0, until: 0 };
        return { ok: true, message: res.message };
      }
      fail(username || 'anonymous', 'RECOVERY_FAILED');
      return { error: res.error || 'Password recovery failed' };
    } catch (err) {
      fail(username || 'anonymous', 'RECOVERY_FAILED');
      return { error: err.message || 'Failed to reset password via recovery code' };
    }
  }, [backendReady]);

  const mfaSetup = useCallback(async () => {
    if (!backendReady) {
      return { error: 'ExamOS server is unreachable. Authenticator enrollment cannot complete offline.' };
    }
    try {
      const res = await authService.mfaSetup(enrollmentRef.current);
      if (res?.error) return { error: res.error };
      if (!res?.secret || !res?.otpauth_url) {
        return { error: 'The server did not return an authenticator secret. Sign in again to restart setup.' };
      }
      /* The secret is generated and held by the server; we only display it. */
      if (res.enrollment_token) enrollmentRef.current = res.enrollment_token;
      return res;
    } catch (err) {
      return { error: err.message || 'Failed to initialize Google Authenticator' };
    }
  }, [backendReady]);

  const mfaConfirm = useCallback(async ({ code }) => {
    if (!backendReady) {
      return { error: 'ExamOS server is unreachable. Authenticator enrollment cannot complete offline.' };
    }
    try {
      const res = await authService.mfaConfirm({ enrollmentToken: enrollmentRef.current, code });
      if (res?.status === 'SUCCESS' || res?.ok) {
        /* The challenge is consumed; the next login uses the enrolled secret. */
        return { ok: true, status: 'SUCCESS' };
      }
      return { error: res?.error || 'Invalid authenticator code. Check your device clock.' };
    } catch (err) {
      return { error: err.message || 'Failed to activate Google Authenticator' };
    }
  }, [backendReady]);

  const touchSession = useCallback(async () => {
    if (!sessionId) return;
    const s = await get('authSessions', sessionId);
    if (s && s.status === 'active') await put('authSessions', { ...s, lastSeen: Date.now() });
  }, [sessionId]);

  const listSessions = useCallback(async () => {
    if (!user) return [];
    return (await all('authSessions')).filter((s) => s.userId === user.id).sort((a, b) => b.lastSeen - a.lastSeen);
  }, [user]);

  const revokeSession = useCallback(async (sid) => {
    if (!user) return { error: 'Not signed in.' };
    const s = await get('authSessions', sid);
    if (!s || s.userId !== user.id) return { error: 'Session not found.' };
    if (sid === sessionId) return { error: 'Use Sign out to end the current session.' };
    await put('authSessions', { ...s, status: 'revoked', current: false, endedAt: Date.now() });
    record(user.id, 'SESSION_REVOKED', s.id);
    return { ok: true };
  }, [user, sessionId]);

  const revokeOthers = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    const list = (await all('authSessions')).filter((s) => s.userId === user.id && s.status === 'active' && s.id !== sessionId);
    for (const s of list) await put('authSessions', { ...s, status: 'revoked', current: false, endedAt: Date.now() });
    record(user.id, 'SESSIONS_REVOKED_ALL', `count=${list.length}`);
    return { ok: true, count: list.length };
  }, [user, sessionId]);

  return <Ctx.Provider value={{
    user, pending, pendingCredentials, locked, sessionId, backendMode, backendReady,
    verifyMfa, cancelPending, backendLogin, backendLogout, backendCandidateLogin, backendCandidateLogout,
    reauth, logout, lock, unlock, changePassword, regenerateRecovery, rotateMfa,
    mfaSetup, mfaConfirm,
    resetWithRecovery, touchSession, listSessions, revokeSession, revokeOthers,
  }}>{children}</Ctx.Provider>;
}
