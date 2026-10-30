// ExamOS Console — Auth context (hybrid: real backend + local IndexedDB fallback).
//
// Supports two authentication realms against the ExamOS C server:
//   • Admin/operator console login  -> POST /api/v1/admin/login  (Bearer + admin_session cookie)
//   • Candidate exam login          -> POST /api/v1/candidate/login (Bearer token)
// Falls back to local IndexedDB users when the backend is unreachable (demo mode).
import { createContext, useContext, useState, useRef, useCallback, useEffect } from 'react';
import { all, get, put } from '../db/db';
import { pbkdf2, safeEqual, sha256, randomId } from '../security/crypto';
import { verifyTotp, newSecret } from '../security/totp';
import { clean } from '../security/sanitize';
import { record } from '../security/auditChain';
import { roleLabel } from '../security/rbac';
import { pwIssues } from '../../modules/users/service';
import { authService } from './authService';
import { setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens } from '../api/client';
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
  const checkPassword = async (key, password) => {
    const u = await get('users', key);
    const given = await pbkdf2(String(password).slice(0, 128), u?.salt || 'decoy-salt-000');
    return !!u && u.status === 'active' && safeEqual(given, u.pwHash);
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
                  role: profile.role || 'PLATFORM_OWNER',
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

  /* ---------- Local (IndexedDB) admin login ---------- */
  const login = useCallback(async (username, password) => {
    const e = throttle(); if (e) return { error: e };
    const key = clean(username, 40).toLowerCase();
    if (!(await checkPassword(key, password))) {
      fail(key || 'anonymous', 'LOGIN_FAILED');
      return { error: GENERIC };
    }
    setPending(key);
    setPendingCredentials(null);
    const u = await get('users', key);
    const isStudent = u.role === 'student' || u.role === 'candidate' || !!u.candidateId;
    if (isStudent || u.mfaEnabled === false) {
      await beginSession(u);
      return { ok: true };
    }
    // New management users who have neither TOTP secret nor recovery codes must set up MFA
    const hasEnrolledTotp = !!(u.totp || u.totpSecret || u.totpEnrolled);
    if (!hasEnrolledTotp && (!u.recoveryCodes || u.recoveryCodes.length === 0)) {
      setPendingCredentials({ username: key, password });
      setPending(key);
      return { mfaSetupRequired: true, username: key };
    }
    record(key, 'LOGIN_PASSWORD_OK');
    return { mfa: true };
  }, [beginSession]);

  /* ---------- Unified MFA verification (Backend + Local) ---------- */
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
          role: profile.role || 'PLATFORM_OWNER',
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
        // Server is offline - try local IndexedDB fallback
        try {
          const localRes = await login(username, password);
          if (localRes?.ok || localRes?.mfa) {
            setBackendMode('none');
            return localRes;
          }
        } catch {}
        return { error: 'ExamOS server is unreachable. Check that the backend is running on port 8895.' };
      }
    }
    try {
      const result = await authService.adminLogin({ username, password, mfaCode });
      if (result.mfaSetupRequired) {
        setPendingCredentials({ username, password });
        setPending(username);
        return { mfaSetupRequired: true, username: result.username || username };
      }
      if (result.mfaRequired) {
        setPendingCredentials({ username, password });
        setPending(username);
        return { mfa: true };
      }

      setPendingCredentials(null);
      setPending(null);
      const profile = result.profile || {};
      const u = {
        id: profile.user_id || username,
        username: profile.username || username,
        name: profile.name || profile.full_name || username,
        role: profile.role || 'PLATFORM_OWNER',
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
      // If backend authentication failed, try local IndexedDB demo accounts as fallback
      try {
        const localRes = await login(username, password);
        if (localRes?.ok || localRes?.mfa) {
          setBackendMode('none');
          return localRes;
        }
      } catch {}
      return { error: err.message || 'Authentication failed' };
    }
  }, [backendReady, beginSession, login]);

  const backendLogout = useCallback(async () => {
    try { await authService.adminLogout(); } catch {}
    setBackendMode('none');
    setUser(null);
    setPending(null);
    setPendingCredentials(null);
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
    setLocked(false);
    setSessionId(null);
    clearTokens();
  }, []);

  const reauth = useCallback(async (password) => {
    const e = throttle(); if (e) return { error: e };
    if (!user) return { error: 'Not signed in.' };

    if (backendMode === 'admin') {
      try {
        const r = await authService.adminLogin({ username: user.id || user.name, password });
        if (r.ok || r.mfaRequired) {
          fails.current = { n: 0, until: 0 };
          record(user.id, 'REAUTH_OK');
          return { ok: true };
        }
      } catch (err) {
        fail(user.id, 'REAUTH_FAILED');
        return { error: 'Password verification failed.' };
      }
    }

    if (!(await checkPassword(user.id, password))) {
      fail(user?.id || 'unknown', 'REAUTH_FAILED');
      return { error: 'Password is incorrect.' };
    }
    fails.current = { n: 0, until: 0 };
    record(user.id, 'REAUTH_OK');
    return { ok: true };
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
    if (!(await checkPassword(user.id, current))) {
      record(user.id, 'PASSWORD_CHANGE_FAILED');
      return { error: 'Current password is incorrect.' };
    }
    const bad = pwIssues(next || '');
    if (bad.length) return { error: 'New password needs ' + bad.join(', ') + '.' };
    const u = await get('users', user.id);
    const salt = randomId(12);
    await put('users', { ...u, salt, pwHash: await pbkdf2(next, salt), passwordChangedAt: Date.now() });
    record(user.id, 'PASSWORD_CHANGED');
    return { ok: true };
  }, [user]);

  const regenerateRecovery = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    const plain = Array.from({ length: 8 }, () => normCode(randomId(5)).slice(0, 8).replace(/(.{4})/, '$1-'));
    const hashes = await Promise.all(plain.map((c) => sha256(normCode(c))));
    const u = await get('users', user.id);
    await put('users', { ...u, recoveryCodes: hashes, recoveryGeneratedAt: Date.now() });
    record(user.id, 'MFA_RECOVERY_ROTATED', `count=${plain.length}`);
    return { ok: true, codes: plain };
  }, [user]);

  const rotateMfa = useCallback(async () => {
    if (!user) return { error: 'Not signed in.' };
    const secret = newSecret();
    const u = await get('users', user.id);
    await put('users', { ...u, totp: secret });
    record(user.id, 'MFA_SECRET_ROTATED');
    const uri = `otpauth://totp/ExamOS:${encodeURIComponent(user.id)}?secret=${secret}&issuer=ExamOS&algorithm=SHA1&digits=6&period=30`;
    return { ok: true, secret, uri };
  }, [user]);

  const resetWithRecovery = useCallback(async (username, code, next) => {
    const e = throttle(); if (e) return { error: e };

    // 1. Real ExamOS C server recovery
    if (backendReady) {
      try {
        const res = await authService.recoveryReset({ username, code, newPassword: next });
        if (res.status === 'SUCCESS' || res.ok) {
          fails.current = { n: 0, until: 0 };
          return { ok: true, message: res.message };
        }
        return { error: res.error || 'Password recovery failed' };
      } catch (err) {
        return { error: err.message || 'Failed to reset password via recovery code' };
      }
    }

    // 2. Local fallback
    const key = clean(username, 40).toLowerCase();
    const u = await get('users', key);
    if (!u || u.status !== 'active') {
      fail(key || 'anonymous', 'RECOVERY_FAILED');
      return { error: 'Invalid recovery details.' };
    }
    const h = await sha256(normCode(code));
    if (!(u.recoveryCodes || []).includes(h)) {
      fail(key, 'RECOVERY_FAILED');
      return { error: 'Invalid recovery details.' };
    }
    const bad = pwIssues(next || '');
    if (bad.length) return { error: 'New password needs ' + bad.join(', ') + '.' };
    const salt = randomId(12);
    const codes = (u.recoveryCodes || []).filter((x) => x !== h);
    await put('users', {
      ...u,
      salt,
      pwHash: await pbkdf2(next, salt),
      recoveryCodes: codes,
      passwordChangedAt: Date.now()
    });
    record(key, 'ACCOUNT_RECOVERED', `remaining=${codes.length}`);
    fails.current = { n: 0, until: 0 };
    return { ok: true };
  }, [backendReady]);

  const mfaSetup = useCallback(async (username) => {
    if (backendReady) {
      try {
        const res = await authService.mfaSetup(username);
        if (res?.status === 'SUCCESS' || res?.secret) return res;
      } catch (err) {
        console.warn('Backend mfaSetup failed, falling back to local generator', err);
      }
    }
    const secret = newSecret();
    const codes = Array.from({ length: 8 }, () => {
      const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
      let c1 = '', c2 = '';
      for (let i = 0; i < 4; i++) c1 += chars[Math.floor(Math.random() * chars.length)];
      for (let i = 0; i < 4; i++) c2 += chars[Math.floor(Math.random() * chars.length)];
      return `${c1}-${c2}`;
    });
    const targetUser = username || 'root';
    const otpauth_url = `otpauth://totp/ExamOS:${encodeURIComponent(targetUser)}?secret=${secret}&issuer=ExamOS&algorithm=SHA1&digits=6&period=30`;
    return {
      status: 'SUCCESS',
      username: targetUser,
      secret,
      otpauth_url,
      recovery_codes: codes,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      issuer: 'ExamOS',
    };
  }, [backendReady]);

  const mfaConfirm = useCallback(async ({ username, secret, code, recoveryCodes }) => {
    let backendSuccess = false;
    let backendErr = null;
    const targetUser = username || 'root';

    if (backendReady) {
      try {
        const res = await authService.mfaConfirm({ username: targetUser, secret, code, recoveryCodes });
        if (res?.status === 'SUCCESS' || res?.ok) {
          backendSuccess = true;
        } else if (res?.error) {
          return { error: res.error };
        }
      } catch (err) {
        backendErr = err.message;
      }
    }

    // Always synchronize the local IndexedDB cache with the newly enrolled secret & recovery codes
    try {
      const u = await get('users', targetUser);
      if (u) {
        // Hash recovery codes if plain
        const hashes = [];
        for (const rc of (recoveryCodes || [])) {
          const h = await sha256(normCode(rc));
          hashes.push(h);
        }
        await put('users', {
          ...u,
          totp: secret,
          totpEnrolled: true,
          mfaEnabled: true,
          recoveryCodes: hashes.length > 0 ? hashes : u.recoveryCodes,
        });
      }
    } catch (e) {
      console.warn('Could not update local user TOTP:', e);
    }

    if (backendReady && !backendSuccess && backendErr) {
      return { error: backendErr };
    }
    return { ok: true, status: 'SUCCESS' };
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
    login, verifyMfa, cancelPending, backendLogin, backendLogout, backendCandidateLogin, backendCandidateLogout,
    reauth, logout, lock, unlock, changePassword, regenerateRecovery, rotateMfa,
    mfaSetup, mfaConfirm,
    resetWithRecovery, touchSession, listSessions, revokeSession, revokeOthers,
  }}>{children}</Ctx.Provider>;
}
