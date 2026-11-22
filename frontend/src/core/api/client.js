// ExamOS Console — authenticated API client.
// Server sessions and authorization are authoritative for all protected calls.

import { ENDPOINTS, API_BASE, REQUEST_TIMEOUT, MAX_RETRIES, CONSOLE_HEADERS } from '../../config/api';
import { auditApiCall } from '../security/auditClient';

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

let adminToken = null;   // Bearer token from /api/v1/admin/login
let candidateToken = null; // Bearer token from /api/v1/candidate/login

export function setAdminToken(token) { adminToken = token; }
export function getAdminToken() { return adminToken; }
export function setCandidateToken(token) { candidateToken = token; }
export function getCandidateToken() { return candidateToken; }
export function clearTokens() { adminToken = null; candidateToken = null; }

function headersFor(token, isCandidate) {
  const h = { ...CONSOLE_HEADERS };
  if (isCandidate) {
    if (candidateToken) h.Authorization = `Bearer ${candidateToken}`;
  } else if (token) {
    h.Authorization = `Bearer ${token}`;
  } else if (adminToken) {
    h.Authorization = `Bearer ${adminToken}`;
  }
  return h;
}

function parseJsonOrText(text) {
  if (!text) return text;
  try { return JSON.parse(text); } catch { return text; }
}

export async function request({
  method = 'GET',
  path,
  body,
  headers: requestHeaders,
  useCandidateToken = false,
  // Legacy callers may pass this flag; signing is not a client trust boundary.
  sign: _legacySign = false,
  audit = true,
  actor = 'console',
  retries = MAX_RETRIES,
  signal,
  timeoutMs = REQUEST_TIMEOUT,
  ...fetchOpts
} = {}) {
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`;
  const start = Date.now();
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const abortController = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      abortController.abort();
    }, timeoutMs);

    let onExternalAbort = null;
    if (signal) {
      if (signal.aborted) {
        abortController.abort(signal.reason);
      } else {
        onExternalAbort = () => abortController.abort(signal.reason);
        signal.addEventListener('abort', onExternalAbort, { once: true });
      }
    }

    try {
      const headers = headersFor(useCandidateToken ? undefined : adminToken, useCandidateToken);
      // Caller-supplied headers (e.g. X-Enrollment-Token) override defaults.
      Object.assign(headers, requestHeaders || {});

      const fetchInit = {
        method,
        headers,
        credentials: 'include',
        signal: abortController.signal,
        ...fetchOpts,
      };
      if (body !== undefined && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        fetchInit.body = typeof body === 'string' ? body : JSON.stringify(body);
        if (!headers['content-type']) headers['content-type'] = 'application/json';
      }

      const res = await fetch(url, fetchInit);

      const responseBody = await res.text();
      const parsed = parseJsonOrText(responseBody);
      const durationMs = Date.now() - start;

      if (!res.ok) {
        const err = new ApiError(res.status, typeof parsed === 'string' ? parsed : (parsed.error || parsed.message || `HTTP ${res.status}`), parsed);
        if (audit) {
          try { auditApiCall({ actor, method, path, status: res.status, durationMs, error: err.message }); } catch {}
        }
        // Do not retry client errors (4xx) except 429/408.
        if (res.status === 429 || res.status === 408) {
          lastError = err;
          if (attempt < retries) { await sleep(500 * (attempt + 1)); continue; }
        }
        throw err;
      }

      if (audit) {
        try { auditApiCall({ actor, method, path, status: res.status, durationMs }); } catch {}
      }
      return { status: res.status, data: parsed, headers: res.headers };
    } catch (err) {
      const requestError = timedOut
        ? new ApiError(408, `Request timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`, null)
        : err;
      lastError = requestError;
      if (timedOut && attempt < retries) {
        await sleep(500 * (attempt + 1));
        continue;
      }
      if (requestError instanceof ApiError && requestError.status >= 400 &&
          requestError.status < 500 && requestError.status !== 429) throw requestError;
      if (attempt < retries) { await sleep(500 * (attempt + 1)); continue; }
      throw requestError;
    } finally {
      clearTimeout(timer);
      if (signal && onExternalAbort) {
        signal.removeEventListener('abort', onExternalAbort);
      }
    }
  }
  throw lastError;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Convenience methods.
export const api = {
  get(path, opts = {}) { return request({ method: 'GET', path, ...opts }); },
  post(path, body, opts = {}) { return request({ method: 'POST', path, body, ...opts }); },
  put(path, body, opts = {}) { return request({ method: 'PUT', path, body, ...opts }); },
  patch(path, body, opts = {}) { return request({ method: 'PATCH', path, body, ...opts }); },
  del(path, opts = {}) { return request({ method: 'DELETE', path, ...opts }); },
};

export default { request, api, setAdminToken, getAdminToken, setCandidateToken, getCandidateToken, clearTokens, ApiError };
