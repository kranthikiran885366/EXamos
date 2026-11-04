// ExamOS Console — Audit client (server-only, no local storage).
//
// Audit events are sent exclusively to the ExamOS C server ledger endpoint.
// Nothing is written to IndexedDB, localStorage, or sessionStorage.
// The server is the single source of truth for all audit records.
import { api } from '../api/client';
import { ENDPOINTS } from '../../config/api';

export class AuditClient {
  constructor() {
    this.queue   = [];
    this.sending = false;
  }

  async record({ actor, event, detail = '', resource = '', severity = 'info' }) {
    const entry = {
      actor:      actor || 'system',
      event,
      detail,
      resource,
      severity,
      created_at: Date.now(),
    };
    this.queue.push(entry);
    this._scheduleFlush();
    return entry;
  }

  _scheduleFlush() {
    if (this.sending) return;
    // Flush asynchronously so the calling code is never blocked.
    Promise.resolve().then(() => this.flush()).catch(() => {});
  }

  async flush() {
    if (this.sending || this.queue.length === 0) return;
    this.sending   = true;
    const batch    = this.queue.splice(0);
    try {
      const res = await api.post(ENDPOINTS.auditBatch, { events: batch }, { actor: 'console', sign: false, audit: false });
      // On server-side error just drop — we never fall back to local storage.
      if (res.status < 200 || res.status >= 300) console.warn('[AuditClient] server returned', res.status);
    } catch {
      // Network failure — entries are dropped. The server-side audit trail
      // (produced by the C backend on every API call) remains intact.
    } finally {
      this.sending = false;
      // Drain any entries that arrived while we were flushing.
      if (this.queue.length > 0) this._scheduleFlush();
    }
  }
}

export const audit = new AuditClient();

export async function auditApiCall({ actor, method, path, status, error }) {
  return audit.record({
    actor,
    event:    'API_CALL',
    detail:   `${method} ${path} -> ${status ?? 'unknown'}${error ? ` (${error})` : ''}`,
    resource: path,
    severity: status && status >= 400 ? 'error' : 'info',
  });
}
