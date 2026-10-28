// ExamOS Console — Audit chain client.
// Sends audit events to the backend ledger (/api/v1/ledger) and mirrors
// them locally in IndexedDB for offline resilience. Every mutating API call
// through the console client is recorded here.

import { put } from '../db/db';
import { sha256 } from './crypto';

const AUDIT_COL = 'apiAudit';

export class AuditClient {
  constructor({ enabled = true, serverEnabled = true } = {}) {
    this.enabled = enabled;
    this.serverEnabled = serverEnabled;
    this.queue = [];
  }

  async record({ actor, event, detail = '', resource = '', severity = 'info' }) {
    const entry = {
      id: `audit_${crypto.randomUUID?.() || Date.now()}`,
      actor: actor || 'system',
      event,
      detail,
      resource,
      severity,
      created_at: Date.now(),
      local_hash: '',
    };
    try {
      entry.local_hash = await sha256(JSON.stringify({ ...entry, local_hash: '' }));
    } catch { entry.local_hash = String(Date.now()); }

    if (this.enabled) {
      await put(AUDIT_COL, entry).catch(() => {});
    }
    this.queue.push(entry);
    if (this.serverEnabled) this.flush().catch(() => {});
    return entry;
  }

  async flush() {
    if (!this.serverEnabled || this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    try {
      const res = await fetch('/api/v1/audit/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-ExamOS-Console': '1' },
        body: JSON.stringify({ events: batch }),
      });
      if (!res.ok) {
        // Stop server push attempts on 404/error to avoid spam; audit remains local in IndexedDB
        this.serverEnabled = false;
      }
    } catch {
      this.serverEnabled = false;
    }
  }
}

export const audit = new AuditClient();

export async function auditApiCall({ actor, method, path, status, durationMs, requestId, error }) {
  return audit.record({
    actor,
    event: 'API_CALL',
    detail: `${method} ${path} -> ${status || 'unknown'} ${error ? `(error: ${error})` : ''}`,
    resource: path,
    severity: status && status >= 400 ? 'error' : 'info',
  });
}
