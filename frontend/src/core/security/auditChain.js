import { audit } from './auditClient';
import * as Api from '../api/services';
import { normalizeAuditEvents } from '../ui/normalizers';

let chain = [];
const subs = new Set();
export async function initChain() {
  const response = await Api.listAuditTrail({ limit: 10000 });
  // The backend returns a flat JSON array, not { events: [...] }.
  // Use the shared normalizer so the chain module and the AuditPage
  // always agree on the same parsed event population.
  try {
    chain = normalizeAuditEvents(response);
  } catch {
    // If the normalizer throws (e.g. malformed response), fall back to empty.
    chain = [];
  }
  subs.forEach((callback) => callback());
  return chain;
}
export function record(actor, event, detail = '') {
  return audit.record({ actor, event, detail });
}
export const getChain = () => chain;
export const subscribe = (callback) => { subs.add(callback); return () => subs.delete(callback); };
export async function verifyChain() {
  const response = await Api.getLedger();
  return {
    ok: response?.ledger_integrity === 'INTACT',
    count: Number(response?.total_blocks) || 0,
    status: response?.status || 'UNAVAILABLE',
  };
}
