import { audit } from './auditClient';
import * as Api from '../api/services';

let chain = [];
const subs = new Set();
export async function initChain() {
  const response = await Api.listAuditTrail({ limit: 10000 });
  chain = response?.events || [];
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
