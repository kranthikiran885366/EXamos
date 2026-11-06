import { clean } from '../security/sanitize';
import { need, fail, requireReason } from './common';
import * as Api from '../api/services';

export const KINDS = {
  'role-change': 'Role assignment',
  'release-approve': 'Release approval',
  'policy-publish': 'Policy publication',
  'policy-rollback': 'Policy rollback',
  'config-change': 'Configuration change',
  'device-reauth': 'Device reauthorisation',
  'exam-approve': 'Exam approval',
  'billing-change': 'Subscription change',
  'privacy-deletion': 'Data deletion request',
};
export const OPEN = ['pending_review'];

export async function create(actor, { kind, label, targetId, tenantId, reason, data = {} }) {
  need(actor, 'approval.view');
  if (!KINDS[kind]) fail('Unknown approval type.');
  if (!targetId) fail('An approval request must identify its target resource.');
  const justification = requireReason(reason, 8);
  const response = await Api.createApprovalRequest({
    kind,
    label: clean(label, 140),
    targetId: clean(targetId, 128),
    tenantId,
    reason: justification,
    data,
  });
  if (!response?.id || response.status !== 'pending_review') {
    fail('The backend did not confirm that the approval request was persisted.');
  }
  return response;
}

export async function decide(actor, request, approve, note = '') {
  need(actor, 'approval.decide');
  if (!request?.id) fail('A valid approval request is required.');
  const reason = requireReason(note, 8);
  return Api.decideApprovalRequest(request.id, approve ? 'approved' : 'rejected', reason);
}

export async function pendingFor() {
  return Api.listApprovalRequests();
}

export async function cancel(actor, request, reason) {
  if (!request?.id) fail('A valid approval request is required.');
  const justification = requireReason(reason, 5);
  const response = await Api.cancelApprovalRequest(request.id, justification);
  if (response?.status !== 'withdrawn') fail('The backend did not confirm request withdrawal.');
  return 'Request withdrawn.';
}

export const apAge = (request) => Date.now() - Number(request?.createdAt || 0);
export async function getApproval(id) {
  if (!id) fail('An approval request identifier is required.');
  const requests = await Api.listApprovalRequests();
  return requests.find((request) => request.id === id);
}
