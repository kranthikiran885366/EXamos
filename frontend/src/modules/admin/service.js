import { wipe } from '../../core/db/db';
import { need, log } from '../../core/services/common';
import * as Api from '../../core/api/services';
export { createTenant, createInstitution, updateInstitution, setInstitutionStatus } from '../institutions/service';

export const setTenantStatus = (a, t, status, reason) => import('../institutions/service').then((m) => m.setInstitutionStatus(a, t, status, reason));

export async function listInstitutions() {
  const res = await Api.listInstitutions();
  return res?.institutions || res || [];
}

export async function resetWorkspace(a) {
  need(a, 'tenant.manage');
  await log(a, 'WORKSPACE_RESET');
  await wipe();
  location.reload();
}
