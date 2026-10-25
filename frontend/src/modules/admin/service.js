import { wipe } from '../../core/db/db';
import { need, log } from '../../core/services/common';
export { createTenant, createInstitution, updateInstitution, setInstitutionStatus } from '../institutions/service';

export const setTenantStatus = (a, t, status, reason) => import('../institutions/service').then((m) => m.setInstitutionStatus(a, t, status, reason));

export async function resetWorkspace(a) {
  need(a, 'tenant.manage');
  await log(a, 'WORKSPACE_RESET');
  await wipe();
  location.reload();
}
