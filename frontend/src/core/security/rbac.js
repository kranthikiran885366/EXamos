// Role catalogue and permission checks.
// The frontend hides actions a user cannot perform; every write service re-checks the
// permission too. A production deployment must enforce the same rules server-side.
let custom = {};

export const ROLES = {
  superadmin: {
    label: 'Platform Super Admin', short: 'Platform', scope: 'global', rank: 100,
    desc: 'Global platform configuration, institutions, privileged roles and release approval.',
    perms: ['*'],
  },
  inst_admin: {
    label: 'Institution Admin', short: 'Institution', scope: 'institution', rank: 80,
    desc: 'Manages the institution, campuses, staff, exams, devices and reports.',
    perms: ['dashboard.view', 'inst.view', 'inst.manage', 'campus.manage', 'dept.manage', 'staff.manage',
      'agreement.view', 'agreement.sign', 'license.view', 'license.manage', 'deployment.view', 'deployment.manage', 'onboarding.view', 'onboarding.manage',
      'exam.view', 'exam.manage', 'exam.approve', 'exam.operate', 'exam.policy',
      'candidate.view', 'candidate.manage', 'candidate.verify', 'center.manage',
      'device.view', 'device.manage', 'usb.view', 'usb.assign',
      'policy.view', 'policy.edit', 'policy.publish', 'policy.rollback', 'incident.view', 'incident.manage',
      'release.view', 'report.generate', 'export', 'audit.view', 'audit.export',
      'audit.institution',
      'support.view', 'support.manage', 'notify.manage', 'notification.view', 'billing.view', 'billing.manage',
      'privacy.view', 'privacy.manage', 'approval.view', 'approval.decide', 'settings.view', 'settings.inst',
      'user.manage', 'monitor.view', 'evidence.view', 'compat.view'],
  },
  exam_controller: {
    label: 'Examination Controller', short: 'Controller', scope: 'institution', rank: 70,
    desc: 'Creates and approves exams, schedules, candidate lists and examination policies.',
    perms: ['dashboard.view', 'inst.view', 'exam.view', 'exam.manage', 'exam.approve', 'exam.operate', 'exam.policy',
      'candidate.view', 'candidate.manage', 'candidate.verify', 'center.manage', 'device.view', 'compat.view',
      'policy.view', 'policy.edit', 'incident.view', 'incident.manage', 'report.generate', 'export',
      'support.view', 'support.manage', 'notify.manage', 'notification.view', 'settings.inst', 'approval.view'],
  },
  invigilator: {
    label: 'Exam Operator / Invigilator', short: 'Invigilator', scope: 'institution', rank: 50,
    desc: 'Monitors assigned live exams, candidate readiness and incidents.',
    perms: ['dashboard.view', 'ops.view', 'exam.view', 'exam.operate', 'candidate.view', 'candidate.verify',
      'device.view', 'incident.view', 'incident.manage', 'session.terminate', 'report.generate',
      'support.view', 'support.manage', 'notification.view'],
  },
  it_admin: {
    label: 'IT / Device Administrator', short: 'IT Admin', scope: 'institution', rank: 60,
    desc: 'Prepares USBs, enrolls devices, manages compatibility, rollouts and troubleshooting.',
    perms: ['dashboard.view', 'device.view', 'device.manage', 'usb.view', 'usb.manage', 'usb.assign',
      'deployment.view', 'deployment.manage',
      'fleet.manage', 'tpm.run', 'firewall.manage', 'policy.view', 'policy.edit', 'release.view', 'release.rollout',
      'incident.view', 'incident.manage', 'monitor.view', 'compat.view', 'compat.manage', 'evidence.view',
      'support.view', 'support.manage', 'support.diagnostics', 'report.generate', 'export', 'settings.inst',
      'notification.view', 'audit.view'],
  },
  security_engineer: {
    label: 'Security Engineer', short: 'Security', scope: 'institution', rank: 65,
    desc: 'Defines approved security profiles, investigates evidence and validates security fixes.',
    perms: ['dashboard.view', 'security.view', 'security.manage', 'tpm.run', 'evidence.view', 'evidence.manage',
      'incident.view', 'incident.manage', 'policy.view', 'policy.edit', 'release.view', 'compat.view',
      'device.view', 'audit.view', 'audit.export', 'monitor.view', 'report.generate', 'export',
      'support.view', 'notification.view'],
  },
  auditor: {
    label: 'Security Auditor', short: 'Auditor', scope: 'global', rank: 40,
    desc: 'Reads authorised evidence, audit trails, policy decisions and security reports.',
    perms: ['dashboard.view', 'inst.view', 'exam.view', 'candidate.view', 'device.view', 'usb.view',
      'audit.view', 'audit.export', 'security.view', 'incident.view', 'release.view', 'policy.view',
      'audit.platform', 'report.generate', 'export', 'monitor.view', 'billing.view', 'support.view', 'privacy.view', 'evidence.view'],
  },
  release_engineer: {
    label: 'Release Engineer', short: 'Release', scope: 'global', rank: 60,
    desc: 'Prepares and validates release candidates, manages rollout evidence and release status.',
    perms: ['dashboard.view', 'release.view', 'release.manage', 'release.rollout', 'evidence.view', 'evidence.manage',
      'device.view', 'security.view', 'monitor.view', 'policy.view', 'support.view', 'support.manage',
      'audit.view', 'report.generate', 'export'],
  },
  support: {
    label: 'Support Engineer', short: 'Support', scope: 'institution', rank: 30,
    desc: 'Diagnoses assigned issues and tracks support requests with limited permissions.',
    perms: ['dashboard.view', 'support.view', 'support.manage', 'support.diagnostics', 'device.view', 'compat.view',
      'monitor.view', 'incident.view', 'exam.view', 'report.generate', 'notification.view'],
  },
  finance: {
    label: 'Finance Officer', short: 'Finance', scope: 'institution', rank: 45,
    desc: 'Manages plans, invoices and payment records through an authorised billing integration.',
    perms: ['dashboard.view', 'billing.view', 'billing.manage', 'report.generate', 'export', 'audit.view', 'notification.view'],
  },
  student: {
    label: 'Student / Candidate', short: 'Student', scope: 'own', rank: 10,
    desc: 'Views assigned exams, completes device checks, takes the exam and confirms submission.',
    perms: ['student.view', 'student.session', 'student.check', 'support.view', 'support.manage', 'notification.view', 'account.view'],
  },
  // Legacy operations role retained so existing workspaces and demo data keep working.
  ops_admin: {
    label: 'Operations Admin (legacy)', short: 'Operations', scope: 'global', rank: 75,
    desc: 'Legacy broad operations role. Prefer the scoped blueprint roles.',
    perms: ['dashboard.view', 'tenant.manage', 'inst.view', 'inst.manage', 'inst.review', 'inst.provision', 'campus.manage', 'dept.manage', 'staff.manage',
      'agreement.view', 'agreement.sign', 'license.view', 'license.manage', 'deployment.view', 'deployment.manage', 'onboarding.view', 'onboarding.manage',
      'exam.view', 'exam.manage', 'exam.approve', 'exam.operate', 'exam.policy', 'candidate.view', 'candidate.manage',
      'candidate.verify', 'center.manage', 'device.view', 'device.manage', 'usb.view', 'usb.manage', 'usb.assign',
      'policy.view', 'policy.edit', 'policy.publish', 'policy.rollback', 'policy.weaken', 'firewall.manage',
      'kiosk.manage', 'tpm.run', 'release.view', 'release.manage', 'release.rollout', 'incident.view',
      'incident.manage', 'session.terminate', 'audit.view', 'audit.export', 'security.view', 'security.manage',
      'monitor.view', 'compat.view', 'compat.manage', 'support.view', 'support.manage', 'support.diagnostics',
      'notify.manage', 'notification.view', 'billing.view', 'billing.manage', 'privacy.view', 'privacy.manage',
      'approval.view', 'approval.decide', 'settings.view', 'settings.inst', 'settings.manage', 'user.manage',
      'role.manage', 'report.generate', 'export', 'evidence.view', 'evidence.manage', 'account.view'],
  },
  system: {
    label: 'System Service / Device Agent', short: 'System', scope: 'machine', rank: 0,
    desc: 'Narrowly scoped machine-to-machine identity. Must never inherit human administrator rights.',
    perms: ['agent.checkin', 'agent.attest', 'agent.policy'],
  },
};

export const HUMAN_ROLES = Object.keys(ROLES).filter((r) => r !== 'system');
export const BACKEND_ADMIN_ROLES = [
  'superadmin', 'inst_admin', 'exam_controller', 'security_engineer',
  'invigilator', 'it_admin', 'auditor', 'support', 'ops_admin',
];

/** Register custom roles loaded from the database. */
export function registerRoles(list = []) {
  custom = {};
  for (const r of list) if (r && r.id && Array.isArray(r.perms)) custom[r.id] = { ...r, custom: true };
}
export function roleInfo(role) { return ROLES[role] || custom[role] || null; }
export function allRoles() { return { ...ROLES, ...custom }; }
export function roleLabel(role) { return roleInfo(role)?.label || role; }

export const can = (role, perm) => {
  const r = roleInfo(role);
  if (!r) return false;
  if (r.perms.includes('*')) return true;
  if (!perm) return true;
  return r.perms.some((p) => p === perm || (p.endsWith('.*') && perm.startsWith(p.slice(0, -1))));
};

/** Effective permissions for display and review. */
export function permissionsOf(role) {
  const r = roleInfo(role);
  if (!r) return [];
  if (r.perms.includes('*')) return ['*'];
  return [...r.perms].sort();
}
export const isGlobal = (role) => roleInfo(role)?.scope === 'global' || can(role, '*');
export const isPrivileged = (role) => (roleInfo(role)?.rank || 0) >= 60;
export const higherPrivilege = (role) => HumanRolesHigher(role);
const HumanRolesHigher = (role) => HUMAN_ROLES.filter((r) => (roleInfo(r)?.rank || 0) > (roleInfo(role)?.rank || 0));

export const PERMISSION_GROUPS = [
  { group: 'Platform', perms: ['tenant.manage', 'user.manage', 'role.manage', 'approval.view', 'approval.decide', 'settings.manage', 'settings.inst'] },
  { group: 'Institution', perms: ['inst.view', 'inst.manage', 'campus.manage', 'dept.manage', 'staff.manage'] },
  { group: 'Examinations', perms: ['exam.view', 'exam.manage', 'exam.approve', 'exam.operate', 'exam.policy', 'candidate.view', 'candidate.manage', 'candidate.verify', 'center.manage'] },
  { group: 'Devices & USB', perms: ['device.view', 'device.manage', 'usb.view', 'usb.manage', 'usb.assign', 'fleet.manage', 'compat.view', 'compat.manage', 'tpm.run'] },
  { group: 'Security', perms: ['security.view', 'security.manage', 'policy.view', 'policy.edit', 'policy.publish', 'policy.rollback', 'firewall.manage', 'incident.view', 'incident.manage', 'evidence.view', 'evidence.manage'] },
  { group: 'Releases', perms: ['release.view', 'release.manage', 'release.approve', 'release.rollout'] },
  { group: 'Operations', perms: ['ops.view', 'session.terminate', 'monitor.view', 'notify.manage', 'notification.view'] },
  { group: 'Compliance', perms: ['audit.view', 'audit.institution', 'audit.platform', 'audit.export', 'report.generate', 'export', 'privacy.view', 'privacy.manage'] },
  { group: 'Commercial & Support', perms: ['billing.view', 'billing.manage', 'support.view', 'support.manage', 'support.diagnostics'] },
  { group: 'Student', perms: ['student.view', 'student.session', 'student.check', 'account.view'] },
];
