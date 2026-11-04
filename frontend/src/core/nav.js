// Navigation and route registry. Sidebar, route table and permissions derive from this list.
const page = (loader, name) => (() => {
  return loader()
    .then((m) => ({ default: m[name] }))
    .catch((err) => {
      const isChunkError = /Failed to fetch dynamically imported module|Importing a module script failed/i.test(err?.message || '');
      if (isChunkError) {
        const key = 'examos_reload_' + (name || 'chunk');
        if (!sessionStorage.getItem(key)) {
          sessionStorage.setItem(key, '1');
          window.location.reload();
          return new Promise(() => {});
        }
      }
      throw err;
    });
});

const D = (path, label, perm, load, group, opts = {}) => ({ path, label, perm, load, group, ...opts });

export const ROUTE_DEFS = [
  // Overview
  D('/dashboard', 'Overview', 'dashboard.view', page(() => import('../modules/dashboard/DashboardPage'), 'default'), 'Overview', { icon: 'grid' }),

  // ── Platform Admin (ExamOS team) ──────────────────────────────────────────
  D('/platform/institutions', 'Overview', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformInstitutionsOverviewPage'), 'Platform Admin', { icon: 'grid' }),
  D('/platform/institutions/directory', 'Institutions', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformInstitutionsDirectoryPage'), 'Platform Admin', { icon: 'building' }),
  D('/platform/institutions/applications', 'Applications & Verification', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformApplicationsPage'), 'Platform Admin', { icon: 'checklist' }),
  D('/platform/provisioning', 'Tenant Provisioning', 'inst.provision', page(() => import('../modules/platform/PlatformPages'), 'PlatformProvisioningPage'), 'Platform Admin', { icon: 'server' }),
  D('/platform/readiness', 'Pilot & Readiness', 'inst.review', page(() => import('../modules/platform/PlatformPages'), 'PlatformReadinessPage'), 'Platform Admin', { icon: 'checklist' }),
  D('/platform/operations', 'Operations & Audit', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformOperationsPage'), 'Platform Admin', { icon: 'shield' }),
  D('/platform/institutions/:id/verification', 'Verification', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformVerificationPage'), 'Platform Admin', { nav: false }),
  D('/platform/institutions/:id/provisioning', 'Provisioning', 'inst.provision', page(() => import('../modules/platform/PlatformPages'), 'PlatformProvisioningPage'), 'Platform Admin', { nav: false }),
  D('/platform/institutions/:id/readiness', 'Readiness', 'inst.review', page(() => import('../modules/platform/PlatformPages'), 'PlatformReadinessPage'), 'Platform Admin', { nav: false }),
  D('/platform/institutions/:id/operations', 'Operations', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformOperationsPage'), 'Platform Admin', { nav: false }),
  D('/platform/institutions/:id', 'Institution Detail', 'tenant.manage', page(() => import('../modules/platform/PlatformPages'), 'PlatformInstitutionDetailPage'), 'Platform Admin', { nav: false }),

  // ── Institution Admin (college/university team) ───────────────────────────
  D('/institution/dashboard', 'Dashboard', 'inst.view', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionDashboardPage'), 'Institution Admin', { icon: 'home' }),
  D('/institution/settings/profile', 'Institution Profile', 'inst.view', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionProfilePage'), 'Institution Admin', { icon: 'building' }),
  D('/institution/organization', 'Organization Structure', 'inst.manage', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionOrganizationPage'), 'Institution Admin', { icon: 'layers' }),
  D('/institution/settings/access', 'Administrators & Access', 'user.manage', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionAccessPage'), 'Institution Admin', { icon: 'users' }),
  D('/institution/settings/security', 'Security & Deployment', 'settings.inst', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionSecurityPage'), 'Institution Admin', { icon: 'shield' }),
  D('/institution/deployment', 'Deployment Readiness', 'deployment.view', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionDeploymentReadinessPage'), 'Institution Admin', { icon: 'device' }),
  D('/institution/audit', 'Audit & Activity', 'audit.view', page(() => import('../modules/institution-admin/InstitutionAdminPages'), 'InstitutionAuditPage'), 'Institution Admin', { icon: 'shield' }),

  // Administration
  D('/admin/institutions', 'Institutions', 'inst.view', page(() => import('../modules/institutions/pages'), 'InstitutionsPage'), 'Administration', { icon: 'building', end: true }),
  D('/admin/institutions/:id', 'Institution', 'inst.view', page(() => import('../modules/institutions/pages'), 'InstitutionDetailPage'), 'Administration', { nav: false }),
  D('/admin/institution-applications', 'Applications queue', 'inst.view', page(() => import('../modules/institutions/pages'), 'InstitutionApplicationsPage'), 'Administration', { icon: 'checklist' }),
  D('/admin/institution-applications/:id', 'Application details', 'inst.view', page(() => import('../modules/institutions/pages'), 'InstitutionApplicationDetailPage'), 'Administration', { nav: false }),
  D('/admin/users', 'Users', 'user.manage', page(() => import('../modules/users/pages'), 'UsersPage'), 'Administration', { icon: 'users', end: true }),
  D('/admin/users/:id', 'User', 'user.manage', page(() => import('../modules/users/pages'), 'UserDetailPage'), 'Administration', { nav: false }),
  D('/admin/roles', 'Roles & permissions', 'user.manage', page(() => import('../modules/users/pages'), 'RolesPage'), 'Administration', { icon: 'key' }),
  D('/admin/approvals', 'Approvals', 'approval.view', page(() => import('../modules/users/pages'), 'ApprovalsPage'), 'Administration', { icon: 'check' }),
  D('/admin/settings', 'Settings', 'settings.view', page(() => import('../modules/settings/pages'), 'SettingsPage'), 'Administration', { icon: 'settings' }),
  D('/admin/integrations', 'Integrations', 'settings.view', page(() => import('../modules/settings/pages'), 'IntegrationsPage'), 'Administration', { nav: false }),
  D('/admin/feature-controls', 'Feature controls', 'settings.view', page(() => import('../modules/settings/pages'), 'FeatureControlsPage'), 'Administration', { nav: false }),
  D('/admin/system-health', 'System health', 'monitor.view', page(() => import('../modules/settings/pages'), 'SystemHealthPage'), 'Administration', { icon: 'pulse' }),
  D('/admin/audit', 'Audit trail', 'audit.view', page(() => import('../modules/audit/AuditPage'), 'default'), 'Administration', { icon: 'shield' }),
  D('/admin/releases', 'Releases', 'release.view', page(() => import('../modules/releases/pages'), 'ReleasesPage'), 'Releases & rollout', { icon: 'package', end: true }),
  D('/releases/:id', 'Release', 'release.view', page(() => import('../modules/releases/pages'), 'ReleaseDetailPage'), 'Releases & rollout', { nav: false }),
  D('/release-rollouts', 'Rollouts', 'release.view', page(() => import('../modules/releases/pages'), 'RolloutsPage'), 'Releases & rollout', { icon: 'upload' }),
  D('/release-validation', 'Validation & evidence', 'release.view', page(() => import('../modules/releases/pages'), 'ReleaseValidationPage'), 'Releases & rollout', { icon: 'checklist' }),
  D('/security/evidence', 'Evidence vault', 'evidence.view', page(() => import('../modules/security/pages'), 'EvidencePage'), 'Releases & rollout', { nav: false }),

  // Institution
  D('/college/overview', 'Institution overview', 'inst.view', page(() => import('../modules/institutions/pages'), 'CollegeOverviewPage'), 'Institution', { icon: 'home' }),
  D('/college/campuses', 'Campuses', 'inst.view', page(() => import('../modules/institutions/pages'), 'CampusesPage'), 'Institution', { icon: 'pin' }),
  D('/college/centers', 'Centers', 'inst.view', page(() => import('../modules/centers/CentersPage'), 'default'), 'Institution', { icon: 'building' }),
  D('/college/departments', 'Departments', 'inst.view', page(() => import('../modules/institutions/pages'), 'DepartmentsPage'), 'Institution', { icon: 'layers' }),
  D('/college/staff', 'Staff', 'staff.manage', page(() => import('../modules/institutions/pages'), 'StaffPage'), 'Institution', { icon: 'badge' }),
  D('/college/settings', 'Institution settings', 'settings.inst', page(() => import('../modules/institutions/pages'), 'CollegeSettingsPage'), 'Institution', { icon: 'settings' }),
  D('/college/subscription', 'Subscription', 'billing.view', page(() => import('../modules/billing/pages'), 'SubscriptionPage'), 'Institution', { icon: 'card' }),
  D('/college/audit', 'Institution audit', 'audit.view', page(() => import('../modules/audit/AuditPage'), 'default'), 'Institution', { nav: false }),

  // Examinations
  D('/college/exams', 'Exams & schedules', 'exam.view', page(() => import('../modules/exams/pages'), 'ExamsPage'), 'Examinations', { icon: 'exam', end: true }),
  D('/college/exams/new', 'New exam', 'exam.manage', page(() => import('../modules/exams/pages'), 'ExamNewPage'), 'Examinations', { nav: false }),
  D('/college/exams/:id', 'Exam', 'exam.view', page(() => import('../modules/exams/pages'), 'ExamDetailPage'), 'Examinations', { nav: false }),
  D('/college/exams/:id/candidates', 'Candidates', 'candidate.manage', page(() => import('../modules/exams/pages'), 'ExamCandidatesPage'), 'Examinations', { nav: false }),
  D('/college/exams/:id/policies', 'Exam policy', 'exam.policy', page(() => import('../modules/exams/pages'), 'ExamPoliciesPage'), 'Examinations', { nav: false }),
  D('/college/candidates', 'Candidates', 'candidate.view', page(() => import('../modules/candidates/pages'), 'CandidatesPage'), 'Examinations', { icon: 'candidate' }),

  // Student
  D('/student/home', 'My exams', 'student.view', page(() => import('../modules/student/pages'), 'StudentHomePage'), 'Student', { icon: 'home' }),
  D('/student/exams', 'Assignments', 'student.view', page(() => import('../modules/student/pages'), 'StudentExamsPage'), 'Student', { icon: 'exam' }),
  D('/student/exams/:id', 'Exam briefing', 'student.view', page(() => import('../modules/student/pages'), 'StudentExamPage'), 'Student', { nav: false }),
  D('/student/exams/:id/device-check', 'Device check', 'student.check', page(() => import('../modules/student/pages'), 'StudentDeviceCheckPage'), 'Student', { nav: false }),
  D('/student/exams/:id/session', 'Exam session', 'student.session', page(() => import('../modules/student/pages'), 'StudentSessionPage'), 'Student', { nav: false }),
  D('/student/exams/:id/submission', 'Submission', 'student.view', page(() => import('../modules/student/pages'), 'StudentSubmissionPage'), 'Student', { nav: false }),
  D('/student/history', 'History & receipts', 'student.view', page(() => import('../modules/student/pages'), 'StudentHistoryPage'), 'Student', { icon: 'history' }),

  // Operator
  D('/operator/overview', 'Operations overview', 'ops.view', page(() => import('../modules/operator/pages'), 'OperatorOverviewPage'), 'Operations', { icon: 'pulse' }),
  D('/operator/exams', 'Assigned exams', 'ops.view', page(() => import('../modules/operator/pages'), 'OperatorExamsPage'), 'Operations', { icon: 'exam' }),
  D('/operator/exams/:id/live', 'Live session', 'ops.view', page(() => import('../modules/operator/pages'), 'LiveExamPage'), 'Operations', { nav: false }),
  D('/operator/exams/:id/incidents', 'Exam incidents', 'incident.view', page(() => import('../modules/operator/pages'), 'OperatorIncidentsPage'), 'Operations', { nav: false }),
  D('/operator/exams/:id/submissions', 'Submissions', 'ops.view', page(() => import('../modules/operator/pages'), 'OperatorSubmissionsPage'), 'Operations', { nav: false }),
  D('/operator/incidents', 'Incident queue', 'incident.view', page(() => import('../modules/operator/pages'), 'OperatorIncidentsPage'), 'Operations', { icon: 'alert' }),

  // Devices & USB
  D('/devices', 'Devices', 'device.view', page(() => import('../modules/devices/pages'), 'DevicesPage'), 'Devices & USB', { icon: 'device', end: true }),
  D('/devices/enrollment', 'Enrollment', 'device.view', page(() => import('../modules/devices/pages'), 'EnrollmentPage'), 'Devices & USB', { icon: 'plus' }),
  D('/devices/compatibility', 'Compatibility', 'compat.view', page(() => import('../modules/devices/pages'), 'CompatibilityPage'), 'Devices & USB', { icon: 'checklist' }),
  D('/devices/:id', 'Device', 'device.view', page(() => import('../modules/devices/pages'), 'DeviceDetailPage'), 'Devices & USB', { nav: false }),
  D('/devices/:id/attestation', 'Attestation', 'device.view', page(() => import('../modules/devices/pages'), 'DeviceAttestationPage'), 'Devices & USB', { nav: false }),
  D('/usb-inventory', 'USB inventory', 'usb.view', page(() => import('../modules/usb/pages'), 'UsbInventoryPage'), 'Devices & USB', { icon: 'usb' }),
  D('/usb-inventory/:id', 'USB asset', 'usb.view', page(() => import('../modules/usb/pages'), 'UsbDetailPage'), 'Devices & USB', { nav: false }),

  // Security
  D('/security/overview', 'Security overview', 'security.view', page(() => import('../modules/security/pages'), 'SecurityOverviewPage'), 'Security', { icon: 'shield' }),
  D('/security/boot-integrity', 'Boot integrity', 'security.view', page(() => import('../modules/security/pages'), 'BootIntegrityPage'), 'Security', { icon: 'boot' }),
  D('/security/attestation', 'Attestation', 'security.view', page(() => import('../modules/security/pages'), 'AttestationPage'), 'Security', { icon: 'cpu' }),
  D('/security/policies', 'Security policies', 'policy.view', page(() => import('../modules/security/pages'), 'SecurityPoliciesPage'), 'Security', { icon: 'policy' }),
  D('/security/events', 'Security events', 'security.view', page(() => import('../modules/security/pages'), 'SecurityEventsPage'), 'Security', { icon: 'radar' }),
  D('/security/incident-response', 'Incident response', 'incident.view', page(() => import('../modules/security/pages'), 'IncidentResponsePage'), 'Security', { icon: 'alert' }),
  D('/security/vulnerabilities', 'Vulnerabilities', 'security.view', page(() => import('../modules/security/pages'), 'VulnerabilitiesPage'), 'Security', { icon: 'bug' }),

  // Monitoring
  D('/monitoring/overview', 'Platform monitoring', 'monitor.view', page(() => import('../modules/monitoring/pages'), 'MonitoringOverviewPage'), 'Monitoring', { icon: 'pulse' }),
  D('/monitoring/services', 'Services', 'monitor.view', page(() => import('../modules/monitoring/pages'), 'ServicesPage'), 'Monitoring', { icon: 'server' }),
  D('/monitoring/alerts', 'Alerts', 'monitor.view', page(() => import('../modules/monitoring/pages'), 'AlertsPage'), 'Monitoring', { icon: 'bell' }),

  // Reports
  D('/reports', 'Report hub', 'report.generate', page(() => import('../modules/reports/pages'), 'ReportsPage'), 'Reports', { icon: 'chart' }),
  D('/reports/exams', 'Exam reports', 'report.generate', page(() => import('../modules/reports/pages'), 'ExamReportsPage'), 'Reports', { icon: 'exam' }),
  D('/reports/devices', 'Device reports', 'report.generate', page(() => import('../modules/reports/pages'), 'DeviceReportsPage'), 'Reports', { icon: 'device' }),
  D('/reports/security', 'Security reports', 'report.generate', page(() => import('../modules/reports/pages'), 'SecurityReportsPage'), 'Reports', { icon: 'shield' }),

  // Support
  D('/support', 'Support home', 'support.view', page(() => import('../modules/support/pages'), 'SupportHomePage'), 'Support', { icon: 'life' }),
  D('/support/requests', 'Requests', 'support.view', page(() => import('../modules/support/pages'), 'SupportRequestsPage'), 'Support', { icon: 'ticket' }),
  D('/support/requests/:id', 'Request', 'support.view', page(() => import('../modules/support/pages'), 'SupportRequestDetailPage'), 'Support', { nav: false }),
  D('/support/diagnostics', 'Diagnostics', 'support.view', page(() => import('../modules/support/pages'), 'DiagnosticsPage'), 'Support', { icon: 'stethoscope' }),
  D('/support/status', 'Service status', 'support.view', page(() => import('../modules/support/pages'), 'StatusPage'), 'Support', { icon: 'status' }),
  D('/support/recovery', 'Recovery', 'support.view', page(() => import('../modules/support/pages'), 'RecoveryPage'), 'Support', { icon: 'recover' }),

  // Business
  D('/admin/billing', 'Plans & billing', 'billing.view', page(() => import('../modules/billing/pages'), 'BillingPage'), 'Business', { icon: 'card' }),
  D('/admin/usage', 'Usage', 'billing.view', page(() => import('../modules/billing/pages'), 'UsagePage'), 'Business', { icon: 'chart' }),
  D('/admin/notifications', 'Notifications', 'notify.manage', page(() => import('../modules/notifications/pages'), 'AdminNotificationsPage'), 'Business', { icon: 'mail' }),

  // Privacy
  D('/admin/privacy', 'Privacy & governance', 'privacy.view', page(() => import('../modules/privacy/pages'), 'PrivacyPage'), 'Privacy', { icon: 'lock' }),
  D('/admin/retention', 'Retention', 'privacy.view', page(() => import('../modules/privacy/pages'), 'RetentionPage'), 'Privacy', { icon: 'clock' }),

  // Account / personal
  D('/account', 'Account', null, page(() => import('../modules/account/pages'), 'AccountPage'), 'Account', { icon: 'user' }),
  D('/account/security', 'Security', null, page(() => import('../modules/account/pages'), 'AccountSecurityPage'), 'Account', { nav: false }),
  D('/account/sessions', 'Sessions', null, page(() => import('../modules/account/pages'), 'AccountSessionsPage'), 'Account', { nav: false }),
  D('/notifications', 'Inbox', 'notification.view', page(() => import('../modules/notifications/pages'), 'NotificationsPage'), 'Account', { icon: 'bell' }),
];

export const ROUTES = ROUTE_DEFS;

export const GROUPS = [...new Set(ROUTE_DEFS.filter((r) => r.nav !== false).map((r) => r.group))].map((g) => ({
  label: g,
  items: ROUTE_DEFS.filter((r) => r.nav !== false && r.group === g),
}));

export const TITLES = {
  '/dashboard': 'Overview',
  '/register-institution': 'Institution Accreditation & Onboarding',
  // Platform Admin
  '/platform/institutions': 'Institution Overview',
  '/platform/institutions/directory': 'Institution Directory',
  '/platform/institutions/applications': 'Onboarding Applications',
  '/platform/provisioning': 'Tenant Provisioning',
  '/platform/readiness': 'Pilot & Readiness',
  '/platform/operations': 'Operations & Audit',
  '/platform/institutions/:id': 'Institution Details',
  '/platform/institutions/:id/verification': 'Identity Verification',
  '/platform/institutions/:id/provisioning': 'Tenant Provisioning',
  '/platform/institutions/:id/readiness': 'Pilot & Readiness',
  '/platform/institutions/:id/operations': 'Operations & Audit',
  // Institution Admin
  '/institution/dashboard': 'Institution Dashboard',
  '/institution/settings/profile': 'Institution Profile',
  '/institution/organization': 'Organization Structure',
  '/institution/settings/access': 'Administrators & Access',
  '/institution/settings/security': 'Security & Deployment',
  '/institution/deployment': 'Deployment Readiness',
  '/institution/audit': 'Audit & Activity',
  '/admin/institutions': 'Institutions',
  '/admin/institution-applications': 'Applications queue',
  '/admin/institution-applications/:id': 'Application details',
  '/admin/users': 'Users',
  '/admin/roles': 'Roles & permissions',
  '/admin/approvals': 'Approvals',
  '/admin/settings': 'Platform settings',
  '/admin/integrations': 'Integrations',
  '/admin/feature-controls': 'Feature controls',
  '/admin/system-health': 'System health',
  '/admin/audit': 'Audit trail',
  '/admin/releases': 'Releases',
  '/release-rollouts': 'Release rollouts',
  '/release-validation': 'Validation & evidence',
  '/college/overview': 'Institution overview',
  '/college/campuses': 'Campuses',
  '/college/departments': 'Departments',
  '/college/staff': 'Staff',
  '/college/settings': 'Institution settings',
  '/college/subscription': 'Subscription',
  '/college/audit': 'Institution audit',
  '/college/exams': 'Exams & schedules',
  '/college/candidates': 'Candidates',
  '/student/home': 'My exams',
  '/student/exams': 'Assignments',
  '/student/history': 'History & receipts',
  '/operator/overview': 'Operations overview',
  '/operator/exams': 'Assigned exams',
  '/operator/incidents': 'Incident queue',
  '/devices': 'Devices',
  '/devices/enrollment': 'Enrollment',
  '/devices/compatibility': 'Compatibility',
  '/usb-inventory': 'USB inventory',
  '/security/overview': 'Security overview',
  '/security/boot-integrity': 'Boot integrity',
  '/security/attestation': 'Attestation',
  '/security/policies': 'Security policies',
  '/security/events': 'Security events',
  '/security/incident-response': 'Incident response',
  '/security/vulnerabilities': 'Vulnerabilities',
  '/security/evidence': 'Evidence vault',
  '/monitoring/overview': 'Platform monitoring',
  '/monitoring/services': 'Services',
  '/monitoring/alerts': 'Alerts',
  '/reports': 'Report hub',
  '/reports/exams': 'Exam reports',
  '/reports/devices': 'Device reports',
  '/reports/security': 'Security reports',
  '/support': 'Support home',
  '/support/requests': 'Support requests',
  '/support/diagnostics': 'Diagnostics',
  '/support/status': 'Service status',
  '/support/recovery': 'Recovery',
  '/admin/billing': 'Plans & billing',
  '/admin/usage': 'Usage',
  '/admin/notifications': 'Notifications',
  '/admin/privacy': 'Privacy & governance',
  '/admin/retention': 'Retention',
  '/account': 'Account',
  '/account/security': 'Account security',
  '/account/sessions': 'Sessions',
  '/notifications': 'Inbox',
};

/** Legacy routes preserved as redirects so old links keep working. */
export const LEGACY = {
  '/admin': '/admin/institutions',
  '/iam': '/admin/users',
  '/exams': '/college/exams',
  '/firewall': '/security/policies',
  '/kiosk': '/devices/compatibility',
  '/fleet': '/devices',
  '/tpm': '/security/attestation',
  '/ops': '/operator/overview',
  '/incidents': '/security/incident-response',
  '/submissions': '/operator/exams',
  '/releases': '/admin/releases',
  '/audit': '/admin/audit',
  '/candidates': '/college/candidates',
  '/centers': '/college/centers',
  '/policies': '/security/policies',
  '/reports/legacy': '/reports',
};
