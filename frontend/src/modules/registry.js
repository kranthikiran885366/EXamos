import { lazy } from 'react';
const m = (key, letter, label, load) => ({ key, letter, label, path: '/' + key, Page: lazy(load) });
// One folder per module: <key>/service.js (logic + persistence) and <Key>Page.jsx (UI). Sidebar, routes and RBAC derive from this list.
export const MODULES = [
  m('admin', 'A', 'Admin', () => import('./admin/AdminPage')),
  m('iam', 'B', 'IAM', () => import('./iam/IamPage')),
  m('exams', 'C', 'Exam Lifecycle', () => import('./exams/ExamsPage')),
  m('firewall', 'D', 'Firewall', () => import('./firewall/FirewallPage')),
  m('kiosk', 'E', 'Kiosk', () => import('./kiosk/KioskPage')),
  m('fleet', 'F', 'Fleet', () => import('./fleet/FleetPage')),
  m('tpm', 'G', 'TPM Trust', () => import('./tpm/TpmPage')),
  m('ops', 'H', 'Ops', () => import('./ops/OpsPage')),
  m('incidents', 'I', 'Incidents', () => import('./incidents/IncidentsPage')),
  m('submissions', 'J', 'Submissions', () => import('./submissions/SubmissionsPage')),
  m('releases', 'K', 'Releases', () => import('./releases/ReleasesPage')),
  m('audit', 'L', 'Audit', () => import('./audit/AuditPage')),
  m('candidates', 'M', 'Candidates', () => import('./candidates/CandidatesPage')),
  m('centers', 'N', 'Centers', () => import('./centers/CentersPage')),
  m('policies', 'O', 'Policies', () => import('./policies/PoliciesPage')),
  m('reports', 'P', 'Reports', () => import('./reports/ReportsPage')),
];
