// SPPIO Console — reporting service.
//
// Every value shown by the report pages comes from the authenticated server-side
// reporting API (`/api/v1/reports/*`, implemented in server/controllers/
// reports_controller.c). Nothing here aggregates, samples or fabricates data:
// this module only builds filter parameters, calls the API, formats returned
// values for display and triggers the browser download of a server-generated
// export.
//
// Server guarantees relied on here:
//   * tenant scope and RBAC are resolved from the bearer/cookie session,
//   * `from`/`to` filters are epoch milliseconds,
//   * exports exist only as CSV and JSON,
//   * each export is appended to `report_exports` before it is returned.

import { api } from '../../core/api/client';

const BASE = '/api/v1/reports';

export const GROUPS = {
  exams: 'Exams',
  devices: 'Devices',
  security: 'Security',
  business: 'Business',
};

export const DEFAULT_PAGE_SIZE = 25;

/* ------------------------------------------------------------------ params */

function toQuery(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const out = search.toString();
  return out ? `?${out}` : '';
}

/** Local-midnight epoch milliseconds for a `<input type="date">` value. */
export function dateStartEpoch(value) {
  if (!value) return '';
  const time = new Date(`${value}T00:00:00`).getTime();
  return Number.isFinite(time) ? time : '';
}

/** Last millisecond of the selected local day. */
export function dateEndEpoch(value) {
  if (!value) return '';
  const time = new Date(`${value}T23:59:59.999`).getTime();
  return Number.isFinite(time) ? time : '';
}

/** Inverse of dateStartEpoch for showing an existing filter in the UI. */
export function epochToDateInput(epoch) {
  if (!epoch) return '';
  const d = new Date(Number(epoch));
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export const emptyFilters = () => ({
  q: '',
  status: '',
  examId: '',
  from: '',
  to: '',
  fromDate: '',
  toDate: '',
  page: 1,
  pageSize: DEFAULT_PAGE_SIZE,
});

/* --------------------------------------------------------------------- api */

/** Catalog: groups/reports the signed-in role may view, plus capabilities. */
export async function getCatalog() {
  const res = await api.get(`${BASE}/catalog`, { actor: 'reports' });
  return res.data;
}

/** One headline summary per group the signed-in role may view. */
export async function getHub(filters = {}, institutionId = null) {
  const query = toQuery({
    from: filters.from,
    to: filters.to,
    q: filters.q,
    status: filters.status,
    examId: filters.examId,
    institutionId,
  });
  const res = await api.get(`${BASE}/hub${query}`, { actor: 'reports' });
  return res.data;
}

/** A single report for a group (exams, devices, security, business). */
export async function getReport(group, report, filters = {}, institutionId = null) {
  const query = toQuery({
    report,
    from: filters.from,
    to: filters.to,
    q: filters.q,
    status: filters.status,
    examId: filters.examId,
    page: filters.page || 1,
    pageSize: filters.pageSize || DEFAULT_PAGE_SIZE,
    institutionId,
  });
  const res = await api.get(`${BASE}/${group}${query}`, { actor: 'reports' });
  return res.data;
}

/** Append-only export history for the caller's tenant scope. */
export async function getHistory(institutionId = null) {
  const query = toQuery({ institutionId });
  const res = await api.get(`${BASE}/history${query}`, { actor: 'reports' });
  return res.data;
}

/**
 * Ask the server to render an export. The server re-runs the report with the
 * caller's scope, renders CSV/JSON, hashes the content and records the audit
 * row before returning the bytes in a JSON envelope.
 */
export async function createExport({ report, group, format, filters = {}, institutionId = null }) {
  const query = toQuery({
    from: filters.from,
    to: filters.to,
    q: filters.q,
    status: filters.status,
    examId: filters.examId,
    institutionId,
  });
  const res = await api.post(
    `${BASE}/export${query}`,
    { report, group, format },
    { actor: 'reports' },
  );
  return res.data;
}

/** Save a server-generated export to disk without altering its bytes. */
export function downloadExport(exp) {
  if (!exp || typeof exp.content !== 'string') {
    throw new Error('The server did not return export content.');
  }
  const blob = new Blob([exp.content], { type: exp.contentType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = exp.filename || 'sppio-report';
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* -------------------------------------------------------------- formatting */

export const SUMMARY_LABELS = {
  total: 'Total',
  live: 'Live',
  finalized: 'Finalized',
  cancelled: 'Cancelled',
  assigned: 'Assigned',
  started: 'Started',
  submitted: 'Submitted',
  attendancePct: 'Attendance',
  completionPct: 'Completion',
  submissions: 'Submissions',
  averageScore: 'Average score',
  averagePercentage: 'Average %',
  passRate: 'Pass rate',
  receipts: 'Receipts',
  identityVerified: 'Identity verified',
  seated: 'Seated',
  deviceAttested: 'Device attested',
  ready: 'Ready',
  devices: 'Devices',
  enrolled: 'Enrolled',
  attested: 'Attested',
  isolated: 'Isolated',
  online: 'Online (60s)',
  compliancePct: 'Compliance',
  trusted: 'Trusted',
  failed: 'Failed',
  unverified: 'Unverified',
  passed: 'Passed',
  notRun: 'Not run',
  assets: 'Assets',
  issued: 'Issued',
  available: 'Available',
  quarantined: 'Quarantined',
  lost: 'Lost',
  open: 'Open',
  critical: 'Critical',
  resolved: 'Resolved',
  high: 'High',
  fixed: 'Fixed',
  releases: 'Releases',
  stable: 'Stable',
  revoked: 'Revoked',
  criticalCves: 'Critical CVEs',
  evidence: 'Evidence',
  events: 'Events',
  actors: 'Actors',
  eventTypes: 'Event types',
  lastAt: 'Last activity',
  breached: 'SLA breached',
  satisfaction: 'Satisfaction',
  invoiced: 'Invoiced',
  paid: 'Paid',
  outstanding: 'Outstanding',
  overdue: 'Overdue',
};

export function summaryLabel(key) {
  if (SUMMARY_LABELS[key]) return SUMMARY_LABELS[key];
  return String(key || '')
    .replace(/Pct$/, ' %')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/^./, (c) => c.toUpperCase());
}

const PERCENT_KEYS = new Set([
  'attendancePct', 'completionPct', 'passRate', 'averagePercentage', 'compliancePct',
]);
const MONEY_KEYS = new Set(['invoiced', 'paid', 'outstanding']);

const numberFormat = new Intl.NumberFormat('en-IN', { maximumFractionDigits: 2 });
const moneyFormat = new Intl.NumberFormat('en-IN', {
  style: 'currency',
  currency: 'INR',
  maximumFractionDigits: 2,
});

function isNumber(value) {
  if (value === null || value === undefined || value === '') return false;
  return Number.isFinite(Number(value));
}

/** Display a KPI value returned in a report `summary` array. */
export function formatSummaryValue(key, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (key === 'lastAt') {
    if (!isNumber(value)) return '—';
    return formatEpoch(value) || '—';
  }
  if (PERCENT_KEYS.has(key)) return `${numberFormat.format(Number(value))}%`;
  if (MONEY_KEYS.has(key)) return moneyFormat.format(Number(value));
  if (isNumber(value)) return numberFormat.format(Number(value));
  return String(value);
}

export function formatEpoch(value, timeZone = 'Asia/Kolkata') {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return '';
  const d = new Date(n);
  if (Number.isNaN(d.getTime())) return '';
  try {
    return d.toLocaleString('en-IN', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      timeZone: timeZone || 'Asia/Kolkata',
      timeZoneName: 'short',
    });
  } catch {
    return d.toLocaleString('en-IN', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }) + ' IST';
  }
}

/** Format a table cell using the column type supplied by the server. */
export function formatValue(value, type) {
  if (value === null || value === undefined || value === '') {
    return value === false ? 'No' : '—';
  }
  if (type === 'epoch') {
    const formatted = formatEpoch(value);
    return formatted || '—';
  }
  if (type === 'bool') {
    if (value === true || value === 'true' || value === 1 || value === '1') return 'Yes';
    if (value === false || value === 'false' || value === 0 || value === '0') return 'No';
    return String(value);
  }
  if (type === 'percent') {
    return isNumber(value) ? `${numberFormat.format(Number(value))}%` : String(value);
  }
  if (type === 'number') {
    return isNumber(value) ? numberFormat.format(Number(value)) : String(value);
  }
  return String(value);
}

/* -------------------------------------------------------------- cataloging */

export function findGroup(catalog, group) {
  return catalog?.groups?.find((g) => g.key === group) || null;
}

export function findReport(catalog, key) {
  for (const group of catalog?.groups || []) {
    const report = (group.reports || []).find((r) => r.key === key);
    if (report) return report;
  }
  return null;
}

/** Reports for a group, optionally restricted to a preferred display order. */
export function reportsForGroup(catalog, group, preferredKeys) {
  const reports = findGroup(catalog, group)?.reports || [];
  if (!preferredKeys?.length) return reports;
  const byKey = new Map(reports.map((r) => [r.key, r]));
  return preferredKeys.map((key) => byKey.get(key)).filter(Boolean);
}

export function reportLabel(catalog, key) {
  return findReport(catalog, key)?.label || key;
}

/** Human-readable explanation of a failed report request. */
export function reportError(error) {
  const status = error?.status;
  if (status === 401) return 'Your session expired or is missing. Sign in again to view reports.';
  if (status === 403) return error?.message || 'Your role cannot view this report.';
  if (status === 400) return error?.message || 'The report filters were rejected.';
  if (status === 404) return 'This report endpoint does not exist on the connected server.';
  if (status >= 500) return 'The reporting service failed to build this report. No cached or fabricated data is shown.';
  return error?.message || 'The report could not be loaded.';
}
