import { all, put } from '../../core/db/db';
import { sha256 } from '../../core/security/crypto';
import { id, need, log } from '../../core/services/common';
import { compliant } from '../fleet/service';
import * as Api from '../../core/api/services';

export const TYPES = { attendance: 'Attendance by exam', results: 'Exam results', attestation: 'Attestation outcomes', fleet: 'Fleet compliance by center', incidents: 'Incident register' };
const d = (t) => (t ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) : '');
export async function buildFromBackend(type, tenantId) {
  try {
    const res = await Api.listAuditTrail({ limit: 500 });
    if (type === 'audit-summary' && res?.events) {
      const counts = {};
      for (const e of res.events) { const k = e.event; counts[k] = (counts[k] || 0) + 1; }
      return { cols: ['Event', 'Count'], rows: Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, n]) };
    }
  } catch { /* fall through to local */ }
  return null;
}

export async function build(type, tenantId) {
  const f = (r) => !tenantId || r.tenantId === tenantId;
  const [exams, cands, sess, devs, atts, incs, pols, rels, ctrs] = await Promise.all(['exams', 'candidates', 'sessions', 'devices', 'attestations', 'incidents', 'policies', 'releases', 'centers'].map(all));
  if (type === 'attendance') return { cols: ['Exam', 'Status', 'Assigned', 'Started', 'Submitted', 'Attendance %'], rows: exams.filter(f).map((e) => { const a = cands.filter((c) => c.examId === e.id).length, s = sess.filter((x) => x.examId === e.id), sub = s.filter((x) => x.status === 'submitted').length; return [e.code, e.status, a, s.length, sub, a ? Math.round((s.length / a) * 100) : 0]; }) };
  if (type === 'results') return { cols: ['Exam', 'Roll no', 'Candidate', 'Score', 'Out of', 'Receipt'], rows: sess.filter((s) => f(s) && s.status === 'submitted').map((s) => { const c = cands.find((x) => x.id === s.candidateId), e = exams.find((x) => x.id === s.examId); return [e?.code, c?.rollNo, c?.name, s.score, e?.questions.length, s.receipt]; }) };
  if (type === 'attestation') return { cols: ['Time (UTC)', 'Device', 'Result', 'Reason'], rows: atts.filter((a) => f(a) && a.result).sort((x, y) => y.issuedAt - x.issuedAt).slice(0, 500).map((a) => [d(a.issuedAt), a.hostname, a.result, a.reason]) };
  if (type === 'fleet') return { cols: ['Center', 'Devices', 'Compliant', 'Compliance %', 'Isolated'], rows: ctrs.filter(f).map((c) => { const v = devs.filter((x) => x.centerId === c.id), ok = v.filter((x) => compliant(x, pols, rels)).length; return [c.code, v.length, ok, v.length ? +((ok / v.length) * 100).toFixed(1) : 0, v.filter((x) => x.isolated).length]; }) };
  return { cols: ['Incident', 'Title', 'Severity', 'Kind', 'Status', 'Owner', 'Opened (UTC)'], rows: incs.filter(f).map((i) => ['INC-' + i.no, i.title, i.severity, i.kind, i.status, i.owner || '', d(i.createdAt)]) };
}
export async function saveReport(a, type, tenantId, rows) {
  need(a, 'report.generate');
  const hash = await sha256(JSON.stringify(rows));
  await put('reports', { id: id('rpt'), tenantId, type, count: rows.length, hash, by: a.id, at: Date.now() });
  await log(a, 'REPORT_GENERATED', `${type} rows=${rows.length} sha256=${hash.slice(0, 12)}`);
}

export const CATALOG = [
  { key: 'attendance', label: 'Attendance by exam', desc: 'Assigned, started and submitted counts for every exam.', group: 'Exams' },
  { key: 'results', label: 'Exam results', desc: 'Per-candidate score and signed submission receipt.', group: 'Exams' },
  { key: 'exam-summary', label: 'Exam summary', desc: 'Lifecycle status, centre coverage, policy and readiness.', group: 'Exams' },
  { key: 'candidate-readiness', label: 'Candidate readiness', desc: 'Assignment, identity, seat and device status per candidate.', group: 'Exams' },
  { key: 'fleet', label: 'Fleet compliance by centre', desc: 'Compliant devices, isolation and release coverage.', group: 'Devices' },
  { key: 'attestation', label: 'Attestation outcomes', desc: 'Recent TPM quote verification results and failure reasons.', group: 'Devices' },
  { key: 'compatibility', label: 'Compatibility results', desc: 'Latest preflight result per device.', group: 'Devices' },
  { key: 'usb-custody', label: 'USB custody', desc: 'USB assets, release, status and current holder.', group: 'Devices' },
  { key: 'incidents', label: 'Incident register', desc: 'All incidents with severity, status and owner.', group: 'Security' },
  { key: 'security-events', label: 'Security events', desc: 'Console security events and their resolution.', group: 'Security' },
  { key: 'vulnerabilities', label: 'Vulnerability register', desc: 'CVE findings, CVSS, ownership and status.', group: 'Security' },
  { key: 'release-validation', label: 'Release validation', desc: 'Release status, rollout, CVEs and evidence counts.', group: 'Security' },
  { key: 'audit-summary', label: 'Audit summary', desc: 'Event counts by actor and event type (not the raw trail).', group: 'Security' },
  { key: 'support', label: 'Support performance', desc: 'Requests, SLA breaches, resolution and satisfaction.', group: 'Business' },
  { key: 'billing', label: 'Billing summary', desc: 'Invoices, outstanding balance and payment status.', group: 'Business' },
];
export const GROUPS = [...new Set(CATALOG.map((c) => c.group))];

const fmtTime = (t) => (t ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) : '');

export async function buildReport(type, tenantId, opts = {}) {
  if (['attendance', 'results', 'attestation', 'fleet', 'incidents'].includes(type)) return build(type, tenantId);
  const f = (r) => !tenantId || r.tenantId === tenantId;
  const [exams, cands, sess, devs, atts, incs, pols, rels, ctrs, usbs, sec, vul, rev, sup, inv, audit] = await Promise.all(
    ['exams', 'candidates', 'sessions', 'devices', 'attestations', 'incidents', 'policies', 'releases', 'centers', 'usbs', 'securityEvents', 'vulnerabilities', 'releaseEvidence', 'support', 'invoices', 'audit'].map(all),
  );
  const exOf = (id) => exams.find((e) => e.id === id);
  const candOf = (id) => cands.find((c) => c.id === id);
  const devOf = (id) => devs.find((d) => d.id === id);
  if (type === 'exam-summary') return { cols: ['Code', 'Title', 'Status', 'Start', 'Duration', 'Centres', 'Assigned', 'Policy', 'Questions'], rows: exams.filter(f).map((e) => [e.code, e.title, e.status, fmtTime(e.startAt), e.durationMin, e.centerIds.length, cands.filter((c) => c.examId === e.id).length, pols.find((p) => p.id === e.policyId)?.name || '', e.questions.length]) };
  if (type === 'candidate-readiness') return { cols: ['Roll no', 'Candidate', 'Exam', 'Centre', 'Seat', 'Identity', 'Device', 'Trust', 'Status'], rows: cands.filter(f).map((c) => { const d = devs.find((x) => x.centerId === c.centerId && x.seat === c.seat); return [c.rollNo, c.name, exOf(c.examId)?.code || '', ctrs.find((x) => x.id === c.centerId)?.code || '', c.seat || '', c.identity, d?.hostname || 'none', d?.trust || 'unknown', c.status]; }) };
  if (type === 'compatibility') return { cols: ['Device', 'Centre', 'Seat', 'Profile', 'Overall', 'Last run', 'Release'], rows: devs.filter(f).map((d) => { const last = atts.filter((a) => a.deviceId === d.id && a.result).sort((x, y) => y.verifiedAt - x.verifiedAt)[0]; void last; return [d.hostname, ctrs.find((c) => c.id === d.centerId)?.code || '', d.seat, d.profile, d.compatStatus, fmtTime(d.lastCompatAt), rels.find((r) => r.id === d.releaseId)?.version || '']; }) };
  if (type === 'usb-custody') return { cols: ['Asset', 'Serial', 'Status', 'Release', 'Holder', 'Location', 'Last check'], rows: usbs.filter(f).map((u) => [u.assetId, u.serial, u.status, rels.find((r) => r.id === u.releaseId)?.version || '', u.holder?.name || '', u.lastLocation || u.station || '', fmtTime(u.lastCheckAt)]) };
  if (type === 'security-events') return { cols: ['Time', 'Type', 'Severity', 'Title', 'Status', 'Actor'], rows: sec.filter(f).sort((a, b) => b.at - a.at).map((e) => [fmtTime(e.at), e.type, e.severity, e.title, e.status, e.actor]) };
  if (type === 'vulnerabilities') return { cols: ['CVE', 'Component', 'Severity', 'CVSS', 'Status', 'Owner', 'Fixed in'], rows: vul.filter(f).map((v) => [v.cve || '', v.component, v.severity, v.cvss, v.status, v.owner || '', v.fixedIn || '']) };
  if (type === 'release-validation') return { cols: ['Version', 'Status', 'Rollout %', 'Critical CVEs', 'Findings', 'Evidence', 'Created'], rows: rels.map((r) => [r.version, r.status, r.rollout || 0, r.criticalCves || 0, r.findings?.length || 0, rev.filter((e) => e.releaseId === r.id).length, fmtTime(r.createdAt)]) };
  if (type === 'audit-summary') {
    const counts = {};
    for (const e of audit) { const k = e.event; counts[k] = (counts[k] || 0) + 1; }
    return { cols: ['Event', 'Count'], rows: Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, n]) };
  }
  if (type === 'support') return { cols: ['Request', 'Subject', 'Priority', 'Status', 'Assignee', 'SLA', 'Satisfaction'], rows: sup.filter(f).map((t) => [t.no, t.subject, t.priority, t.status, t.assignee || '', t.slaDue && t.slaDue < Date.now() && !t.firstResponseAt ? 'BREACHED' : 'ok', t.satisfaction?.score || '']) };
  if (type === 'billing') return { cols: ['Invoice', 'Issued', 'Due', 'Status', 'Subtotal', 'Tax', 'Total', 'Paid'], rows: inv.filter(f).map((i) => [i.number, fmtTime(i.issuedAt), fmtTime(i.dueAt), i.status, i.subtotal, i.tax, i.total, fmtTime(i.paidAt)]) };
  return build(type, tenantId);
}

export const reportStats = (rows) => ({ generated: rows.length, lastAt: rows.sort((a, b) => b.at - a.at)[0]?.at || null, types: new Set(rows.map((r) => r.type)).size });
