import { all, get, put, putMany } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, seatLabel, assertScope, requireReason } from '../../core/services/common';
import { verifyPolicy } from '../policies/service';

export function parseCsv(text) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}
export const CSV_TEMPLATE = 'rollNo,name,email\nNQT26100001,Aarav Sharma,aarav.sharma@example.edu\nNQT26100002,Diya Nair,diya.nair@example.edu';
export const validate = ({ rollNo, name, email }) => {
  const e = [];
  if (!/^[A-Z0-9]{6,14}$/.test(rollNo)) e.push('roll number must be 6–14 letters/digits');
  if (!/^[\p{L} .'-]{2,80}$/u.test(name)) e.push('name must be 2–80 letters');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 120) e.push('email is invalid');
  return e;
};
export async function previewImport(tenantId, text) {
  if (text.length > 1_000_000) fail('File is larger than 1 MB.');
  const rows = parseCsv(text); if (rows.length < 2) fail('The CSV needs a header and at least one row.');
  const head = rows[0].map((h) => h.trim().toLowerCase()); const ix = (k) => head.indexOf(k);
  if (['rollno', 'name', 'email'].some((k) => ix(k) < 0)) fail('Header must contain rollNo, name, email.');
  if (rows.length > 5001) fail('Import up to 5,000 rows at a time.');
  const have = new Set((await all('candidates')).filter((c) => c.tenantId === tenantId).map((c) => c.rollNo));
  const emails = new Set((await all('candidates')).filter((c) => c.tenantId === tenantId).map((c) => c.email));
  const valid = [], invalid = [], seen = new Set();
  rows.slice(1).forEach((r, i) => {
    const c = { rollNo: clean(r[ix('rollno')], 20).toUpperCase(), name: clean(r[ix('name')], 80), email: clean(r[ix('email')], 120).toLowerCase() };
    const errs = validate(c);
    if (have.has(c.rollNo) || seen.has(c.rollNo)) errs.push('duplicate roll number');
    if (c.email && emails.has(c.email)) errs.push('duplicate email');
    seen.add(c.rollNo);
    errs.length ? invalid.push({ line: i + 2, ...c, errs }) : valid.push(c);
  });
  return { valid, invalid, total: rows.length - 1 };
}
export async function commitImport(a, tenantId, valid) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  const have = new Set((await all('candidates')).filter((c) => c.tenantId === tenantId).map((c) => c.rollNo));
  const fresh = valid.filter((c) => !have.has(c.rollNo));
  await putMany('candidates', fresh.map((c) => ({ id: id('cnd'), tenantId, ...c, examId: null, centerId: null, seat: null, identity: 'pending', status: 'registered', exceptions: [], corrections: [], createdAt: Date.now() })));
  await log(a, 'CANDIDATES_IMPORTED', `${fresh.length} of ${valid.length}`);
  return `${fresh.length} candidate(s) imported.`;
}
export async function addCandidate(a, { tenantId, rollNo, name, email }) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  const c = { rollNo: clean(rollNo, 20).toUpperCase(), name: clean(name, 80), email: clean(email, 120).toLowerCase() };
  const errs = validate(c); if (errs.length) fail('Fix: ' + errs.join('; ') + '.');
  if ((await all('candidates')).some((x) => x.tenantId === tenantId && x.rollNo === c.rollNo)) fail('That roll number already exists.');
  if ((await all('candidates')).some((x) => x.tenantId === tenantId && x.email === c.email)) fail('That email is already registered.');
  await put('candidates', { id: id('cnd'), tenantId, ...c, examId: null, centerId: null, seat: null, identity: 'pending', status: 'registered', exceptions: [], corrections: [], createdAt: Date.now() });
  await log(a, 'CANDIDATE_ADDED', c.rollNo); return `${c.rollNo} added.`;
}
export async function assignToExam(a, { tenantId, examId, centerId, count }) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  const ex = await get('exams', examId), ce = await get('centers', centerId);
  if (!ex || ex.tenantId !== tenantId) fail('Pick an exam.');
  if (!['draft', 'review', 'approved', 'published'].includes(ex.status)) fail(`Exam is ${ex.status}; assignments are locked.`);
  if (!ce || !ex.centerIds.includes(centerId)) fail('That center is not part of this exam.');
  if (ce.status !== 'active') fail('Center is inactive.');
  const cands = (await all('candidates')).filter((c) => c.tenantId === tenantId);
  const used = new Set(cands.filter((c) => c.examId === examId && c.centerId === centerId).map((c) => c.seat));
  const free = []; for (let i = 0; i < ce.capacity; i++) { const s = seatLabel(i); if (!used.has(s)) free.push(s); }
  const pool = cands.filter((c) => !c.examId); const n = Math.min(Number(count) || pool.length, pool.length);
  if (n < 1) fail('There are no unassigned candidates.');
  if (n > free.length) fail(`Only ${free.length} free seat(s) at ${ce.code}.`);
  await putMany('candidates', pool.slice(0, n).map((c, i) => ({ ...c, examId, centerId, seat: free[i], status: 'assigned', assignedAt: Date.now() })));
  await log(a, 'CANDIDATES_ASSIGNED', `${n} -> ${ex.code} @ ${ce.code}`); return `${n} candidate(s) seated at ${ce.code}.`;
}

export async function assignCandidates(a, { tenantId, examId, centerId, candidateIds }) {
  need(a, 'candidate.manage'); assertScope(a, tenantId);
  const ex = await get('exams', examId), ce = await get('centers', centerId);
  if (!ex || ex.tenantId !== tenantId) fail('Pick an exam.');
  if (!['draft', 'review', 'approved', 'published'].includes(ex.status)) fail(`Exam is ${ex.status}; assignments are locked.`);
  if (!ce || !ex.centerIds.includes(centerId)) fail('That center is not part of this exam.');
  if (!Array.isArray(candidateIds) || !candidateIds.length) fail('Select at least one candidate.');
  const cands = (await all('candidates')).filter((c) => c.tenantId === tenantId);
  const used = new Set(cands.filter((c) => c.examId === examId && c.centerId === centerId).map((c) => c.seat));
  const free = []; for (let i = 0; i < ce.capacity; i++) { const s = seatLabel(i); if (!used.has(s)) free.push(s); }
  const pool = cands.filter((c) => candidateIds.includes(c.id));
  if (pool.length > free.length) fail(`Only ${free.length} free seat(s) at ${ce.code}.`);
  await putMany('candidates', pool.map((c, i) => ({ ...c, examId, centerId, seat: free[i], status: 'assigned', assignedAt: Date.now() })));
  await log(a, 'CANDIDATES_ASSIGNED', `${pool.length} -> ${ex.code} @ ${ce.code}`);
  return `${pool.length} candidate(s) assigned to ${ce.code}.`;
}

export async function unassign(a, c, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const r = requireReason(reason, 8);
  if ((await all('sessions')).some((s) => s.candidateId === c.id && s.status === 'in_progress')) fail('The candidate has a session in progress.');
  await put('candidates', { ...c, examId: null, centerId: null, seat: null, status: 'registered' });
  await log(a, 'CANDIDATE_UNASSIGNED', `${c.rollNo}: ${r}`);
  return `${c.rollNo} removed from the exam.`;
}
export async function setIdentity(a, c, outcome, reason) {
  need(a, 'candidate.verify'); assertScope(a, c.tenantId);
  if (!c.examId) fail('Assign the candidate to an exam first.');
  if (!['verified', 'rejected', 'exempt'].includes(outcome)) fail('Unknown identity outcome.');
  const r = requireReason(reason || (outcome === 'verified' ? 'Photo ID matched' : ''), 5);
  await put('candidates', { ...c, identity: outcome, identityBy: a.id, identityAt: Date.now(), identityNote: r });
  await log(a, 'IDENTITY_' + outcome.toUpperCase(), `${c.rollNo}: ${r}`);
  return `${c.rollNo} identity marked ${outcome}.`;
}
export async function correctName(a, c, newName, reason) {
  need(a, 'candidate.manage'); assertScope(a, c.tenantId);
  const nm = clean(newName, 80);
  if (!/^[\p{L} .'-]{2,80}$/u.test(nm)) fail('Name must be 2–80 letters.');
  const r = requireReason(reason, 8);
  await put('candidates', { ...c, name: nm, corrections: [...(c.corrections || []), { at: Date.now(), by: a.id, from: c.name, to: nm, reason: r }] });
  await log(a, 'CANDIDATE_NAME_CORRECTED', `${c.rollNo}: ${r}`);
  return 'Name corrected and the change was recorded.';
}

export function readinessFor(c, ctx = {}) {
  const { devices = [], exams = [], policies = [], releases = [] } = ctx;
  const ex = exams.find((e) => e.id === c.examId);
  const dev = devices.find((d) => d.centerId === c.centerId && d.seat === c.seat);
  const pol = policies.find((p) => p.id === ex?.policyId);
  const rel = releases.find((r) => r.id === dev?.releaseId);
  const out = [];
  out.push({ key: 'assignment', label: 'Exam assignment', status: c.examId ? 'PASS' : 'FAIL', detail: ex ? `${ex.code} · seat ${c.seat}` : 'Not assigned' });
  out.push({ key: 'identity', label: 'Identity check', status: c.identity === 'verified' ? 'PASS' : c.identity === 'rejected' ? 'FAIL' : 'NOT_RUN', detail: c.identity });
  out.push({ key: 'device', label: 'Seat device', status: dev ? 'PASS' : 'FAIL', detail: dev ? dev.hostname : 'No device enrolled at this seat' });
  out.push({ key: 'trust', label: 'Device trust', status: dev?.trust === 'attested' ? 'PASS' : dev?.status === 'enrolled' ? 'NOT_RUN' : 'FAIL', detail: dev?.trust || 'unknown' });
  out.push({ key: 'policy', label: 'Policy deployment', status: pol && pol.status === 'published' && dev?.policyId === pol.id ? 'PASS' : pol && dev?.policyId ? 'WARN' : 'FAIL', detail: pol ? `v${pol.version}` : 'No policy' });
  out.push({ key: 'release', label: 'Approved release', status: rel && !['revoked', 'candidate'].includes(rel.status) ? 'PASS' : 'FAIL', detail: rel?.version || 'unknown' });
  return out;
}
export const isReady = (checks) => checks.every((c) => c.status === 'PASS' || c.status === 'WARN');

export async function notifyCandidate(a, c, title, body) {
  const n = await import('../notifications/service');
  return n.broadcast({ tenantId: c.tenantId, userId: null, title, body, link: c.examId ? `/college/exams/${c.examId}/candidates` : '/college/candidates', role: 'student' });
}
export const candidateName = (cands, id) => cands.find((c) => c.id === id)?.name || '—';
export const candidateRoll = (cands, id) => cands.find((c) => c.id === id)?.rollNo || '—';
