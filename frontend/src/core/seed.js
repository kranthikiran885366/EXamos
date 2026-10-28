import { all, get, put, putMany } from './db/db';
import { DEMO } from './data/demoAccounts';
import { makeUser, createRole } from '../modules/users/service';
import { ensureKey, mulberry32 } from './services/common';
import {
  createInstitution, createCampus, createDepartment, assignStaff, assignCampusAdmin,
} from '../modules/institutions/service';
import { createCenter } from '../modules/centers/service';
import { createRelease, approveRelease, rollout, addReleaseEvidence } from '../modules/releases/service';
import { createRule } from '../modules/firewall/service';
import { createPolicy, publishPolicy } from '../modules/policies/service';
import { createProfile, promote } from '../modules/kiosk/service';
import { enrollDevices } from '../modules/fleet/service';
import { attest, setTamper } from '../modules/tpm/service';
import { createExam, transition } from '../modules/exams/service';
import { assignToExam, setIdentity } from '../modules/candidates/service';
import { startSession, saveAnswer, submitSession } from '../modules/submissions/service';
import { createUsb, prepareUsb, assignUsb, issueUsb, returnUsb, reportUsb } from '../modules/usb/service';
import { createRequest, addMessage, assignRequest, setStatus } from '../modules/support/service';
import { ensurePlans, startSubscription, createInvoice, markInvoice } from '../modules/billing/service';
import { broadcast, sendNotification } from '../modules/notifications/service';
import { createPrivacyRequest, verifySubject, saveRetention, runRetention } from '../modules/privacy/service';
import { logSecurityEvent, createVulnerability, updateVulnerability, addEvidence, syncVulnerabilities } from '../modules/security/service';
import { saveConfig, saveIntegration, testIntegration, toggleFeature } from '../modules/settings/service';

const FIRST = ['Aarav', 'Diya', 'Vihaan', 'Ananya', 'Aditya', 'Isha', 'Arjun', 'Kavya', 'Rohan', 'Meera', 'Karthik', 'Priya', 'Sai', 'Neha', 'Rahul', 'Sneha', 'Varun', 'Pooja', 'Manish', 'Lakshmi'];
const LAST = ['Sharma', 'Reddy', 'Iyer', 'Nair', 'Gupta', 'Patel', 'Rao', 'Singh', 'Das', 'Menon', 'Kulkarni', 'Verma', 'Naidu', 'Joshi', 'Bose', 'Pillai', 'Chopra', 'Shetty', 'Mishra', 'Kapoor'];
const CITIES = [
  { city: 'Bengaluru', code: 'BLR-87', campus: 'BLR' },
  { city: 'Mumbai', code: 'MUM-94', campus: 'MUM' },
  { city: 'Hyderabad', code: 'HYD-101', campus: 'HYD' },
  { city: 'Chennai', code: 'CHE-108', campus: 'CHE' },
  { city: 'Delhi', code: 'DEL-115', campus: 'DEL' },
];
const SBOM = (v, o) => `kiosk-agent@${v}\nopenssl@${o}\nlibwebp@1.3.2\ncurl@8.4.0\nzlib@1.2.13\nchromium@126.0.0`;
const chunk = (a, n) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, i * n + n));
const at = (ms) => new Date(Date.now() + ms).toISOString();

export async function seed() {
  if (await get('meta', 'seeded')) return;
  const rnd = mulberry32(20260225);
  const seedStarted = Date.now();

  // 1. Signing keys and vulnerability advisories used by the SBOM scanner.
  for (const k of ['policy-signer', 'release-signer', 'receipt-signer']) await ensureKey(k);
  await put('meta', {
    id: 'advisories',
    list: [
      { name: 'openssl', below: '3.0.14', cve: 'CVE-2024-5535', sev: 'critical' },
      { name: 'libwebp', below: '1.3.2', cve: 'CVE-2023-4863', sev: 'critical' },
      { name: 'curl', below: '8.4.0', cve: 'CVE-2023-38545', sev: 'high' },
      { name: 'zlib', below: '1.2.12', cve: 'CVE-2018-25032', sev: 'high' },
    ],
  });

  // 2. Bootstrap actors. Users are persisted later, once the institutions and candidate records exist.
  const root = { id: 'root', role: 'superadmin' };
  const ops = { id: 'ananya', role: 'ops_admin' };
  const relEng = { id: 'release', role: 'release_engineer' };
  const auditor = { id: 'auditor', role: 'auditor' };
  const inst = { id: 'instadmin', role: 'inst_admin', tenantId: null };
  const ctrl = { id: 'controller', role: 'exam_controller', tenantId: null };
  const invig = { id: 'invig', role: 'invigilator', tenantId: null };
  const it = { id: 'itadmin', role: 'it_admin', tenantId: null };
  const sec = { id: 'security', role: 'security_engineer', tenantId: null };
  const support = { id: 'support', role: 'support', tenantId: null };
  const finance = { id: 'finance', role: 'finance', tenantId: null };
  const student = { id: 'student', role: 'student', tenantId: null };

  // 3. Production Institution: National Examination Board
  let T1 = await get('tenants', 'inst-default');
  if (!T1) {
    T1 = {
      id: 'inst-default',
      name: 'National Examination Board',
      code: 'NAT-EXAM',
      domains: ['exam.gov.in', 'examos.org'],
      contactEmail: 'controller@exam.gov.in',
      contactPhone: '+91 11 2300 0001',
      region: 'India · New Delhi',
      timezone: 'Asia/Kolkata',
      plan: 'enterprise',
      status: 'active',
      maxCenters: 50,
      maxCandidates: 50000,
      deploymentModel: 'usb-boot',
      branding: { displayName: 'National Examination Board', accent: '#2f5bea' },
      notificationPrefs: { email: true, inApp: true },
      examDefaults: { durationMin: 120, lateEntryMin: 15, attestationLevel: 'tpm-secureboot' },
      security: { requireTpm: true, requireSecureBoot: true, allowUsbStorage: false },
      createdAt: 1700000000000,
      createdBy: 'root',
    };
    await put('tenants', T1);
    await put('institutions', T1).catch(() => {});
  }
  const T2 = T1;
  inst.tenantId = T1.id; ctrl.tenantId = T1.id; invig.tenantId = T1.id; it.tenantId = T1.id;
  sec.tenantId = T1.id; support.tenantId = T1.id; finance.tenantId = T1.id; student.tenantId = T1.id;
  const demoInst = { id: 'demoinst', role: 'inst_admin', tenantId: T1.id };
  const demoStudent = { id: 'demostudent', role: 'student', tenantId: T1.id };

  // 4. Candidate records. The first T1 candidate is linked to the demo student account.
  const mkCandidate = (tenantId, i, prefix) => {
    const f = FIRST[i % FIRST.length], l = LAST[(i * 3) % LAST.length];
    const name = i === 0 && prefix === 'NQT' ? 'Aarav Sharma' : `${f} ${l}`;
    const email = i === 0 && prefix === 'NQT' ? 'aarav.sharma@mail.examos.example' : `${f}.${l}${i}@mail.examos.example`.toLowerCase();
    return {
      id: `cnd_${prefix.toLowerCase()}_${String(i).padStart(4, '0')}`, tenantId,
      rollNo: `${prefix}26${String(100000 + i)}`, name, email,
      examId: null, centerId: null, seat: null, identity: 'pending', status: 'registered',
      exceptions: [], corrections: [], createdAt: Date.now(),
    };
  };
  const t1Cands = Array.from({ length: 110 }, (_, i) => mkCandidate(T1.id, i, 'NQT'));
  const t2Cands = Array.from({ length: 12 }, (_, i) => mkCandidate(T2.id, i, 'DMO'));
  await putMany('candidates', [...t1Cands, ...t2Cands]);

  // 5. Users for every blueprint role.
  const tenantMap = { T1: T1.id, T2: T2.id };
  const users = {};
  for (const d of DEMO) {
    const candidateId = d.role === 'student'
      ? (d.username === 'student' ? t1Cands[0].id : t2Cands[0].id)
      : null;
    const u = await makeUser({
      username: d.username, name: d.name, role: d.role, password: d.password,
      tenantId: d.tenant ? tenantMap[d.tenant] : null, email: d.email, candidateId,
    });
    await put('users', u);
    users[d.username] = u;
  }
  // The student actor now has a candidate link.
  student.candidateId = t1Cands[0].id;
  demoStudent.candidateId = t2Cands[0].id;

  // 6. Campuses, departments and staff assignments.
  const campusSpecs = [
    ['Bengaluru Campus', 'BLR', 'Bengaluru', 'Outer Ring Road, Bengaluru 560103', 900],
    ['Mumbai Campus', 'MUM', 'Mumbai', 'Powai, Mumbai 400076', 700],
    ['Hyderabad Campus', 'HYD', 'Hyderabad', 'HITEC City, Hyderabad 500081', 650],
    ['Chennai Campus', 'CHE', 'Chennai', 'Guindy, Chennai 600032', 600],
    ['Delhi Campus', 'DEL', 'Delhi', 'Dwarka, New Delhi 110075', 750],
  ];
  const existingCampuses = await all('campuses');
  for (const [name, code, city, address, capacity] of campusSpecs) {
    if (!existingCampuses.some((x) => x.tenantId === T1.id && x.code === code)) {
      try {
        await createCampus(inst, { tenantId: T1.id, name, code, city, address, capacity });
      } catch (_) {}
    }
  }
  if (!existingCampuses.some((x) => x.tenantId === T2.id && x.code === 'DMC')) {
    try {
      await createCampus(demoInst, { tenantId: T2.id, name: 'Demo Mumbai Campus', code: 'DMC', city: 'Mumbai', address: 'Andheri East, Mumbai 400069', capacity: 180 });
    } catch (_) {}
  }
  const campuses = (await all('campuses')).filter((c) => c.tenantId === T1.id).sort((a, b) => a.code.localeCompare(b.code));
  const t2Campus = (await all('campuses')).find((c) => c.tenantId === T2.id) || campuses[0];

  const existingDepts = await all('departments');
  for (const [name, code, type] of [
    ['Examination Control', 'EXAM', 'examination'],
    ['Computer Science', 'CSE', 'academic'],
    ['Laboratory Operations', 'LAB', 'laboratory'],
    ['Administration', 'ADMIN', 'administrative'],
  ]) {
    if (!existingDepts.some((x) => x.tenantId === T1.id && x.code === code)) {
      try {
        await createDepartment(inst, { tenantId: T1.id, name, code, campusId: campuses[0]?.id, type });
      } catch (_) {}
    }
  }
  if (!existingDepts.some((x) => x.tenantId === T2.id && x.code === 'DEXAM')) {
    try {
      await createDepartment(demoInst, { tenantId: T2.id, name: 'Examination Unit', code: 'DEXAM', campusId: t2Campus?.id, type: 'examination' });
    } catch (_) {}
  }
  const depts = (await all('departments')).filter((d) => d.tenantId === T1.id);
  const dept = (code) => depts.find((d) => d.code === code) || depts[0];

  if (campuses[0] && dept('ADMIN')) {
    try {
      await assignStaff(inst, { tenantId: T1.id, userId: 'instadmin', campusId: campuses[0].id, departmentId: dept('ADMIN')?.id, roleTitle: 'Institution Administrator' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'controller', campusId: campuses[0].id, departmentId: dept('EXAM')?.id, roleTitle: 'Examination Controller' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'invig', campusId: campuses[0].id, departmentId: dept('EXAM')?.id, roleTitle: 'Chief Invigilator' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'itadmin', campusId: campuses[2]?.id || campuses[0].id, departmentId: dept('LAB')?.id, roleTitle: 'Device Operations Lead' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'security', campusId: campuses[0].id, departmentId: dept('ADMIN')?.id, roleTitle: 'Security Engineer' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'support', campusId: campuses[1]?.id || campuses[0].id, departmentId: dept('ADMIN')?.id, roleTitle: 'Support Engineer' });
      await assignStaff(inst, { tenantId: T1.id, userId: 'finance', campusId: campuses[0].id, departmentId: dept('ADMIN')?.id, roleTitle: 'Finance Officer' });
      await assignCampusAdmin(inst, campuses[0], 'instadmin');
      if (campuses[2]) await assignCampusAdmin(inst, campuses[2], 'itadmin');
    } catch (_) {}
  }

  // 7. Exam centres.
  const existingCenters = await all('centers');
  for (const c of CITIES) {
    const campus = campuses.find((x) => x.code === c.campus) || campuses[0];
    if (campus && !existingCenters.some((x) => x.tenantId === T1.id && x.code === c.code)) {
      try {
        await createCenter(inst, {
          tenantId: T1.id, campusId: campus.id, code: c.code,
          name: `${c.city} Assessment Centre`, city: c.city, labs: 2, seatsPerLab: 16,
        });
      } catch (_) {}
    }
  }
  if (!existingCenters.some((x) => x.tenantId === T2.id && x.code === 'PUN-87')) {
    try {
      await createCenter(demoInst, {
        tenantId: T2.id, campusId: t2Campus?.id, code: 'PUN-87',
        name: 'Demo Pune Assessment Centre', city: 'Pune', labs: 1, seatsPerLab: 16,
      });
    } catch (_) {}
  }
  const centersT1 = (await all('centers')).filter((c) => c.tenantId === T1.id).sort((a, b) => a.code.localeCompare(b.code));
  const centerT2 = (await all('centers')).find((c) => c.tenantId === T2.id);

  // 8. Releases. 2.18.4 becomes the stable baseline for all enrolled devices.
  const mkRelease = async (version, openssl) => {
    await createRelease(relEng, { version, components: SBOM(version, openssl) });
    return (await all('releases')).find((r) => r.version === version);
  };
  const r2182 = await mkRelease('2.18.2', '3.0.14');
  await approveRelease(root, r2182);
  await rollout(relEng, await get('releases', r2182.id), 100);
  const r2184 = await mkRelease('2.18.4', '3.0.15');
  await approveRelease(root, r2184);
  await rollout(relEng, await get('releases', r2184.id), 100);
  await mkRelease('2.19.0-rc1', '3.0.8');
  const stable = (await all('releases')).find((r) => r.version === '2.18.4');

  // 9. Egress firewall + signed exam policies.
  for (const T of [T1, T2]) {
    await createRule(it, { tenantId: T.id, name: 'exam-origin', host: 'exam.examos.in', port: '443', action: 'allow', priority: 10 });
    await createRule(it, { tenantId: T.id, name: 'fleet-telemetry', host: 'fleet.examos.in', port: '443', action: 'allow', priority: 20 });
    await createRule(it, { tenantId: T.id, name: 'release-updates', host: 'updates.examos.in', port: '443', action: 'allow', priority: 30 });
    await createRule(it, { tenantId: T.id, name: 'default-deny', host: '*', port: '*', action: 'deny', priority: 9999 });
  }
  const mkPolicy = async (tenantId, name, violation) => {
    const draft = await createPolicy(ops, {
      tenantId, name, requireTpm: true, kioskLockdown: true, allowUsb: false,
      onViolation: violation, origins: ['https://exam.examos.in'],
    });
    return publishPolicy(ops, draft.id);
  };
  const pol1 = await mkPolicy(T1.id, 'nqt-secure-kiosk', 'Warn candidate & log');
  await mkPolicy(T2.id, 'demo-secure-kiosk', 'Isolate device & notify supervisor');

  // 10. Kiosk profiles.
  await createProfile(ops, { tenantId: T1.id, name: 'nqt-secure-kiosk', releaseId: stable.id, lockdown: 'full', blockClipboard: true, blockCapture: true });
  await createProfile(ops, { tenantId: T2.id, name: 'demo-secure-kiosk', releaseId: stable.id, lockdown: 'standard', blockClipboard: true, blockCapture: true });
  const kiosk1 = (await all('kiosks')).find((k) => k.tenantId === T1.id);
  if (kiosk1) await promote(ops, kiosk1);

  // 11. Devices: 20 per national centre, 8 at the demo centre.
  for (const c of centersT1) await enrollDevices(it, { tenantId: T1.id, centerId: c.id, count: 20 });
  await enrollDevices(demoInst, { tenantId: T2.id, centerId: centerT2.id, count: 8 });

  // 12. Exams.
  const baseExam = {
    tenantId: T1.id, type: 'final', policyId: pol1.id, durationMin: 90, timeZone: 'Asia/Kolkata',
    instructions: 'Carry your photo ID. The kiosk will verify the device before the paper starts. Answers save automatically; submit before the timer ends.',
    description: 'National Qualifier · cognitive ability paper delivered on secure kiosks.',
    authMode: 'candidate-login', attestationLevel: 'tpm', requiredChecks: ['uefi', 'usb', 'tpm', 'network', 'display', 'keyboard'],
  };
  await createExam(ctrl, {
    ...baseExam, code: 'NQT-COG-01', title: 'NQT · Cognitive Ability',
    centerIds: centersT1.map((c) => c.id), startAt: Date.now() - 10 * 60000, durationMin: 90, generate: 25,
  });
  const ex1 = (await all('exams')).find((e) => e.code === 'NQT-COG-01');
  await transition(ctrl, ex1, 'review');
  await transition(root, await get('exams', ex1.id), 'approved');
  for (const c of centersT1) await assignToExam(ctrl, { tenantId: T1.id, examId: ex1.id, centerId: c.id, count: 18 });
  await transition(ctrl, await get('exams', ex1.id), 'published');

  await createExam(ctrl, {
    ...baseExam, code: 'NQT-CODE-01', title: 'NQT · Coding Aptitude', type: 'laboratory',
    centerIds: centersT1.slice(0, 2).map((c) => c.id), startAt: Date.now() + 26 * 3600e3,
    durationMin: 120, generate: 15,
    description: 'Programming aptitude paper with a two-hour window.',
  });
  const ex2 = (await all('exams')).find((e) => e.code === 'NQT-CODE-01');
  await transition(ctrl, ex2, 'review');
  await transition(root, await get('exams', ex2.id), 'approved');
  await assignToExam(ctrl, { tenantId: T1.id, examId: ex2.id, centerId: centersT1[0].id, count: 10 });
  await transition(ctrl, await get('exams', ex2.id), 'published');

  await createExam(ctrl, {
    ...baseExam, code: 'NQT-DATA-01', title: 'NQT · Data Interpretation', type: 'practice',
    centerIds: [centersT1[1].id], startAt: Date.now() + 3 * 864e5, durationMin: 60, generate: 20,
    description: 'Practice paper used for centre readiness drills.',
  });
  await createExam(demoInst, {
    tenantId: T2.id, code: 'DMO-ENTRY-01', title: 'Demo Institute · Entry Assessment', type: 'internal',
    centerIds: [centerT2.id], startAt: Date.now() + 2 * 864e5, durationMin: 60, generate: 12,
    policyId: (await all('policies')).find((p) => p.tenantId === T2.id && p.status === 'published').id,
    instructions: 'Demo assessment used to explore the candidate journey.',
  });

  // 13. Identity verification for the live national paper.
  for (const c of (await all('candidates')).filter((x) => x.examId === ex1.id)) {
    await setIdentity(invig, c, 'verified', 'Photo ID matched at entry');
  }

  // 14. Bring the national paper live.
  await transition(invig, await get('exams', ex1.id), 'live', 'Window open for the national qualifier');

  // 15. Attest all devices, then simulate one firmware change so the security modules have a finding.
  const t1Devices = (await all('devices')).filter((d) => d.tenantId === T1.id);
  for (const part of chunk(t1Devices, 12)) await Promise.all(part.map((d) => attest(it, d.id)));
  const t2Devices = (await all('devices')).filter((d) => d.tenantId === T2.id);
  for (const part of chunk(t2Devices, 8)) await Promise.all(part.map((d) => attest(root, d.id)));
  const bad = t1Devices.find((d) => d.centerId === centersT1[1].id && d.seat === 'A03');
  if (bad) { await setTamper(it, bad); await attest(it, bad.id); }
  // Heartbeats must be fresh before opening candidate sessions.
  await putMany('devices', (await all('devices')).map((d) => ({ ...d, lastSeen: Date.now() })));

  // 16. Live sessions and submissions. The demo student is deliberately left unstarted.
  const verified = (await all('candidates')).filter((c) => c.examId === ex1.id && c.identity === 'verified');
  let started = 0; let submitted = 0;
  for (const c of verified) {
    if (c.id === t1Cands[0].id) continue;
    if (rnd() > 0.42) continue;
    try {
      const s = await startSession(invig, c.id);
      started++;
      const answers = 8 + Math.floor(rnd() * 8);
      for (let q = 0; q < answers; q++) await saveAnswer(s.id, q, Math.floor(rnd() * 4));
      if (rnd() < 0.32) { await submitSession(invig, s.id); submitted++; }
    } catch { /* a seat without a trusted device stays idle */ }
  }

  // 17. USB inventory and custody.
  const usbRows = [];
  for (let i = 1; i <= 6; i++) {
    usbRows.push(await createUsb(it, {
      tenantId: T1.id, assetId: `USB-NQT-${String(i).padStart(3, '0')}`,
      serial: `SNUSB2026${String(i).padStart(4, '0')}`, model: ['SanDisk Extreme 64GB', 'Samsung BAR Plus 64GB', 'Kingston DataTraveler 128GB'][i % 3],
      capacityGb: 64, notes: i === 6 ? 'Reserved for centre readiness drills.' : '',
    }));
  }
  for (const u of usbRows.slice(0, 4)) {
    await prepareUsb(it, u, {
      releaseId: stable.id, station: 'Bengaluru imaging station 1',
      writtenHash: stable.digest, confirmation: u.assetId, target: 'removable-usb',
    });
  }
  let usb = (await all('usbs')).filter((u) => u.tenantId === T1.id).sort((a, b) => a.assetId.localeCompare(b.assetId));
  await assignUsb(it, usb[0], { centerId: centersT1[0].id, campusId: campuses[0].id });
  await assignUsb(it, usb[1], { centerId: centersT1[1].id, campusId: campuses[1].id });
  await issueUsb(it, usb[0], { holderName: 'Rahul Sen', holderId: 'invig', reason: 'Morning shift delivery' });
  await issueUsb(it, usb[1], { holderName: 'Sneha Kulkarni', holderId: 'itadmin', reason: 'Centre imaging and recovery' });
  usb = (await all('usbs')).filter((u) => u.tenantId === T1.id).sort((a, b) => a.assetId.localeCompare(b.assetId));
  await returnUsb(it, usb[1], { condition: 'good', reason: 'Returned after the centre readiness drill' });
  usb = (await all('usbs')).filter((u) => u.tenantId === T1.id).sort((a, b) => a.assetId.localeCompare(b.assetId));
  await reportUsb(it, usb[3], { kind: 'lost', reason: 'Not returned after the previous shift; custody is under review.' });

  // 18. Support requests across the lifecycle.
  const s1 = await createRequest(support, {
    tenantId: T1.id, subject: 'Kiosk fails attestation at MUM-94', priority: 'high', category: 'device',
    description: 'Seat A03 reports a PCR 7 mismatch after a firmware update. Candidates cannot start on that kiosk.',
    linkedDeviceId: bad?.id,
  });
  await assignRequest(support, s1, 'support', 'Triage to the device operations queue.');
  await addMessage(support, s1, 'The station was re-imaged and re-attested. Please retry the seat check.', false);
  await setStatus(support, s1, 'resolved', 'Re-imaged the USB and re-attested the kiosk successfully.');
  await createRequest(student, {
    tenantId: T1.id, subject: 'Need help finding my exam briefing', priority: 'normal', category: 'exam',
    description: 'I can see the exam in my assignments but want to confirm the reporting time and seat.',
    requesterName: 'Aarav Sharma', requesterEmail: 'aarav.sharma@mail.examos.example',
  });
  await createRequest(inst, {
    tenantId: T1.id, subject: 'Clarify USB custody policy for evening shift', priority: 'low', category: 'policy',
    description: 'Please confirm whether USB assets can be held overnight by the centre invigilator.',
  });
  const s4 = await createRequest(it, {
    tenantId: T1.id, subject: 'USB-NQT-004 missing after shift handover', priority: 'critical', category: 'device',
    description: 'The asset was not returned at handover. Custody log shows the last issue to the morning shift.',
  });
  await assignRequest(support, s4, 'security', 'Security to lead the custody investigation.');

  // 19. Billing.
  await ensurePlans();
  await startSubscription(finance, { tenantId: T1.id, planId: 'plan_enterprise', seats: 90, autoRenew: true });
  await startSubscription(root, { tenantId: T2.id, planId: 'plan_pilot', seats: 12, autoRenew: false });
  const inv1 = await createInvoice(finance, { tenantId: T1.id, planId: 'plan_enterprise', seats: 90, taxPct: 18, dueDays: 15, notes: 'Annual platform subscription' });
  await markInvoice(finance, inv1, 'paid', 'Payment received via NEFT');
  await createInvoice(finance, { tenantId: T1.id, planId: 'plan_enterprise', seats: 90, taxPct: 18, dueDays: 20, notes: 'Additional centre licences' });

  // 20. Notifications.
  await sendNotification(inst, {
    tenantId: T1.id, audience: 'all', title: 'NQT window is open', tone: 'info', channel: 'both', link: '/student/home',
    body: 'The national qualifier is live. Candidates should complete the device check and open the briefing.',
  });
  await sendNotification(inst, {
    tenantId: T1.id, audience: 'role', role: 'invigilator', title: 'Live monitoring checklist', tone: 'warn', channel: 'in-app', link: '/operator/overview',
    body: 'Check candidate check-in, device trust and the submission feed before the first slot ends.',
  });
  await broadcast({ tenantId: T1.id, title: 'Security policy updated', body: 'A new signed policy version is in force for all national centres.', tone: 'warn', link: '/security/policies', kind: 'policy' });
  await broadcast({ tenantId: T1.id, userId: 'student', title: 'Your exam is ready', body: 'Complete the device check, then open the briefing to start.', tone: 'success', link: '/student/exams', kind: 'exam' });
  await sendNotification(inst, {
    tenantId: T1.id, audience: 'students', title: 'Device check reminder', tone: 'info', channel: 'email', link: '/student/home',
    body: 'Run the device check at least 30 minutes before your exam window.',
    scheduledAt: at(864e5),
  });

  // 21. Privacy and retention.
  const pr1 = await createPrivacyRequest(inst, {
    tenantId: T1.id, type: 'access', subjectType: 'candidate', subjectId: t1Cands[5].id,
    subjectName: t1Cands[5].name, details: 'Candidate requested a copy of their exam assignment, answers and receipt.',
  });
  await verifySubject(inst, pr1, 'Photo ID verified at the support desk.');
  await createPrivacyRequest(inst, {
    tenantId: T1.id, type: 'erasure', subjectType: 'candidate', subjectId: t1Cands[6].id,
    subjectName: t1Cands[6].name, details: 'Candidate requested erasure of records from a cancelled practice attempt.',
  });
  await saveRetention(inst, {
    tenantId: T1.id, dataType: 'candidates', retentionDays: 730, action: 'anonymize',
    legalBasis: 'Institutional retention schedule approved by the examination board.',
  });
  const retention = (await all('retention')).find((r) => r.tenantId === T1.id);
  if (retention) await runRetention(inst, retention, true);

  // 22. Security events, vulnerabilities and evidence.
  await logSecurityEvent(sec, {
    tenantId: T1.id, type: 'attestation-failure', severity: 'high', title: 'TPM attestation failed at MUM-94/A03',
    detail: 'PCR 7 differed from the golden policy after a firmware update.', deviceId: bad?.id, source: 'tpm-verifier',
  });
  await logSecurityEvent(sec, {
    tenantId: T1.id, type: 'policy-violation', severity: 'medium', title: 'Clipboard blocked during a live exam',
    detail: 'The kiosk blocked three clipboard attempts and recorded the candidate seat.', source: 'kiosk-agent',
  });
  await logSecurityEvent(sec, {
    tenantId: T1.id, type: 'usb-incident', severity: 'high', title: 'USB asset reported lost',
    detail: 'USB-NQT-004 was not returned after the morning shift; custody review opened.', source: 'usb-inventory',
  });
  const v1 = await createVulnerability(sec, {
    tenantId: T1.id, cve: 'CVE-2024-5535', component: 'openssl@3.0.8', title: 'OpenSSL buffer overread in the exam image',
    severity: 'critical', cvss: 9.1, affected: '2.19.0-rc1', fixedIn: '3.0.14', source: 'sbom-scan', owner: 'security',
  });
  await updateVulnerability(sec, v1, { status: 'triaged' }, 'Assigned to release engineering for the next candidate.');
  const v2 = await createVulnerability(sec, {
    tenantId: T1.id, cve: 'CVE-2023-4863', component: 'libwebp@1.3.2', title: 'libwebp heap overflow in the image decoder',
    severity: 'high', cvss: 8.8, affected: '2.18.2', fixedIn: '1.3.2', source: 'sbom-scan', owner: 'itadmin',
  });
  await updateVulnerability(sec, v2, { status: 'fixed' }, 'Component upgraded and regression-tested.');
  await syncVulnerabilities(sec, T1.id);
  await addEvidence(sec, {
    tenantId: T1.id, title: 'NQT-COG-01 attestation summary', kind: 'attestation-report', classification: 'internal',
    content: 'All national centre devices were attested before the live window. One firmware change was isolated at MUM-94/A03.',
    tags: ['nqt', 'attestation'],
  });
  await addEvidence(sec, {
    tenantId: T1.id, title: 'Release 2.18.4 security review', kind: 'release-validation', classification: 'confidential',
    content: 'SBOM review, signature verification and regression evidence for the stable release.', releaseId: stable.id,
  });
  await addReleaseEvidence(relEng, {
    releaseId: stable.id, title: 'Regression test report', kind: 'test-report', classification: 'internal',
    content: 'Full kiosk boot, attestation and submission regression suite passed on 2.18.4.',
  });

  // 23. Monitoring seed data.
  const now = Date.now();
  await putMany('services', [
    { id: 'svc_api', name: 'Exam API', kind: 'api', status: 'healthy', latencyMs: 42, lastCheckAt: now, updatedBy: 'system' },
    { id: 'svc_auth', name: 'Identity & sessions', kind: 'auth', status: 'healthy', latencyMs: 28, lastCheckAt: now, updatedBy: 'system' },
    { id: 'svc_db', name: 'Primary database', kind: 'database', status: 'healthy', latencyMs: 8, lastCheckAt: now, updatedBy: 'system' },
    { id: 'svc_audit', name: 'Audit chain verifier', kind: 'audit', status: 'healthy', latencyMs: 12, lastCheckAt: now, updatedBy: 'system' },
    { id: 'svc_attest', name: 'Attestation verifier', kind: 'worker', status: 'healthy', latencyMs: 65, lastCheckAt: now, updatedBy: 'system' },
    { id: 'svc_smtp', name: 'Email delivery', kind: 'smtp', status: 'degraded', latencyMs: 820, lastCheckAt: now, statusReason: 'Upstream queue delay', updatedBy: 'system' },
    { id: 'svc_reports', name: 'Report worker', kind: 'worker', status: 'maintenance', latencyMs: 0, lastCheckAt: now, statusReason: 'Scheduled maintenance window', updatedBy: 'system' },
    { id: 'svc_storage', name: 'Evidence storage', kind: 'storage', status: 'healthy', latencyMs: 34, lastCheckAt: now, updatedBy: 'system' },
  ]);
  await putMany('alerts', [
    { id: 'alr_seed1', title: 'Attestation failure rate above threshold', severity: 'high', source: 'tpm-verifier', serviceId: 'svc_attest', status: 'open', at: now - 42 * 60000, detail: 'Two failures in the last hour at MUM-94.', runbook: 'Inspect PCR 7 and re-image the affected kiosk.' },
    { id: 'alr_seed2', title: 'Email delivery latency elevated', severity: 'medium', source: 'smtp-probe', serviceId: 'svc_smtp', status: 'acknowledged', at: now - 3 * 3600e3, ackBy: 'support', ackAt: now - 2 * 3600e3, detail: 'Queue delay above the 5 minute objective.' },
    { id: 'alr_seed3', title: 'Report worker in maintenance', severity: 'low', source: 'scheduler', serviceId: 'svc_reports', status: 'silenced', at: now - 6 * 3600e3, silencedUntil: now + 2 * 3600e3 },
    { id: 'alr_seed4', title: 'Backup verification completed', severity: 'low', source: 'backup', serviceId: 'svc_storage', status: 'resolved', at: now - 26 * 3600e3, resolvedAt: now - 25 * 3600e3, resolution: 'Restore test passed.' },
  ]);
  await putMany('jobs', [
    { id: 'job_backup', name: 'Nightly encrypted backup', schedule: 'daily', status: 'succeeded', lastRun: now - 9 * 3600e3, nextRun: now + 15 * 3600e3, lastDurationMs: 1840 },
    { id: 'job_retention', name: 'Retention dry-run', schedule: 'daily', status: 'succeeded', lastRun: now - 7 * 3600e3, nextRun: now + 17 * 3600e3, lastDurationMs: 620 },
    { id: 'job_health', name: 'Service health sweep', schedule: 'every 5 minutes', status: 'succeeded', lastRun: now - 4 * 60000, nextRun: now + 60000, lastDurationMs: 340 },
    { id: 'job_reports', name: 'Scheduled report delivery', schedule: 'weekly', status: 'failed', lastRun: now - 2 * 864e5, nextRun: now + 5 * 864e5, lastDurationMs: 0, result: 'SMTP timeout' },
  ]);
  await putMany('backups', [
    { id: 'bak_seed1', scope: 'full', status: 'complete', at: now - 9 * 3600e3, sizeMb: 184.2, hash: '9f2c4e7a1b6d8c3f5e0a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e', location: 'local-encrypted-vault', by: 'system', note: 'Nightly backup', restoreTestedAt: now - 8 * 3600e3 },
    { id: 'bak_seed2', scope: 'incremental', status: 'complete', at: now - 33 * 3600e3, sizeMb: 12.8, hash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b', location: 'local-encrypted-vault', by: 'system', note: 'Hourly increment', restoreTestedAt: null },
  ]);

  // 24. Platform settings, feature controls and integrations.
  await saveConfig(root, {
    environment: 'production', sessionIdleMin: 15, maxSessionHours: 8, mfaRequired: true,
    passwordMinLength: 12, maintenance: { enabled: false, message: '' },
    supportEmail: 'support@examos.example', telemetry: true, auditRetentionDays: 365,
    defaultCandidateRetentionDays: 730, allowedOrigins: ['https://exam.examos.in'],
    releaseChannel: 'stable', requireReleaseEvidence: true, deviceHeartbeatSeconds: 40,
  }, 'Initial platform configuration');
  for (const [key, enabled] of [
    ['two-person-approvals', true], ['privacy-console', true], ['tpm-attestation', true],
    ['auto-submit', true], ['scheduled-reports', false], ['usb-exam-delivery', true],
  ]) await toggleFeature(root, key, enabled);
  await saveIntegration(root, { name: 'SMTP relay', kind: 'smtp', url: '', secret: 'demo-smtp-secret', enabled: true, notes: 'Outbound exam notifications' });
  await saveIntegration(root, { name: 'SIEM collector', kind: 'siem', url: 'https://siem.example.com/ingest', secret: 'demo-siem-secret', enabled: true, notes: 'Security event forwarding' });
  const siem = (await all('integrations')).find((i) => i.kind === 'siem');
  if (siem) await testIntegration(root, siem);
  await put('meta', { id: 'platform', environment: 'production', value: { environment: 'production' }, updatedAt: Date.now() });

  // 25. A custom role demonstrating the role builder.
  await createRole(root, {
    id: 'center-coordinator', label: 'Centre Coordinator',
    desc: 'Coordinates one exam centre: check-in, device readiness and incident triage without policy or release rights.',
    perms: ['dashboard.view', 'ops.view', 'exam.view', 'candidate.view', 'candidate.verify', 'device.view',
      'compat.view', 'incident.view', 'incident.manage', 'report.generate', 'notification.view',
      'support.view', 'support.manage'],
  });

  await put('meta', {
    id: 'seeded', at: Date.now(), version: 3, elapsedMs: Date.now() - seedStarted,
    summary: { tenants: 2, candidates: t1Cands.length + t2Cands.length, exams: 4, started, submitted },
  });
}
