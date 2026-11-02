import { all, get, put, del } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { need, fail, log, assertScope, requireReason, isEmail } from '../../core/services/common';
import { can } from '../../core/security/rbac';
import * as Api from '../../core/api/services';

export const DEPLOYMENT_MODELS = [
  { v: 'usb-boot', l: 'Bootable USB (recommended)' },
  { v: 'managed-lab', l: 'Managed lab devices' },
  { v: 'hybrid', l: 'Hybrid USB + managed lab' },
];

export const ENTITY_TYPES = [
  { v: 'enterprise', l: 'Corporate Enterprise / Company', category: 'Corporate', desc: 'Pre-employment hiring, recruitment drives, and workforce certification' },
  { v: 'technology', l: 'Technology / Software Enterprise', category: 'Corporate', desc: 'Developer coding tests, engineering hiring, and technical assessments' },
  { v: 'university', l: 'University / Higher Education', category: 'Academic', desc: 'Centralized semester examinations, thesis vivas, and entrance tests' },
  { v: 'college', l: 'College / Institute / Polytechnic', category: 'Academic', desc: 'Undergraduate, postgraduate, and laboratory examinations' },
  { v: 'certification_body', l: 'Professional Certification / Licensure Board', category: 'Certification', desc: 'Licensing, regulatory accreditation, and credential exams' },
  { v: 'government', l: 'Government / Public Sector Recruitment Board', category: 'Public Sector', desc: 'Civil services, national public recruitment, and service commissions' },
  { v: 'testing_agency', l: 'Commercial Testing Agency / Assessment Center', category: 'Commercial', desc: 'Standardized testing providers, proctoring enclaves, and client test suites' },
];

export const isCorporateEntity = (type) => ['enterprise', 'technology', 'company', 'corporate'].includes(String(type || '').toLowerCase());

export const entityLabel = (type) => {
  const found = ENTITY_TYPES.find((t) => t.v === String(type || '').toLowerCase());
  return found ? found.l : (type ? type.charAt(0).toUpperCase() + type.slice(1) : 'Enterprise / Institution');
};

export const getOrgTerms = (entityType) => {
  const isCorp = isCorporateEntity(entityType);
  return {
    isCorp,
    orgLabel: isCorp ? 'Company / Enterprise' : 'Institution / University',
    candidateLabel: isCorp ? 'Candidates / Examinees' : 'Students / Candidates',
    candidateSingular: isCorp ? 'Candidate' : 'Student',
    campusLabel: isCorp ? 'Offices & Testing Centers' : 'Campuses & Centers',
    campusSingular: isCorp ? 'Office / Center' : 'Campus',
    departmentLabel: isCorp ? 'Business Units & Teams' : 'Departments & Units',
    departmentSingular: isCorp ? 'Business Unit' : 'Department',
    regNumberLabel: isCorp ? 'Corporate CIN / Tax / Incorporation ID' : 'Accreditation Board / Charter Reg No',
    regNumberPlaceholder: isCorp ? 'e.g. U72200MH2026PTC123456 or EIN/Tax ID' : 'e.g. UGC-UNIV-2026-9810 or Charter ID',
    domainPlaceholder: isCorp ? 'e.g. company.com or enterprise.tech' : 'e.g. university.ac.in or college.edu',
    signatoryLabel: isCorp ? 'Authorized Executive / VP / HR Director / Officer' : 'Registrar / Vice-Chancellor / Exam Controller',
  };
};
export const TIMEZONES = ['Asia/Kolkata', 'Asia/Dubai', 'Asia/Singapore', 'Europe/London', 'UTC'];
const randomSuffix = () => {
  const buf = new Uint32Array(1);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(buf);
  else buf[0] = Date.now();
  return 100 + (buf[0] % 900);
};
const codeOf = (name) => 'INS-' + clean(name, 20).replace(/[^A-Za-z0-9]/g, '').slice(0, 4).toUpperCase().padEnd(4, 'X') + '-' + randomSuffix();
const requireBackendId = (value, what) => {
  if (!value) fail(`The backend did not return a ${what} identifier. The operation was not saved.`);
  return value;
};

export async function createInstitution(a, input) {
  need(a, 'tenant.manage');
  const name = clean(input.name, 80);
  if (name.length < 3) fail('Institution name needs 3+ characters.');
  const code = clean(input.code, 20).toUpperCase() || codeOf(name);
  const domains = (Array.isArray(input.domains) ? input.domains : String(input.domains || '').split(/[\s,]+/)).map((d) => d.trim().toLowerCase()).filter(Boolean);
  for (const d of domains) if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) fail(`${d} is not a valid domain.`);
  if (input.contactEmail && !isEmail(input.contactEmail)) fail('Enter a valid contact email.');

  /* H5 fix: backend must succeed first — no local-only institution creation.
   * If the backend is unreachable or rejects, we fail immediately instead of
   * silently creating a local-only IndexedDB record. */
  let backendRes;
  try {
    backendRes = await Api.createInstitution({
      name,
      code,
      contactEmail: clean(input.contactEmail, 120),
      contactPhone: clean(input.contactPhone, 30),
      region: clean(input.region, 40) || '',
      timezone: input.timezone || '',
      plan: input.plan || 'pilot',
      maxCenters: Number(input.maxCenters) || 5,
      maxCandidates: Number(input.maxCandidates) || 500,
      deploymentModel: input.deploymentModel || 'usb-boot',
      retentionDays: 365,
      domains,
    });
  } catch (err) {
    fail(err.message || 'Backend institution registration failed. Cannot create institution offline.');
  }

  const instId = backendRes?.institution_id || backendRes?.id;
  if (!instId) fail('Backend did not return an institution ID.');

  const now = Date.now();
  const t = {
    id: instId, name, code, domains, contactEmail: clean(input.contactEmail, 120), contactPhone: clean(input.contactPhone, 30),
    region: clean(input.region, 40) || '', timezone: input.timezone || '',
    plan: input.plan || 'pilot', status: 'active', entityType: input.entityType || 'university',
    registrationNumber: clean(input.registrationNumber || '', 60),
    maxCenters: Number(input.maxCenters) || 5,
    maxCandidates: Number(input.maxCandidates) || 500, deploymentModel: input.deploymentModel || 'usb-boot',
    branding: { displayName: name, accent: '#2f5bea' }, notificationPrefs: { email: true, inApp: true },
    examDefaults: { durationMin: 60, lateEntryMin: 15, attestationLevel: 'tpm' },
    security: { requireTpm: true, requireSecureBoot: true, allowUsbStorage: false },
    history: [{ at: now, by: a.id, action: 'Institution registered' }],
    createdAt: now, createdBy: a.id,
  };
  await put('tenants', t);
  await put('institutions', t).catch(() => {});
  await log(a, 'TENANT_CREATED', `${name} (${code})`);
  return t;
}
// Backwards-compatible alias used by the original provisioning flow.
export const createTenant = createInstitution;

export async function updateInstitution(a, t, patch) {
  need(a, 'inst.manage'); assertScope(a, t.id);
  const next = { ...t };
  if (patch.name !== undefined) {
    const n = clean(patch.name, 80); if (n.length < 3) fail('Institution name needs 3+ characters.');
    if ((await all('tenants')).some((x) => x.id !== t.id && x.name.toLowerCase() === n.toLowerCase())) fail('Another institution already uses this name.');
    next.name = n;
  }
  if (patch.domains !== undefined) {
    const ds = (Array.isArray(patch.domains) ? patch.domains : String(patch.domains).split(/[\s,]+/)).map((d) => d.trim().toLowerCase()).filter(Boolean);
    for (const d of ds) if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) fail(`${d} is not a valid domain.`);
    next.domains = ds;
  }
  for (const k of ['contactEmail', 'contactPhone', 'region', 'timezone', 'deploymentModel', 'entityType', 'registrationNumber']) if (patch[k] !== undefined) next[k] = clean(patch[k], 120);
  if (patch.contactEmail && !isEmail(patch.contactEmail)) fail('Enter a valid contact email.');
  if (patch.maxCandidates !== undefined) { const n = Number(patch.maxCandidates); if (!(n >= 10 && n <= 100000)) fail('Candidate capacity must be 10–100,000.'); next.maxCandidates = n; }
  if (patch.plan !== undefined) { if (a.role !== 'superadmin' && a.role !== 'ops_admin') fail('Only the platform can change a plan.'); next.plan = patch.plan; }
  if (patch.examDefaults) next.examDefaults = { ...next.examDefaults, ...patch.examDefaults };
  if (patch.security) next.security = { ...next.security, ...patch.security };
  if (patch.notificationPrefs) next.notificationPrefs = { ...next.notificationPrefs, ...patch.notificationPrefs };
  if (patch.branding) next.branding = { ...next.branding, ...patch.branding };
  next.history = [...(t.history || []), { at: Date.now(), by: a.id, action: 'Institution settings updated' }];

  await Api.updateInstitution(t.id, {
    name: next.name,
    contactEmail: next.contactEmail,
    contactPhone: next.contactPhone,
    region: next.region,
    timezone: next.timezone,
    deploymentModel: next.deploymentModel,
    maxCandidates: next.maxCandidates,
    maxCenters: next.maxCenters,
    plan: next.plan,
    domains: next.domains,
  });

  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_UPDATED', next.name);
  return 'Institution updated.';
}

export async function setInstitutionStatus(a, t, status, reason) {
  need(a, 'tenant.manage');
  if (!['active', 'suspended', 'archived'].includes(status)) fail('Unknown institution status.');
  const r = requireReason(reason, 8);
  if (status === 'suspended') {
    if ((await all('tenants')).filter((x) => x.status === 'active').length <= 1) fail('Cannot suspend the last active institution.');
    if ((await all('exams')).some((e) => e.tenantId === t.id && e.status === 'live')) fail('Close live exams before suspending this institution.');
  }
  if (status === 'archived') {
    if ((await all('exams')).some((e) => e.tenantId === t.id && ['live', 'published'].includes(e.status))) fail('Close or cancel published/live exams before archiving.');
  }

  await Api.setInstitutionStatus(t.id, status, r);

  const next = { ...t, status, statusReason: r, statusAt: Date.now(), history: [...(t.history || []), { at: Date.now(), by: a.id, action: `Status → ${status}`, reason: r }] };
  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_' + status.toUpperCase(), `${t.name}: ${r}`);
  return `${t.name} is now ${status}.`;
}

export async function saveExamDefaults(a, t, defaults) {
  need(a, 'settings.inst'); assertScope(a, t.id);
  const next = { ...t, examDefaults: { ...t.examDefaults, ...defaults }, history: [...(t.history || []), { at: Date.now(), by: a.id, action: 'Exam defaults updated' }] };

  await Api.saveInstitutionExamDefaults(t.id, defaults);

  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_EXAM_DEFAULTS', t.name);
  return 'Exam defaults saved.';
}

export async function saveSecuritySettings(a, t, security) {
  need(a, 'settings.inst'); assertScope(a, t.id);
  const next = { ...t, security: { ...t.security, ...security }, history: [...(t.history || []), { at: Date.now(), by: a.id, action: 'Security defaults updated' }] };

  await Api.saveInstitutionSecurity(t.id, security);

  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_SECURITY_UPDATED', t.name);
  return 'Security defaults saved.';
}

/* ---------------- Campuses ---------------- */
export async function createCampus(a, { tenantId, name, code, city, address, capacity }) {
  need(a, 'campus.manage'); assertScope(a, tenantId);
  if (!tenantId) fail('Pick an institution.');
  const n = clean(name, 80); if (n.length < 3) fail('Campus name needs 3+ characters.');
  const c = clean(code, 10).toUpperCase() || `CMP-${randomSuffix()}`;
  const cap = Number(capacity); if (!(cap >= 1 && cap <= 5000)) fail('Capacity must be 1–5,000.');

  const res = await Api.createCampus({
    tenantId,
    name: n,
    code: c,
    city: clean(city, 40),
    address: clean(address, 160),
    capacity: cap,
  });
  const campusId = requireBackendId(res?.campus_id || res?.id, 'campus');
  const campusObj = {
    id: campusId, tenantId, name: n, code: c,
    city: clean(city, 40), address: clean(address, 160),
    capacity: cap, status: 'active', adminIds: [], createdAt: Date.now(),
  };
  await put('campuses', campusObj);
  await put('centers', campusObj).catch(() => {});
  await log(a, 'CAMPUS_CREATED', `${tenantId} · ${c}`);
  return `Campus ${c} created.`;
}

export async function updateCampus(a, c, patch) {
  need(a, 'campus.manage'); assertScope(a, c.tenantId);
  const next = { ...c, name: patch.name !== undefined ? clean(patch.name, 80) : c.name, city: patch.city !== undefined ? clean(patch.city, 40) : c.city, address: patch.address !== undefined ? clean(patch.address, 160) : c.address };
  if (patch.capacity !== undefined) { const cap = Number(patch.capacity); if (!(cap >= 1 && cap <= 5000)) fail('Capacity must be 1–5,000.'); next.capacity = cap; }

  await Api.updateCampus(c.id, {
    name: next.name,
    city: next.city,
    address: next.address,
    capacity: next.capacity,
  });

  await put('campuses', next);
  await log(a, 'CAMPUS_UPDATED', c.code);
  return 'Campus updated.';
}

export async function setCampusStatus(a, c, status, reason) {
  need(a, 'campus.manage'); assertScope(a, c.tenantId);
  if (!['active', 'inactive', 'archived'].includes(status)) fail('Unknown campus status.');
  const r = requireReason(reason, 8);
  if (status !== 'active') {
    const centers = (await all('centers')).filter((x) => x.campusId === c.id);
    const open = (await all('exams')).some((e) => e.centerIds.some((id) => centers.some((x) => x.id === id)) && ['published', 'live'].includes(e.status));
    if (open) fail('An open exam uses a center in this campus.');
  }

  await Api.setCampusStatus(c.id, status, r);

  await put('campuses', { ...c, status, statusReason: r });
  await log(a, 'CAMPUS_' + status.toUpperCase(), `${c.code}: ${r}`);
  return `${c.code} is now ${status}.`;
}

/* ---------------- Departments ---------------- */
export const DEPT_TYPES = [
  // Corporate & Enterprise
  { v: 'engineering', l: 'Engineering / Technology / R&D' },
  { v: 'hr_recruitment', l: 'HR / Talent Acquisition & Recruitment' },
  { v: 'operations', l: 'Operations & Business Delivery' },
  { v: 'corporate_training', l: 'Workforce Training & L&D' },
  { v: 'certification', l: 'Quality, Risk & Compliance' },
  // Academic & Public Sector
  { v: 'academic', l: 'Academic Department' },
  { v: 'examination', l: 'Examination & Assessment Directorate' },
  { v: 'laboratory', l: 'Laboratory & Research Facility' },
  { v: 'administrative', l: 'Corporate HQ / Administration' },
];

export async function createDepartment(a, { tenantId, name, code, campusId, type = 'academic' }) {
  need(a, 'dept.manage'); assertScope(a, tenantId);
  if (!tenantId) fail('Pick an institution.');
  const n = clean(name, 80); if (n.length < 3) fail('Department name needs 3+ characters.');
  const c = clean(code, 12).toUpperCase() || `DEP-${randomSuffix()}`;
  if (!DEPT_TYPES.some((t) => t.v === type)) fail('Pick a department type.');

  const res = await Api.createDepartment({
    tenantId,
    name: n,
    code: c,
    type,
    campusId: campusId || '',
  });
  const depId = requireBackendId(res?.department_id || res?.id, 'department');
  const deptObj = { id: depId, tenantId, name: n, code: c, type, campusId: campusId || null, status: 'active', createdAt: Date.now() };
  await put('departments', deptObj);
  await log(a, 'DEPARTMENT_CREATED', c);
  return `Department ${c} created.`;
}

export async function setDepartmentStatus(a, d, status, reason) {
  need(a, 'dept.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 8);
  if (status === 'inactive' && (await all('users')).some((u) => u.departmentId === d.id && u.status === 'active')) fail('Reassign active staff before deactivating this department.');

  await Api.setDepartmentStatus(d.id, status, r);

  await put('departments', { ...d, status, statusReason: r });
  await log(a, 'DEPARTMENT_' + status.toUpperCase(), `${d.code}: ${r}`);
  return `${d.code} is now ${status}.`;
}

/* ---------------- Staff assignments ---------------- */
export async function assignStaff(a, { tenantId, userId, campusId = '', departmentId = '', roleTitle }) {
  need(a, 'staff.manage'); assertScope(a, tenantId);
  if (!tenantId || !userId) fail('Pick an institution and a user.');
  const u = await get('users', userId).catch(() => null);

  const res = await Api.assignStaff({
    tenantId,
    userId,
    name: u?.name || '',
    roleTitle: clean(roleTitle, 60) || u?.title || '',
    campusId,
    departmentId,
  });
  const staffId = requireBackendId(res?.staff_id || res?.id, 'staff');
  const rec = {
    id: staffId, tenantId, userId,
    name: u?.name || res?.name || '',
    roleTitle: clean(roleTitle, 60) || u?.title || '',
    campusId, departmentId, status: 'active',
    createdAt: Date.now(), updatedAt: Date.now(),
  };
  await put('staff', rec);
  await log(a, 'STAFF_ASSIGNED', `${userId} ${campusId || 'all campuses'}`);
  return 'Staff assignment saved.';
}

export async function removeStaff(a, s, reason) {
  need(a, 'staff.manage'); assertScope(a, s.tenantId);
  const r = requireReason(reason, 8);

  await Api.removeStaff(s.id, r);

  await put('staff', { ...s, status: 'inactive', statusReason: r, updatedAt: Date.now() });
  await log(a, 'STAFF_REMOVED', `${s.userId}: ${r}`);
  return 'Staff assignment removed.';
}

/* ---------------- Institution Admin Management ---------------- */

/**
 * List administrators for a specific institution. The backend is the only
 * source of truth — a network or authorization failure is surfaced to the
 * caller instead of silently showing stale local rows.
 */
export async function listInstitutionAdmins(institutionId) {
  const apiAdmins = await Api.listInstitutionAdmins(institutionId);
  const rows = Array.isArray(apiAdmins) ? apiAdmins : [];
  for (const u of rows) {
    const local = {
      id: u.id || u.user_id || u.username,
      username: u.username,
      name: u.full_name || u.name || u.username,
      email: u.email || '',
      role: u.role || 'inst_admin',
      tenantId: institutionId,
      status: u.status || (u.active === 0 ? 'suspended' : 'active'),
      mfaEnabled: !!u.mfa_enabled,
      lastLogin: u.last_login || null,
      createdAt: u.created_at || null,
    };
    await put('users', local).catch(() => {});
  }
  return rows.map((u) => ({
    id: u.id || u.user_id || u.username,
    username: u.username,
    name: u.full_name || u.name || u.username,
    email: u.email || '',
    role: u.role || 'inst_admin',
    tenantId: institutionId,
    status: u.status || (u.active === 0 ? 'suspended' : 'active'),
    mfaEnabled: !!u.mfa_enabled,
    lastLogin: u.last_login || null,
    createdAt: u.created_at || null,
  }));
}

/**
 * Invite / create an administrator for an institution. The backend creates the
 * account and generates the one-time credential; the client never fabricates a
 * user, password, or identifier.
 */
export async function inviteInstitutionAdmin(actor, institutionId, { name, email, role, campusId = '' }) {
  need(actor, 'user.manage');
  if (!clean(name, 60) || clean(name, 60).length < 2) fail('Enter the full name of the administrator.');
  if (!email || !email.includes('@')) fail('Enter a valid institutional email address.');

  const result = await Api.inviteInstitutionAdmin(institutionId, { name, email, role, campusId });
  const userId = requireBackendId(result?.user_id || result?.id, 'administrator');
  const newUser = {
    id: userId,
    username: result?.username || '',
    name: clean(name, 60),
    email: clean(email, 120).toLowerCase(),
    role: result?.role || role || 'inst_admin',
    tenantId: institutionId,
    campusId: campusId || null,
    status: 'active',
    mfaEnabled: !!result?.mfa_enabled,
    createdAt: Date.now(),
    invitedBy: actor.id,
    tempPassword: result?.tempPassword || null,
  };
  await put('users', newUser);
  await log(actor, 'INSTITUTION_ADMIN_INVITED', `${email} as ${role} for ${institutionId}`);
  return newUser;
}

/**
 * Remove an administrator from an institution — the backend suspends the
 * account and records the reason; the local cache is updated from the result.
 */
export async function removeInstitutionAdmin(actor, institutionId, userId, reason) {
  need(actor, 'user.manage');
  const r = requireReason(reason, 8);
  await Api.removeInstitutionAdmin(institutionId, userId, r);
  const u = await get('users', userId).catch(() => null);
  if (u) await put('users', { ...u, status: 'suspended', statusReason: r, statusAt: Date.now(), statusBy: actor.id });
  await log(actor, 'INSTITUTION_ADMIN_REMOVED', `${userId} from ${institutionId}: ${r}`);
  return 'Administrator access removed.';
}

export async function institutionStats(tenantId) {
  const backendStats = await Api.getInstitutionStats(tenantId);
  if (!backendStats || typeof backendStats.campuses !== 'number') {
    fail('Institution metrics are unavailable from the backend.');
  }
  return backendStats;
}

export const canManageInstitution = (user, t) => can(user.role, 'tenant.manage') || (can(user.role, 'inst.manage') && user.tenantId === t.id);

/* ---------------- Production Institution Lifecycle ---------------- */

export async function submitInstitutionApplication(input) {
  const payload = {
    legalName: clean(input.legalName, 160),
    displayName: clean(input.displayName || input.legalName, 160),
    entityType: input.entityType || 'university',
    registrationNumber: clean(input.registrationNumber, 60),
    country: clean(input.country || 'India', 60),
    state: clean(input.state || 'Maharashtra', 60),
    address: clean(input.address, 512),
    domain: clean(input.domain, 120).toLowerCase(),
    repName: clean(input.repName, 120),
    repRole: clean(input.repRole, 60),
    repEmail: clean(input.repEmail, 120).toLowerCase(),
    repPhone: clean(input.repPhone, 40),
    coordName: clean(input.coordName, 120),
    coordEmail: clean(input.coordEmail, 120).toLowerCase(),
    techName: clean(input.techName, 120),
    techEmail: clean(input.techEmail, 120).toLowerCase(),
    campusCount: Number(input.campusCount) || 1,
    studentCount: Number(input.studentCount) || 500,
    deviceCount: Number(input.deviceCount) || 100,
    deploymentModel: input.deploymentModel || 'usb-boot',
    hardwareProfile: input.hardwareProfile || 'standard-uefi',
    plan: input.plan || 'pilot',
    documents: input.documents || [],
    declarations: input.declarations || { termsAgreed: true, privacyAgreed: true },
  };

  if (!payload.legalName || !payload.registrationNumber || !payload.domain || !payload.repEmail || !payload.address) {
    fail('Legal name, registration number, official domain, address, and representative email are required.');
  }

  const res = await Api.applyInstitution(payload);
  return res;
}

export async function fetchInstitutionApplications() {
  const res = await Api.listInstitutionApplications();
  return res?.applications || [];
}

export async function fetchInstitutionApplication(id) {
  const res = await Api.getInstitutionApplication(id);
  return res;
}

export async function reviewApplication(user, id, action, reviewNotes) {
  need(user, 'tenant.manage');
  const res = await Api.reviewInstitutionApplication(id, action, reviewNotes);
  await log(user, 'INSTITUTION_APPLICATION_REVIEWED', `${id}: ${action}`);
  return res;
}

export async function provisionApplication(user, id) {
  need(user, 'tenant.manage');
  const res = await Api.provisionInstitutionApplication(id);
  /* The backend creates the real tenant/license/agreement records atomically.
   * Do not fabricate a local tenant stub; the dashboard re-fetches from the API. */
  await log(user, 'INSTITUTION_PROVISIONED', `${res?.institution_id || id}`);
  return res;
}

export async function fetchInstitutionAgreements(institutionId) {
  const res = await Api.listInstitutionAgreements(institutionId);
  return res?.agreements || [];
}

export async function createAgreementDraft(user, institutionId, data) {
  need(user, 'tenant.manage');
  const res = await Api.createInstitutionAgreement(institutionId, data);
  await log(user, 'AGREEMENT_DRAFTED', `${institutionId}: ${data.title}`);
  return res;
}

export async function signAgreement(user, agreementId, signerData) {
  const res = await Api.signInstitutionAgreement(agreementId, signerData);
  await log(user, 'AGREEMENT_SIGNED', `${agreementId}: ${res.document_digest}`);
  return res;
}

export async function fetchInstitutionLicense(institutionId) {
  const res = await Api.getInstitutionLicense(institutionId);
  return res;
}

export async function updateInstitutionLicense(user, institutionId, data) {
  need(user, 'tenant.manage');
  const res = await Api.updateInstitutionLicense(institutionId, data);
  await log(user, 'LICENSE_UPDATED', `${institutionId}`);
  return res;
}

export async function checkEntitlements(institutionId, resource) {
  const res = await Api.checkInstitutionEntitlements(institutionId, resource);
  return res;
}

export async function fetchInstitutionDeployments(institutionId) {
  const res = await Api.listInstitutionDeployments(institutionId);
  return res?.deployments || [];
}

export async function assignDeployment(user, institutionId, data) {
  need(user, 'tenant.manage');
  const res = await Api.assignInstitutionDeployment(institutionId, data);
  await log(user, 'DEPLOYMENT_ASSIGNED', `${institutionId}: ${data.releaseId}`);
  return res;
}

export async function pushDeployment(user, deploymentId) {
  need(user, 'deployment.manage');
  const res = await Api.pushDeploymentToKiosks(deploymentId);
  await log(user, 'DEPLOYMENT_PUSHED_TO_KIOSKS', `Deployment: ${deploymentId}`);
  return res;
}

export async function fetchInstitutionOnboarding(institutionId) {
  const res = await Api.getInstitutionOnboarding(institutionId);
  return res;
}

export async function updateOnboardingStep(user, institutionId, stepKey, completed, notes = '') {
  const res = await Api.updateInstitutionOnboardingStep(institutionId, stepKey, completed, notes);
  await log(user, 'ONBOARDING_STEP_UPDATED', `${institutionId}: ${stepKey}`);
  return res;
}

export async function fetchInstitutionPilotReadiness(institutionId) {
  const res = await Api.getInstitutionPilotReadiness(institutionId);
  return res;
}
