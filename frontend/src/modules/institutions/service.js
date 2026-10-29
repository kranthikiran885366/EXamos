import { all, get, put, del } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log, assertScope, requireReason, isEmail } from '../../core/services/common';
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
const codeOf = (name) => 'INS-' + clean(name, 20).replace(/[^A-Za-z0-9]/g, '').slice(0, 4).toUpperCase().padEnd(4, 'X') + '-' + Math.floor(Math.random() * 900 + 100);

export async function createInstitution(a, input) {
  need(a, 'tenant.manage');
  const name = clean(input.name, 80);
  if (name.length < 3) fail('Institution name needs 3+ characters.');
  const tenants = await all('tenants');
  if (tenants.some((t) => t.name.toLowerCase() === name.toLowerCase())) fail('An institution with this name already exists.');
  const code = clean(input.code, 20).toUpperCase() || codeOf(name);
  if (tenants.some((t) => t.code === code)) fail('This institution code is already used.');
  const domains = (Array.isArray(input.domains) ? input.domains : String(input.domains || '').split(/[\s,]+/)).map((d) => d.trim().toLowerCase()).filter(Boolean);
  for (const d of domains) if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) fail(`${d} is not a valid domain.`);
  if (input.contactEmail && !isEmail(input.contactEmail)) fail('Enter a valid contact email.');
  const now = Date.now();
  const t = {
    id: id('ten'), name, code, domains, contactEmail: clean(input.contactEmail, 120), contactPhone: clean(input.contactPhone, 30),
    region: clean(input.region, 40) || 'India · Mumbai', timezone: input.timezone || 'Asia/Kolkata',
    plan: input.plan || 'pilot', status: 'active', entityType: input.entityType || 'enterprise',
    registrationNumber: clean(input.registrationNumber || '', 60),
    maxCenters: Number(input.maxCenters) || 5,
    maxCandidates: Number(input.maxCandidates) || 500, deploymentModel: input.deploymentModel || 'usb-boot',
    branding: { displayName: name, accent: '#2f5bea' }, notificationPrefs: { email: true, inApp: true },
    examDefaults: { durationMin: 60, lateEntryMin: 15, attestationLevel: 'tpm' },
    security: { requireTpm: true, requireSecureBoot: true, allowUsbStorage: false },
    history: [{ at: now, by: a.id, action: 'Institution registered' }],
    createdAt: now, createdBy: a.id,
  };
  try {
    const backendRes = await Api.createInstitution({
      name,
      code,
      contactEmail: t.contactEmail,
      contactPhone: t.contactPhone,
      region: t.region,
      timezone: t.timezone,
      plan: t.plan,
      maxCenters: t.maxCenters,
      maxCandidates: t.maxCandidates,
      deploymentModel: t.deploymentModel,
      retentionDays: 365,
      domains: t.domains,
    });
    if (backendRes?.institution_id) {
      t.id = backendRes.institution_id;
    }
  } catch (err) {
    console.warn('Backend institution registration fallback:', err.message);
  }
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

  try {
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
  } catch (err) {
    console.warn('Backend updateInstitution sync:', err.message);
  }

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

  try {
    await Api.setInstitutionStatus(t.id, status, r);
  } catch (err) {
    console.warn('Backend setInstitutionStatus sync:', err.message);
  }

  const next = { ...t, status, statusReason: r, statusAt: Date.now(), history: [...(t.history || []), { at: Date.now(), by: a.id, action: `Status → ${status}`, reason: r }] };
  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_' + status.toUpperCase(), `${t.name}: ${r}`);
  return `${t.name} is now ${status}.`;
}

export async function saveExamDefaults(a, t, defaults) {
  need(a, 'settings.inst'); assertScope(a, t.id);
  const next = { ...t, examDefaults: { ...t.examDefaults, ...defaults }, history: [...(t.history || []), { at: Date.now(), by: a.id, action: 'Exam defaults updated' }] };

  try {
    await Api.saveInstitutionExamDefaults(t.id, defaults);
  } catch (err) {
    console.warn('Backend saveExamDefaults sync:', err.message);
  }

  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_EXAM_DEFAULTS', t.name);
  return 'Exam defaults saved.';
}

export async function saveSecuritySettings(a, t, security) {
  need(a, 'settings.inst'); assertScope(a, t.id);
  const next = { ...t, security: { ...t.security, ...security }, history: [...(t.history || []), { at: Date.now(), by: a.id, action: 'Security defaults updated' }] };

  try {
    await Api.saveInstitutionSecurity(t.id, security);
  } catch (err) {
    console.warn('Backend saveSecuritySettings sync:', err.message);
  }

  await put('tenants', next);
  await put('institutions', next).catch(() => {});
  await log(a, 'TENANT_SECURITY_UPDATED', t.name);
  return 'Security defaults saved.';
}

/* ---------------- Campuses ---------------- */
export async function createCampus(a, { tenantId, name, code, city, address, capacity }) {
  need(a, 'campus.manage'); assertScope(a, tenantId);
  const t = await get('tenants', tenantId); if (!t) fail('Institution not found.');
  if ((await all('campuses')).filter((c) => c.tenantId === tenantId).length >= 200) fail('Campus limit reached.');
  const n = clean(name, 80); if (n.length < 3) fail('Campus name needs 3+ characters.');
  const c = clean(code, 10).toUpperCase() || `CMP-${Math.floor(Math.random() * 900 + 100)}`;
  if ((await all('campuses')).some((x) => x.tenantId === tenantId && x.code === c)) fail('Campus code already used.');
  const cap = Number(capacity); if (!(cap >= 1 && cap <= 5000)) fail('Capacity must be 1–5,000.');
  const campusObj = { id: id('cmp'), tenantId, name: n, code: c, city: clean(city, 40), address: clean(address, 160), capacity: cap, status: 'active', adminIds: [], createdAt: Date.now() };

  try {
    const res = await Api.createCampus({
      tenantId,
      name: n,
      code: c,
      city: campusObj.city,
      address: campusObj.address,
      capacity: cap,
    });
    if (res?.campus_id) campusObj.id = res.campus_id;
  } catch (err) {
    console.warn('Backend createCampus sync:', err.message);
  }

  await put('campuses', campusObj);
  await put('centers', campusObj).catch(() => {});
  await log(a, 'CAMPUS_CREATED', `${t.name} · ${c}`);
  return `Campus ${c} created.`;
}

export async function updateCampus(a, c, patch) {
  need(a, 'campus.manage'); assertScope(a, c.tenantId);
  const next = { ...c, name: patch.name !== undefined ? clean(patch.name, 80) : c.name, city: patch.city !== undefined ? clean(patch.city, 40) : c.city, address: patch.address !== undefined ? clean(patch.address, 160) : c.address };
  if (patch.capacity !== undefined) { const cap = Number(patch.capacity); if (!(cap >= 1 && cap <= 5000)) fail('Capacity must be 1–5,000.'); next.capacity = cap; }

  try {
    await Api.updateCampus(c.id, {
      name: next.name,
      city: next.city,
      address: next.address,
      capacity: next.capacity,
    });
  } catch (err) {
    console.warn('Backend updateCampus sync:', err.message);
  }

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

  try {
    await Api.setCampusStatus(c.id, status, r);
  } catch (err) {
    console.warn('Backend setCampusStatus sync:', err.message);
  }

  await put('campuses', { ...c, status, statusReason: r });
  await log(a, 'CAMPUS_' + status.toUpperCase(), `${c.code}: ${r}`);
  return `${c.code} is now ${status}.`;
}

export async function assignCampusAdmin(a, c, userId) {
  need(a, 'campus.manage'); assertScope(a, c.tenantId);
  const u = await get('users', userId); if (!u || u.tenantId !== c.tenantId) fail('Pick a user from this institution.');
  await put('campuses', { ...c, adminIds: [...new Set([...(c.adminIds || []), u.id])] });
  await log(a, 'CAMPUS_ADMIN_ASSIGNED', `${c.code} -> ${u.id}`);
  return 'Campus administrator assigned.';
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
  const n = clean(name, 80); if (n.length < 3) fail('Department name needs 3+ characters.');
  const c = clean(code, 12).toUpperCase() || `DEP-${Math.floor(Math.random() * 900 + 100)}`;
  if ((await all('departments')).some((x) => x.tenantId === tenantId && x.code === c)) fail('Department code already used.');
  if (!DEPT_TYPES.some((t) => t.v === type)) fail('Pick a department type.');
  if (campusId) { const cp = await get('campuses', campusId); if (!cp || cp.tenantId !== tenantId) fail('Pick a campus in this institution.'); }
  const deptObj = { id: id('dep'), tenantId, name: n, code: c, type, campusId: campusId || null, status: 'active', createdAt: Date.now() };

  try {
    const res = await Api.createDepartment({
      tenantId,
      name: n,
      code: c,
      type,
      campusId: deptObj.campusId,
    });
    if (res?.department_id) deptObj.id = res.department_id;
  } catch (err) {
    console.warn('Backend createDepartment sync:', err.message);
  }

  await put('departments', deptObj);
  await log(a, 'DEPARTMENT_CREATED', c);
  return `Department ${c} created.`;
}

export async function setDepartmentStatus(a, d, status, reason) {
  need(a, 'dept.manage'); assertScope(a, d.tenantId);
  const r = requireReason(reason, 8);
  if (status === 'inactive' && (await all('users')).some((u) => u.departmentId === d.id && u.status === 'active')) fail('Reassign active staff before deactivating this department.');

  try {
    await Api.setDepartmentStatus(d.id, status, r);
  } catch (err) {
    console.warn('Backend setDepartmentStatus sync:', err.message);
  }

  await put('departments', { ...d, status, statusReason: r });
  await log(a, 'DEPARTMENT_' + status.toUpperCase(), `${d.code}: ${r}`);
  return `${d.code} is now ${status}.`;
}

/* ---------------- Staff assignments ---------------- */
export async function assignStaff(a, { tenantId, userId, campusId = '', departmentId = '', roleTitle }) {
  need(a, 'staff.manage'); assertScope(a, tenantId);
  const u = await get('users', userId); if (!u || u.tenantId !== tenantId) fail('Pick a user from this institution.');
  if (campusId) { const c = await get('campuses', campusId); if (!c || c.tenantId !== tenantId) fail('Pick a campus in this institution.'); }
  if (departmentId) { const d = await get('departments', departmentId); if (!d || d.tenantId !== tenantId) fail('Pick a department in this institution.'); }
  const existing = (await all('staff')).find((s) => s.tenantId === tenantId && s.userId === userId);
  const rec = { id: existing?.id || id('stf'), tenantId, userId, name: u.name, roleTitle: clean(roleTitle, 60) || u.title, campusId, departmentId, status: 'active', createdAt: existing?.createdAt || Date.now(), updatedAt: Date.now() };

  try {
    const res = await Api.assignStaff({
      tenantId,
      userId,
      name: u.name,
      roleTitle: rec.roleTitle,
      campusId,
      departmentId,
    });
    if (res?.staff_id) rec.id = res.staff_id;
  } catch (err) {
    console.warn('Backend assignStaff sync:', err.message);
  }

  await put('staff', rec);
  await log(a, 'STAFF_ASSIGNED', `${u.id} ${campusId || 'all campuses'}`);
  return 'Staff assignment saved.';
}

export async function removeStaff(a, s, reason) {
  need(a, 'staff.manage'); assertScope(a, s.tenantId);
  const r = requireReason(reason, 8);

  try {
    await Api.removeStaff(s.id, r);
  } catch (err) {
    console.warn('Backend removeStaff sync:', err.message);
  }

  await put('staff', { ...s, status: 'inactive', statusReason: r, updatedAt: Date.now() });
  await log(a, 'STAFF_REMOVED', `${s.userId}: ${r}`);
  return 'Staff assignment removed.';
}

/* ---------------- Institution Admin Management ---------------- */

/**
 * List administrators for a specific institution.
 * Fetches from API first, falls back to local IndexedDB filtered by tenantId.
 */
export async function listInstitutionAdmins(institutionId) {
  try {
    const apiAdmins = await Api.listInstitutionAdmins(institutionId);
    if (Array.isArray(apiAdmins) && apiAdmins.length > 0) {
      // Sync to local cache
      for (const u of apiAdmins) {
        const local = {
          id: u.user_id || u.id || u.username,
          username: u.username,
          name: u.full_name || u.name || u.username,
          email: u.email || '',
          role: u.role_name ? u.role_name.toLowerCase().replace(/ /g, '_') : 'inst_admin',
          tenantId: institutionId,
          status: u.active === 0 ? 'suspended' : 'active',
          mfaEnabled: !!u.mfa_enabled,
          lastLogin: u.last_login || null,
          createdAt: u.created_at || Date.now(),
        };
        await put('users', local).catch(() => {});
      }
      return apiAdmins.map((u) => ({
        id: u.user_id || u.id || u.username,
        username: u.username,
        name: u.full_name || u.name || u.username,
        email: u.email || '',
        role: u.role_name ? u.role_name.toLowerCase().replace(/ /g, '_') : 'inst_admin',
        tenantId: institutionId,
        status: u.active === 0 ? 'suspended' : 'active',
        mfaEnabled: !!u.mfa_enabled,
        lastLogin: u.last_login || null,
        createdAt: u.created_at || Date.now(),
      }));
    }
  } catch (err) {
    console.warn('Backend listInstitutionAdmins fallback:', err.message);
  }
  // Fallback: local IndexedDB
  const allUsers = await all('users');
  return allUsers.filter((u) => u.tenantId === institutionId);
}

/**
 * Invite / create an administrator for an institution.
 * Calls POST /api/v1/admin/users with institution_id scoped to the target institution.
 * Stores the result in local IndexedDB for immediate UI update.
 */
export async function inviteInstitutionAdmin(actor, institutionId, { name, email, role, campusId = '' }) {
  need(actor, 'user.manage');
  if (!clean(name, 60) || clean(name, 60).length < 2) fail('Enter the full name of the administrator.');
  if (!email || !email.includes('@')) fail('Enter a valid institutional email address.');

  let result;
  try {
    result = await Api.inviteInstitutionAdmin(institutionId, { name, email, role, campusId });
  } catch (err) {
    // If the dedicated endpoint fails, try fallback via createUser
    try {
      result = await Api.createUser({
        username: email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_') + '_' + Date.now().toString(36),
        fullName: name,
        email,
        password: 'ExamOS!Temp' + Math.random().toString(36).slice(2, 8).toUpperCase() + '1',
        institutionId,
        role,
      });
    } catch (e2) {
      console.warn('Backend inviteInstitutionAdmin both attempts failed:', e2.message);
      // Create locally so UI is consistent
      result = null;
    }
  }

  const userId = result?.user_id || result?.id || ('usr_' + Date.now().toString(36));
  const newUser = {
    id: userId,
    username: result?.username || email.split('@')[0],
    name: clean(name, 60),
    email: clean(email, 120).toLowerCase(),
    role: role || 'inst_admin',
    tenantId: institutionId,
    campusId: campusId || null,
    status: 'active',
    mfaEnabled: false,
    createdAt: Date.now(),
    invitedBy: actor.id,
    tempPassword: result?.tempPassword || null,
  };
  await put('users', newUser);
  await log(actor, 'INSTITUTION_ADMIN_INVITED', `${email} as ${role} for ${institutionId}`);
  return newUser;
}

/**
 * Remove an administrator from an institution — sets their account to suspended.
 */
export async function removeInstitutionAdmin(actor, institutionId, userId, reason) {
  need(actor, 'user.manage');
  const r = requireReason(reason, 8);
  const u = await get('users', userId);
  if (!u) fail('User not found.');
  await put('users', { ...u, status: 'suspended', statusReason: r, statusAt: Date.now(), statusBy: actor.id });
  await log(actor, 'INSTITUTION_ADMIN_REMOVED', `${userId} from ${institutionId}: ${r}`);
  return 'Administrator access removed.';
}

export async function institutionStats(tenantId, ctx = {}) {
  try {
    const backendStats = await Api.getInstitutionStats(tenantId);
    if (backendStats && typeof backendStats.campuses === 'number') {
      return backendStats;
    }
  } catch (err) {
    // Offline / fallback to local DB aggregation
  }

  const { centers = await all('centers'), devices = await all('devices'), candidates = await all('candidates'), exams = await all('exams'), campuses = await all('campuses'), departments = await all('departments'), users = await all('users') } = ctx;
  const f = (x) => x.tenantId === tenantId;
  const e = exams.filter(f), d = devices.filter(f), cm = campuses.filter(f);
  return {
    campuses: cm.length, departments: departments.filter(f).length, users: users.filter(f).length,
    centers: centers.filter(f).length, devices: d.length, enrolledDevices: d.filter((x) => x.status === 'enrolled').length,
    candidates: candidates.filter(f).length, exams: e.length, liveExams: e.filter((x) => x.status === 'live').length,
    publishedExams: e.filter((x) => x.status === 'published').length, openIncidents: (await all('incidents')).filter((i) => f(i) && ['open', 'investigating', 'contained'].includes(i.status)).length,
  };
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
  if (res?.tenant_id) {
    // Sync local IndexedDB for immediate responsive UI
    await put('tenants', {
      id: res.tenant_id,
      name: res.name || 'Provisioned Institution',
      code: 'INS',
      status: 'active',
      plan: 'pilot',
      createdAt: Date.now(),
    }).catch(() => {});
  }
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
