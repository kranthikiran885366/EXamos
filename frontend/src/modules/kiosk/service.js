// ExamOS Production Kiosk Fleet & Maintenance Service
// Connects the console to the real ExamOS C Security Server (port 8895).
import { all, get, put, putMany } from '../../core/db/db';
import { clean } from '../../core/security/sanitize';
import { id, need, fail, log } from '../../core/services/common';
import { verifyRelease } from '../releases/service';
import * as Api from '../../core/api/services';

/**
 * Fetch real-time status of the ExamOS Kiosk Gateway.
 */
export async function getLiveKioskStatus() {
  try {
    const [srvStatus, srvHealth, terminals, fleet, kiosks] = await Promise.allSettled([
      Api.status(),
      Api.health(),
      Api.getTerminals(),
      Api.listFleet(),
      Api.getKiosks(),
    ]);

    return {
      status: srvStatus.status === 'fulfilled' ? srvStatus.value : null,
      health: srvHealth.status === 'fulfilled' ? srvHealth.value : null,
      terminals: terminals.status === 'fulfilled' ? terminals.value : { terminals: [] },
      fleet: fleet.status === 'fulfilled' ? fleet.value : { devices: [] },
      kiosks: kiosks.status === 'fulfilled' && kiosks.value?.terminals ? kiosks.value.terminals : [],
      timestamp: Date.now(),
      connected: srvHealth.status === 'fulfilled' && srvHealth.value?.status === 'ok',
    };
  } catch (err) {
    console.error('Failed to query live kiosk status:', err);
    return {
      status: null,
      health: null,
      terminals: { terminals: [] },
      fleet: { devices: [] },
      kiosks: [],
      timestamp: Date.now(),
      connected: false,
      error: String(err.message),
    };
  }
}

/**
 * Dispatch or update the Active Exam URL on all kiosks in real time.
 */
export async function dispatchExamUrl(user, { examUrl, examName, examId, durationMinutes = 120, allowedOrigins }) {
  need(user, 'kiosk.manage');
  if (!examUrl || examUrl.trim().length < 5) {
    fail('Please enter a valid Exam URL or local file path.');
  }

  const origins = allowedOrigins || 'staging.examos.example.edu,exam.university.edu,127.0.0.1,localhost';
  const cleanUrl = examUrl.trim();
  const cleanName = examName ? examName.trim() : 'ExamOS Examination Session';

  const res = await Api.saveConfig({
    examUrl: cleanUrl,
    examName: cleanName,
    examId: examId || 'EXAM-2026-DISPATCHED',
    allowedOrigins: origins,
    examDurationMinutes: durationMinutes,
  });

  await log(user, 'KIOSK_URL_DISPATCHED', `URL: ${cleanUrl} | Name: ${cleanName}`);
  return res || { status: 'DISPATCHED', exam_url: cleanUrl };
}

/**
 * Send maintenance command directly to active terminals (PING, RELOAD, LOCK, UNLOCK).
 */
export async function sendKioskCommand(user, { command, targetCandidateId = '*', payload = '' }) {
  need(user, 'kiosk.manage');
  const validCommands = ['PING', 'RELOAD', 'LOCK', 'UNLOCK', 'TERMINATE', 'KEY_RELEASE'];
  if (!validCommands.includes(command)) {
    fail(`Invalid command: ${command}. Must be one of ${validCommands.join(', ')}`);
  }

  const res = await Api.examCommand({
    command,
    targetCandidateId,
    payload,
  });

  await log(user, 'KIOSK_COMMAND_SENT', `Command: ${command} to ${targetCandidateId}`);
  return res;
}

/**
 * Trigger immediate emergency lock across the examination kiosk fleet.
 */
export async function triggerEmergencyLock(user, reason = 'Operator triggered emergency lockdown') {
  need(user, 'kiosk.manage');
  const res = await Api.adminLock();
  await log(user, 'KIOSK_EMERGENCY_LOCK', reason);
  return res;
}

/**
 * Release emergency lock across the examination kiosk fleet.
 */
export async function triggerEmergencyUnlock(user, reason = 'Operator released emergency lockdown') {
  need(user, 'kiosk.manage');
  const res = await Api.adminUnlock();
  await log(user, 'KIOSK_EMERGENCY_UNLOCK', reason);
  return res;
}

/**
 * Trigger live kiosk reload (Wayland / Cage policy refresh).
 */
export async function triggerKioskReload(user) {
  need(user, 'kiosk.manage');
  const res = await Api.adminReload();
  await log(user, 'KIOSK_RELOADED', 'Refreshed browser policies and active runtime config');
  return res;
}

// ---------------------------------------------------------------------------
// Standard Kiosk Profile Management
// ---------------------------------------------------------------------------

export async function createProfile(a, { tenantId, name, releaseId, lockdown, blockClipboard, blockCapture }) {
  need(a, 'kiosk.manage');
  name = clean(name, 60);
  if (name.length < 3) fail('Give the profile a name.');
  const rel = await get('releases', releaseId);
  if (!rel || !['approved', 'rolling', 'stable'].includes(rel.status)) {
    fail('Pick an approved, rolling or stable release.');
  }
  if ((await all('kiosks')).some((k) => k.tenantId === tenantId && k.name === name && k.releaseId === releaseId)) {
    fail('This profile already exists for that release.');
  }
  await put('kiosks', {
    id: id('kio'),
    tenantId,
    name,
    releaseId,
    lockdown,
    blockClipboard: !!blockClipboard,
    blockCapture: !!blockCapture,
    status: 'canary',
    createdBy: a.id,
    createdAt: Date.now(),
  });
  await log(a, 'KIOSK_PROFILE_CREATED', `${name} -> ${rel.version}`);
  return `Profile ${name} created as canary.`;
}

export async function promote(a, k) {
  need(a, 'kiosk.manage');
  if (k.status !== 'canary') fail('Only canary profiles can be promoted.');
  const rel = await get('releases', k.releaseId);
  if (!rel || rel.status === 'revoked' || rel.status === 'candidate') {
    fail('The linked release is not approved.');
  }
  if (!(await verifyRelease(rel))) fail('Release signature failed verification.');
  await put('kiosks', { ...k, status: 'stable' });
  await log(a, 'KIOSK_PROMOTED', k.name);
  return `${k.name} is stable.`;
}

export async function retire(a, k, reason) {
  need(a, 'kiosk.manage');
  await put('kiosks', { ...k, status: 'retired' });
  await log(a, 'KIOSK_RETIRED', `${k.name}: ${reason}`);
}

export async function assignToCenter(a, k, centerId) {
  need(a, 'kiosk.manage');
  if (k.status === 'retired') fail('Retired profiles cannot be assigned.');
  const c = await get('centers', centerId);
  if (!c || c.tenantId !== k.tenantId) fail('Pick a center.');
  const devs = (await all('devices')).filter((d) => d.centerId === centerId && d.status === 'enrolled');
  if (!devs.length) fail('No enrolled devices at that center.');
  await putMany('devices', devs.map((d) => ({ ...d, kioskId: k.id })));
  await log(a, 'KIOSK_ASSIGNED', `${k.name} -> ${c.code} (${devs.length})`);
  return `${k.name} assigned to ${devs.length} device(s) at ${c.code}.`;
}
