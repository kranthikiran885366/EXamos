import assert from 'node:assert/strict';
import test from 'node:test';
import {
  canonicalPlan,
  displayValue,
  domainHostname,
  formatDuration,
  formatExamSchedule,
  formatStatus,
  normalizeAuthSessions,
  normalizeAuditEvents,
  normalizeExaminationDetail,
  normalizeExaminationList,
  resolvePlan,
} from '../src/core/ui/normalizers.js';
import { normalizeHttpsOrigin } from '../src/core/security/sanitize.js';

test('examination list accepts the server envelope and produces one canonical shape', () => {
  const exams = [{ id: 'exam-1' }];
  assert.deepEqual(normalizeExaminationList({ examinations: exams, total: 1 }), {
    examinations: [{
      id: 'exam-1',
      startAt: null,
      timeZone: 'Asia/Kolkata',
      startTimeState: 'missing',
      timeZoneState: 'valid',
    }],
    total: 1,
  });
  assert.deepEqual(normalizeExaminationList(exams), {
    examinations: [{
      id: 'exam-1',
      startAt: null,
      timeZone: 'Asia/Kolkata',
      startTimeState: 'missing',
      timeZoneState: 'valid',
    }],
    total: 1,
  });
});

test('examination list rejects malformed envelopes rather than showing an empty list', () => {
  assert.throws(() => normalizeExaminationList({ examinations: null }), /unexpected response/i);
});

test('canonical plan IDs normalize prefixes and preserve missing assignment', () => {
  assert.equal(canonicalPlan({ planId: 'PLAN_enterprise' }), 'enterprise');
  assert.equal(canonicalPlan({ plan: 'Standard' }), 'standard');
  assert.equal(canonicalPlan({ plan: '' }), null);
  assert.equal(resolvePlan([{ id: 'plan_enterprise', name: 'Enterprise' }], 'enterprise')?.name, 'Enterprise');
  assert.equal(resolvePlan([], 'unassigned'), null);
});

test('audit array response maps the server field names without inventing chain data', () => {
  const [event] = normalizeAuditEvents([{
    event_type: 'INSTITUTION_UPDATED',
    actor: 'admin-1',
    recorded_at: '2026-11-17T10:00:00Z',
    subject_type: 'institution',
    subject_id: 'inst-1',
  }]);
  assert.equal(event.event, 'INSTITUTION_UPDATED');
  assert.equal(event.recordedAt, '2026-11-17T10:00:00.000Z');
  assert.equal(event.subjectType, 'institution');
  assert.equal(event.subjectId, 'inst-1');
  assert.equal(event.hash, null);
  assert.equal(event.previousHash, null);
});

test('audit normalizer accepts wrapped responses and rejects incomplete event records', () => {
  assert.equal(normalizeAuditEvents({ events: [{
    event: 'EXAM_OPENED',
    ts: '2026-11-17T10:00:00Z',
  }] }).length, 1);
  assert.throws(() => normalizeAuditEvents([{ event_type: 'EXAM_OPENED' }]), /type or timestamp/i);
});

test('domain display normalizes legacy URLs without accepting a path as a domain', () => {
  assert.equal(domainHostname('vignan.ac.in'), 'vignan.ac.in');
  assert.equal(domainHostname('https://www.vignan.ac.in/'), 'www.vignan.ac.in');
  assert.equal(domainHostname('https://www.vignan.ac.in/profile'), null);
});

test('policy origins require canonical HTTPS origins', () => {
  assert.equal(normalizeHttpsOrigin('https://EXAMPLE.COM:443/'), 'https://example.com');
  for (const origin of [
    'http://example.com',
    'https://user:pass@example.com',
    'https://example.com/path',
    'https://example.com?next=/',
    'https://example.com/#fragment',
    'https://*.example.com',
    'not a URL',
  ]) {
    assert.equal(normalizeHttpsOrigin(origin), null, origin);
  }
});

test('session normalization gives account and session views the same scope and time units', () => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const sessions = normalizeAuthSessions({ sessions: [
    { id: 'current', user_id: 'user-1', status: 'active', current: true, created_at: nowSeconds, expires_at: nowSeconds + 3600 },
    { id: 'expired', user_id: 'user-1', status: 'active', expires_at: nowSeconds - 3600 },
  ] }, 'user-1');
  assert.equal(sessions[0].current, true);
  assert.equal(sessions[0].createdAt, nowSeconds * 1000);
  assert.equal(sessions[0].userId, 'user-1');
  assert.equal(sessions[1].status, 'expired');
  assert.equal(sessions.filter((session) => session.status === 'active').length, 1);
});

test('schedule adapters distinguish missing and invalid starts and honor the exam timezone', () => {
  const [exam] = normalizeExaminationList({ examinations: [{
    id: 'exam-2',
    exam_config: { startAt: '2026-11-17T10:00:00Z', timezone: 'Asia/Kolkata' },
  }] }).examinations;
  assert.equal(exam.startAt, Date.parse('2026-11-17T10:00:00Z'));
  assert.equal(exam.startTimeState, 'available');
  assert.match(formatExamSchedule(exam), /17 Nov 2026/);
  assert.equal(formatExamSchedule({ startAt: null }), 'Not scheduled');
  assert.equal(formatExamSchedule({ startAt: 'invalid' }), 'Invalid start time');
  assert.equal(formatExamSchedule({ startAt: Date.now(), timeZone: 'invalid-zone' }), 'Invalid time zone');
});

test('examination detail uses its schedule and preserves cancellation metadata', () => {
  const normalized = normalizeExaminationDetail({
    examination: {
      id: 'exam-3',
      status: 'cancelled',
      cancel_reason: 'Synthetic cancellation',
      cancelled_at: 1794912000000,
      exam_config: { startAt: 1794912000000, timezone: 'UTC' },
    },
    schedules: [{ start_time: 1794915600000, timezone: 'Asia/Kolkata' }],
  });
  assert.equal(normalized.examination.startAt, 1794915600000);
  assert.equal(normalized.examination.timeZone, 'Asia/Kolkata');
  assert.equal(normalized.examination.cancel_reason, 'Synthetic cancellation');
});

test('shared display formatters normalize missing values, statuses, and duration rollover', () => {
  assert.equal(displayValue(null), '—');
  assert.equal(displayValue(' null '), '—');
  assert.equal(formatStatus('pending_approval'), 'Pending Approval');
  assert.equal(formatDuration(72 * 60), '72h');
});
