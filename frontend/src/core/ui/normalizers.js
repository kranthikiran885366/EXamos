/** Shared contract and presentation normalizers for server response data. */
export function toEpochMs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) return null;
    return value < 100000000000 ? value * 1000 : value;
  }
  const numeric = Number(value);
  if (String(value).trim() !== '' && Number.isFinite(numeric) && numeric > 0) {
    return numeric < 100000000000 ? numeric * 1000 : numeric;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function formatTimestamp(value, { empty = 'Unknown', timeZone } = {}) {
  const epoch = toEpochMs(value);
  if (!epoch) return empty;
  return new Date(epoch).toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
    ...(timeZone ? { timeZone } : {}),
  });
}

export function formatRelativeTime(value, { empty = 'Never' } = {}) {
  const epoch = toEpochMs(value);
  if (!epoch) return empty;
  const seconds = Math.max(0, Math.round((Date.now() - epoch) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function normalizeAuthSessions(response, fallbackUserId) {
  const rows = Array.isArray(response) ? response : response?.sessions;
  if (!Array.isArray(rows)) {
    throw new Error('The session endpoint returned an unexpected response.');
  }
  return rows.map((session) => {
    if (!session || typeof session !== 'object' || Array.isArray(session)) {
      throw new Error('The session endpoint returned a malformed session.');
    }
    const createdAt = toEpochMs(session.created_at ?? session.createdAt);
    const expiresAt = toEpochMs(session.expires_at ?? session.expiresAt);
    const endedAt = toEpochMs(session.revoked_at ?? session.revokedAt ?? session.ended_at ?? session.endedAt);
    let status = session.status;
    if (!status) status = endedAt ? 'revoked' : expiresAt && expiresAt < Date.now() ? 'expired' : 'active';
    if (status === 'active' && expiresAt && expiresAt < Date.now()) status = 'expired';
    return {
      id: session.id || session.session_id || '',
      userId: session.user_id ?? session.userId ?? fallbackUserId,
      userAgent: session.user_agent || session.userAgent || 'Unknown',
      ip: session.ip_address || session.ip || '—',
      createdAt,
      lastSeen: toEpochMs(session.last_seen_at ?? session.lastSeen ?? session.created_at ?? session.createdAt),
      status,
      current: Boolean(session.current ?? session.is_current),
      reason: session.revocation_reason || session.reason || '',
      endedAt,
      expiresAt,
    };
  });
}

export function formatDuration(minutes) {
  const total = Math.max(0, Math.round(Number(minutes) || 0));
  const hours = Math.floor(total / 60);
  const remainder = total % 60;
  if (!hours) return `${remainder}m`;
  return remainder ? `${hours}h ${remainder}m` : `${hours}h`;
}

export function displayValue(value, empty = '—') {
  if (value === null || value === undefined) return empty;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed || ['null', 'undefined'].includes(trimmed.toLowerCase())) return empty;
    return trimmed;
  }
  return value;
}

export function formatStatus(value, empty = 'Unknown') {
  const display = displayValue(value, empty);
  if (display === empty) return empty;
  return String(display).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/** Return a display-safe hostname from a legacy domain or full HTTPS URL. */
export function domainHostname(value) {
  const input = String(value || '').trim().replace(/^@+/, '');
  if (!input) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  try {
    const url = new URL(candidate);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password ||
        url.port || url.hostname.includes('*') || url.pathname !== '/' || url.search || url.hash) return null;
    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function canonicalPlan(record) {
  const value = record?.planId ?? record?.plan_id ?? record?.plan ?? record?.subscription?.planId ?? null;
  if (value === null || value === undefined || String(value).trim() === '') return null;
  return String(value).trim().toLowerCase().replace(/^plan[-_]/, '');
}

export function resolvePlan(plans, planId) {
  const key = canonicalPlan({ planId });
  if (!key || !Array.isArray(plans)) return null;
  return plans.find((plan) => canonicalPlan({ planId: plan?.id }) === key) || null;
}

export function normalizeExaminationList(response) {
  const rows = Array.isArray(response)
    ? response
    : response?.examinations ?? response?.exams;
  if (!Array.isArray(rows)) {
    throw new Error('The examination endpoint returned an unexpected response.');
  }
  const examinations = rows.map((record) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('The examination endpoint returned a malformed record.');
    }
    return { ...record, ...canonicalExamSchedule(record) };
  });
  return {
    ...(Array.isArray(response) ? {} : response),
    examinations,
    total: response?.total ?? examinations.length,
  };
}

export function normalizeExaminationDetail(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    throw new Error('The examination endpoint returned an unexpected detail response.');
  }
  const record = response.examination ?? response;
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('The examination endpoint returned a malformed detail record.');
  }
  const rawConfig = record.exam_config ?? record.examConfig;
  const config = typeof rawConfig === 'string' ? JSON.parse(rawConfig) : rawConfig;
  if (config !== undefined && config !== null && (typeof config !== 'object' || Array.isArray(config))) {
    throw new Error('The examination endpoint returned malformed schedule configuration.');
  }
  const schedule = response.schedules?.[0] || {};
  const scheduleFields = {
    ...record,
    exam_config: config,
    startAt: schedule.start_time ?? record.startAt ?? record.start_at ?? record.scheduled_start ?? config?.startAt ?? config?.start_at,
    timeZone: schedule.timezone ?? record.timeZone ?? record.timezone ?? config?.timeZone ?? config?.timezone,
  };
  return {
    ...response,
    examination: { ...record, ...canonicalExamSchedule(scheduleFields) },
  };
}

export function normalizeAuditEvents(response) {
  const rows = Array.isArray(response) ? response : response?.events ?? response?.audit;
  if (!Array.isArray(rows)) {
    throw new Error('The audit endpoint returned an unexpected response.');
  }
  return rows.map((row, index) => {
    if (!row || typeof row !== 'object') {
      throw new Error('The audit endpoint returned a malformed event.');
    }
    const event = row.event_type ?? row.event;
    const recordedAt = row.recorded_at ?? row.occurred_at ?? row.created_at ?? row.ts ?? null;
    const recordedAtMs = toEpochMs(recordedAt);
    if (typeof event !== 'string' || !event.trim() || recordedAtMs === null) {
      throw new Error('The audit endpoint returned an event without its type or timestamp.');
    }
    return {
      id: row.audit_id ?? row.id ?? `${recordedAt}:${event}:${index}`,
      event: event.trim(),
      actor: row.actor || 'Unknown',
      recordedAt: new Date(recordedAtMs).toISOString(),
      subjectType: row.subject_type || '',
      subjectId: row.subject_id || '',
      detail: row.detail ?? row.description ?? '',
      sequence: row.seq ?? null,
      previousHash: row.prev ?? row.prev_hash ?? null,
      hash: row.hash ?? row.chain_hash ?? null,
    };
  });
}

export function canonicalExamSchedule(record) {
  const config = record?.exam_config ?? record?.examConfig ?? {};
  const raw = record?.startAt ?? record?.start_at ?? record?.scheduled_start ?? record?.scheduledStart ??
    record?.start_time ?? record?.startTime ?? config?.startAt ?? config?.start_at ?? config?.start_time ?? null;
  const timeZone = record?.timeZone ?? record?.timezone ?? config?.timeZone ?? config?.timezone ?? 'Asia/Kolkata';
  const startAt = toEpochMs(raw);
  let validTimeZone = true;
  try { new Intl.DateTimeFormat('en-US', { timeZone }).format(0); } catch { validTimeZone = false; }
  return {
    startAt,
    timeZone,
    startTimeState: raw === null || raw === undefined || raw === '' ? 'missing' : startAt === null ? 'invalid' : 'available',
    timeZoneState: validTimeZone ? 'valid' : 'invalid',
  };
}

export function formatExamSchedule(record) {
  const schedule = canonicalExamSchedule(record);
  if (schedule.startTimeState === 'missing') return 'Not scheduled';
  if (schedule.startTimeState === 'invalid') return 'Invalid start time';
  if (schedule.timeZoneState === 'invalid') return 'Invalid time zone';
  return formatTimestamp(schedule.startAt, { timeZone: schedule.timeZone, empty: 'Start time unavailable' });
}
