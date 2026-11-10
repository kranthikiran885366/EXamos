import { useMemo, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import { useLoad, usePerm } from '../../core/ui/hooks';
import { listCenters as listBackendCenters } from '../centers/service';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash,
  Empty, Icon, Progress, Tabs,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  transition, nextSteps, duplicateExam, TYPES, LIFECYCLE, LIFECYCLE_LABEL, examCounts, conflicts,
} from './service';
import * as Api from '../../core/api/services';

const STEP_LABEL = {
  configured: 'Configure',
  pending_approval: 'Submit for review',
  review: 'Submit for review',
  draft: 'Return to draft',
  approved: 'Approve',
  scheduled: 'Schedule & publish',
  published: 'Publish',
  ready: 'Mark ready',
  in_progress: 'Start exam',
  live: 'Go live',
  closed: 'Close & score',
  finalized: 'Finalize & lock',
  cancelled: 'Cancel exam',
};
const STEP_PERM = {
  approved: 'exam.approve',
  ready: 'exam.operate',
  in_progress: 'exam.operate',
  live: 'exam.operate',
  closed: 'exam.operate',
  finalized: 'exam.manage',
};
const REASON = new Set(['live', 'in_progress', 'cancelled', 'draft']);
const configFromApi = (value) => {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch { /* Older records may have no persisted configuration. */ }
  }
  return {};
};

function useInstitutionCenters(tenantId) {
  return useLoad(() => tenantId ? listBackendCenters(tenantId) : Promise.resolve([]), [tenantId]);
}

export default function ExamsPage() {
  const { user } = useAuth();
  const { tenantId } = useTenant();
  const may = usePerm();
  const navigate = useNavigate();
  const [backendExams, setBackendExams] = useState(null); // null = not yet fetched
  const [seatedByExam, setSeatedByExam] = useState({});
  const [fetchError, setFetchError] = useState('');
  const [assignmentError, setAssignmentError] = useState('');
  const { data: centerData, error: centersError } = useInstitutionCenters(tenantId);
  const centers = Array.isArray(centerData) ? centerData : [];

  useEffect(() => {
    let cancelled = false;
    setFetchError('');
    const fetchExams = async () => {
      try {
        const res = await Api.listExaminations();
        const list = res?.examinations || res?.exams || (Array.isArray(res) ? res : []);
        if (!Array.isArray(list)) throw new Error('The backend returned an invalid examination list.');
        if (!cancelled) {
          // Map backend field names to frontend shape, sync to local cache
          const scopedList = tenantId ? list.filter((exam) => exam.institution_id === tenantId) : list;
          const mapped = scopedList.map((e) => {
            const config = configFromApi(e.exam_config);
            return ({
            ...config,
            id: e.id,
            tenantId: e.institution_id,
            code: config.code || e.code,
            title: config.title || e.name || e.title,
            type: config.type || e.exam_type || e.type || 'final',
            course: config.course || e.subject || e.course || '',
            academicYear: config.academicYear || e.academic_year || e.academicYear || '',
            status: e.status || 'draft',
            startAt: config.startAt || e.scheduled_start || e.start_time || e.startAt || 0,
            durationMin: config.durationMin || e.duration_minutes || e.durationMin || 60,
            timeZone: config.timezone || config.timeZone || 'Asia/Kolkata',
            examUrl: config.examUrl || e.exam_url || e.examUrl || '',
            instructions: config.instructions || e.instructions || '',
            origins: config.origins || (e.allowed_origins || '').split(',').filter(Boolean),
            policyId: config.policyId || e.policy_id || e.policyId || null,
            centerIds: Array.isArray(config.centerIds)
              ? config.centerIds
              : Array.isArray(e.center_ids) ? e.center_ids
                : Array.isArray(e.centerIds) ? e.centerIds : [],
            createdBy: e.created_by || e.createdBy || '',
            createdAt: e.created_at || e.createdAt || 0,
            updatedAt: e.updated_at || e.updatedAt || 0,
            version: e.version || 1,
            history: e.history || [],
            });
          });
          setBackendExams(mapped);
        }
      } catch (error) {
        if (!cancelled) {
          setBackendExams([]);
          setFetchError(error.message || 'Could not load examinations from the backend.');
        }
      }
    };
    fetchExams();
    return () => { cancelled = true; };
  }, [tenantId]);

  useEffect(() => {
    let active = true;
    if (!backendExams) return () => { active = false; };
    setAssignmentError('');
    Promise.all(backendExams.map(async (exam) => [
      exam.id,
      (await Api.listExaminationStudents(exam.id)).length,
    ])).then((entries) => {
      if (active) setSeatedByExam(Object.fromEntries(entries));
    }).catch((error) => {
      if (active) {
        setSeatedByExam({});
        setAssignmentError(error.message || 'Assigned candidate counts could not be loaded.');
      }
    });
    return () => { active = false; };
  }, [backendExams]);

  const exams = backendExams ?? [];
  const { data: policyData, error: policiesError } = useLoad(async () => {
    const response = await Api.listPolicies();
    if (!Array.isArray(response?.policies)) throw new Error('The backend returned an invalid policy response.');
    return response.policies
      .map((policy) => ({ ...policy, tenantId: policy.tenantId || policy.tenant_id }))
      .filter((policy) => policy.tenantId === tenantId);
  }, [tenantId]);
  const policies = Array.isArray(policyData) ? policyData : [];
  const { msg, setMsg, run, busy } = useFlash();
  const [pending, setPending] = useState(null);
  const [tab, setTab] = useState('all');

  const counts = useMemo(() => examCounts(exams), [exams]);
  const now = Date.now();
  const upcoming = exams.filter((e) => ['approved', 'published'].includes(e.status) && e.startAt > now).length;
  const live = exams.filter((e) => e.status === 'live').length;
  const needsReview = exams.filter((e) => e.status === 'review').length;

  const rows = useMemo(() => {
    const base = tab === 'all' ? exams : tab === 'upcoming' ? exams.filter((e) => ['approved', 'published'].includes(e.status)) : exams.filter((e) => e.status === tab);
    return [...base].sort((a, b) => b.startAt - a.startAt);
  }, [exams, tab]);

  const centerName = (id) => centers.find((c) => c.id === id)?.code || '—';
  const policyName = (id) => {
    const p = policies.find((x) => x.id === id);
    return p ? `${p.name} v${p.version}` : '—';
  };

  const advance = async (exam, to, reason) => {
    const ok = await run(() => transition(user, exam, to, reason), 'Lifecycle updated.');
    if (ok) setPending(null);
  };

  return (
    <Page
      title="Exams & schedules"
      desc="Draft → review → approved → published → live → closed. Every gate is enforced by the service, including separation of duties."
      actions={may('exam.manage') ? <button className="btn primary" onClick={() => navigate('/college/exams/new')}><Icon name="plus" size={15} /> New exam</button> : null}
    >
      <Flash msg={msg} onClose={() => setMsg(null)} />
      {fetchError && <Alert tone="danger" title="Examination list unavailable">{fetchError}</Alert>}
      {assignmentError && <Alert tone="danger" title="Assigned candidate counts unavailable">{assignmentError}</Alert>}
      {centersError && <Alert tone="danger" title="Institution centres unavailable">{centersError.message || 'Could not load active centres from the backend.'}</Alert>}
      {policiesError && <Alert tone="danger" title="Institution policies unavailable">{policiesError.message || 'Could not load policies from the backend.'}</Alert>}
      <StatGrid cols={4}>
        <Stat label="Total exams" value={exams.length} icon="exam" sub={`${counts.draft || 0} draft`} />
        <Stat label="Awaiting review" value={needsReview} icon="checklist" tone="amber" sub="Needs an approver" />
        <Stat label="Upcoming" value={upcoming} icon="clock" tone="blue" sub="Approved or published" />
        <Stat label="Live now" value={live} icon="pulse" tone={live ? 'green' : 'blue'} sub={`${counts.closed || 0} closed`} />
      </StatGrid>

      {exams.some((e) => conflicts(exams, e)) && (
        <Alert tone="warn" title="Schedule conflict">
          Two published or live exams overlap at a shared centre. Publishing a conflicting exam is blocked until the schedule is adjusted.
        </Alert>
      )}

      <Card pad>
        <Tabs
          value={tab}
          onChange={setTab}
          tabs={[
            { key: 'all', label: 'All exams', count: exams.length },
            { key: 'draft', label: 'Drafts', count: counts.draft || 0 },
            { key: 'review', label: 'Review', count: counts.review || 0 },
            { key: 'approved', label: 'Approved', count: counts.approved || 0 },
            { key: 'published', label: 'Published', count: counts.published || 0 },
            { key: 'live', label: 'Live', count: counts.live || 0 },
            { key: 'closed', label: 'Closed', count: counts.closed || 0 },
          ]}
        />
        <DataTable
          rows={rows}
          search={(e) => `${e.code} ${e.title} ${e.type} ${e.status} ${e.course || ''}`}
          filters={[
            { key: 'type', label: 'All types', options: TYPES.map((t) => ({ v: t, l: t })) },
            { key: 'status', label: 'All statuses', options: LIFECYCLE.map((s) => ({ v: s, l: LIFECYCLE_LABEL[s] })) },
          ]}
          columns={[
            { label: 'Exam', render: (e) => <><b>{e.code}</b><br /><small className="muted">{e.title}</small></> },
            { label: 'Type', key: 'type' },
            { label: 'Window', sortable: true, key: 'startAt', render: (e) => <>{fmt(e.startAt)}<br /><small className="muted">{e.durationMin} min</small></> },
            { label: 'Portal URL', render: (e) => e.examUrl ? <span className="mono sm" title={e.examUrl}>{e.examUrl.replace(/^https?:\/\//, '').slice(0, 22)}{e.examUrl.length > 22 ? '…' : ''}</span> : <span className="muted">—</span> },
            { label: 'Centres', render: (e) => <span title={e.centerIds.map(centerName).join(', ')}>{e.centerIds.length}</span> },
            { label: 'Seated', render: (e) => seatedByExam[e.id] || 0 },
            { label: 'Policy', render: (e) => policyName(e.policyId) },
            { label: 'Result', render: (e) => (e.summary ? `${e.summary.submitted}/${e.summary.assigned} · avg ${e.summary.avg}/${e.summary.total}` : '—') },
            { label: 'Status', key: 'status', badge: true },
          ]}
          actions={(e) => [
            { label: 'Open', onClick: () => navigate(`/college/exams/${e.id}`) },
            ...nextSteps(e.status)
              .filter((to) => may(STEP_PERM[to] || 'exam.manage'))
              .slice(0, 2)
              .map((to) => ({
                label: STEP_LABEL[to],
                danger: to === 'cancelled',
                disabled: busy,
                onClick: () => {
                  if (REASON.has(to)) setPending({ exam: e, to });
                  else run(() => transition(user, e, to), 'Lifecycle updated.');
                },
              })),
            { label: 'Duplicate', disabled: !may('exam.manage'), onClick: () => run(async () => {
              const copy = await duplicateExam(user, e);
              return `Duplicated as ${copy.code}.`;
            }) },
          ]}
          onRow={(e) => navigate(`/college/exams/${e.id}`)}
          empty={<Empty icon="exam" title="No exams yet">Create a draft exam, assign candidates and publish it when ready.</Empty>}
        />
      </Card>

      {pending && (
        <ActionDialog
          title={`${STEP_LABEL[pending.to]} · ${pending.exam.code}`}
          desc={pending.to === 'live'
            ? 'Starting before the window opens needs a recorded reason. Live exams lock critical configuration.'
            : pending.to === 'cancelled'
              ? 'Cancelling is permanent and notifies candidates.'
              : pending.to === 'draft'
                ? 'The exam returns to draft and must be re-reviewed before publication.'
                : 'This transition is recorded in the audit trail.'}
          confirmLabel={STEP_LABEL[pending.to]}
          danger={pending.to === 'cancelled'}
          requireReason
          onClose={() => setPending(null)}
          onConfirm={(reason) => advance(pending.exam, pending.to, reason)}
        />
      )}
    </Page>
  );
}
