import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { usePerm } from '../../core/ui/hooks';
import {
  Page, Card, Stat, StatGrid, DataTable, Badge, Alert, ActionDialog, useFlash, Flash,
  Empty, Icon, Progress, Tabs,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  transition, nextSteps, duplicateExam, TYPES, LIFECYCLE, LIFECYCLE_LABEL, examCounts, conflicts,
} from './service';

const STEP_LABEL = {
  review: 'Submit for review', draft: 'Return to draft', approved: 'Approve', published: 'Publish',
  live: 'Go live', closed: 'Close & score', cancelled: 'Cancel exam',
};
const STEP_PERM = { approved: 'exam.approve', live: 'exam.operate', closed: 'exam.operate' };
const REASON = new Set(['live', 'cancelled', 'draft']);

export default function ExamsPage() {
  const { user } = useAuth();
  const may = usePerm();
  const navigate = useNavigate();
  const exams = useCol('exams');
  const centers = useCol('centers');
  const policies = useCol('policies');
  const candidates = useCol('candidates');
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
            { label: 'Centres', render: (e) => <span title={e.centerIds.map(centerName).join(', ')}>{e.centerIds.length}</span> },
            { label: 'Seated', render: (e) => candidates.filter((c) => c.examId === e.id).length },
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
