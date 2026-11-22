const MILESTONE_INDEX = Object.freeze({
  draft: 0, configured: 0, pending_approval: 1, review: 1, approved: 2,
  scheduled: 3, published: 3, ready: 3, in_progress: 4, live: 4, closed: 5, finalized: 5,
});

export function deriveLifecycleMilestone(exam) {
  const history = Array.isArray(exam?.history) ? exam.history : [];
  const reached = history
    .map((entry) => MILESTONE_INDEX[entry?.to ?? entry?.to_status])
    .filter(Number.isInteger);
  const current = exam?.status === 'cancelled' ? null : MILESTONE_INDEX[exam?.status];
  if (Number.isInteger(current)) reached.push(current);
  return Math.max(0, ...reached);
}
