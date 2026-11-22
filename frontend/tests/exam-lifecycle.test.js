import assert from 'node:assert/strict';
import test from 'node:test';
import { deriveLifecycleMilestone } from '../src/modules/exams/lifecycle.js';

test('cancellation stops lifecycle progress at the last recorded transition', () => {
  assert.equal(deriveLifecycleMilestone({
    status: 'cancelled',
    history: [{ to: 'draft' }, { to: 'cancelled' }],
  }), 0);
  assert.equal(deriveLifecycleMilestone({
    status: 'cancelled',
    history: [{ to: 'draft' }, { to: 'pending_approval' }, { to: 'approved' }, { to: 'cancelled' }],
  }), 2);
});

test('current status is used when transition history is absent and unknown stages do not poison progress', () => {
  assert.equal(deriveLifecycleMilestone({ status: 'approved' }), 2);
  assert.equal(deriveLifecycleMilestone({ status: 'unknown', history: [{ to: 'draft' }] }), 0);
});
