import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeExamUsageSummary } from '../src/modules/billing/usage.js';

test('exam usage summary requires validated server counts and exposes non-exam billing transparently', () => {
  assert.deepEqual(normalizeExamUsageSummary([
    { key: 'created', value: 6 },
    { key: 'published', value: 3 },
    { key: 'attempted', value: 2 },
    { key: 'completed', value: 1 },
  ]), {
    created: 6,
    published: 3,
    attempted: 2,
    completed: 1,
    billable: null,
  });
  assert.throws(() => normalizeExamUsageSummary([{ key: 'created', value: -1 }]), /invalid created/);
  assert.throws(() => normalizeExamUsageSummary([{ key: 'created', value: 1 }, { key: 'created', value: 2 }]), /malformed/);
});
