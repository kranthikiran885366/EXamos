import assert from 'node:assert/strict';
import test from 'node:test';
import { can } from '../src/core/security/rbac.js';

test('platform audit access is distinct from institution-scoped audit access', () => {
  assert.equal(can('superadmin', 'audit.platform'), true);
  assert.equal(can('auditor', 'audit.platform'), true);
  assert.equal(can('inst_admin', 'audit.platform'), false);
  assert.equal(can('inst_admin', 'audit.institution'), true);
  assert.equal(can('auditor', 'audit.institution'), false);
});
