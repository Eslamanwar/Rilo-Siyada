import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadPolicy, evaluate, checkRelease, classify, RELEASE_WINDOW_MS } from '../src/policy.js';

const POLICY = `
version: 3
organization: "Test Authority"
default_action: redact
justification:
  min_length: 20
classes:
  credentials:
    action: block
    matches: [password, api_key]
  emirates_id:
    action: break_glass
    matches: [emirates_id, passport]
    approvers: [dpo@test.ae, ciso@test.ae, legal@test.ae]
    min_approvals: 2
  financial:
    action: allow_with_justification
    matches: [iban, bank_account]
  identity:
    action: redact
    matches: [name, email, face]
channels:
  image:
    emirates_id: block
`;

let dir;
function withPolicy(text) {
  dir ??= mkdtempSync(join(tmpdir(), 'siyada-policy-'));
  const path = join(dir, 'siyada-policy.yaml');
  writeFileSync(path, text);
  return loadPolicy(path);
}

test.after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

test('a loaded policy is hashed so a decision names the text that produced it', () => {
  const a = withPolicy(POLICY);
  assert.equal(a.error, null);
  assert.match(a.hash, /^[0-9a-f]{16}$/);

  const b = withPolicy(`${POLICY}\n# an auditor added a note\n`);
  assert.notEqual(b.hash, a.hash, 'editing the file must change the hash');
  withPolicy(POLICY);
});

test('model-authored type names are normalised onto classes', () => {
  withPolicy(POLICY);
  assert.equal(classify('Emirates ID'), 'emirates_id');
  assert.equal(classify('API-Key'), 'credentials');
  assert.equal(classify('shoe size'), null);
});

test('the strictest action across the findings governs the message', () => {
  withPolicy(POLICY);
  const d = evaluate([{ type: 'name' }, { type: 'iban' }, { type: 'emirates_id' }]);
  assert.equal(d.action, 'break_glass');
  assert.equal(d.minApprovals, 2);
  assert.deepEqual(d.rules.map(r => r.action),
    ['redact', 'allow_with_justification', 'break_glass']);
});

test('an unmatched finding falls to the default action, not to allow', () => {
  withPolicy(POLICY);
  const d = evaluate([{ type: 'shoe size' }]);
  assert.equal(d.action, 'redact');
  assert.equal(d.rules[0].class, 'unclassified');
});

test('a channel can tighten a class without touching the other channel', () => {
  withPolicy(POLICY);
  assert.equal(evaluate([{ type: 'emirates_id' }], 'text').action, 'break_glass');
  assert.equal(evaluate([{ type: 'emirates_id' }], 'image').action, 'block');
});

test('a missing policy file blocks everything', () => {
  const state = loadPolicy(join(tmpdir(), 'siyada-does-not-exist.yaml'));
  assert.match(state.error, /no policy file/);
  assert.equal(evaluate([{ type: 'name' }]).action, 'block');
});

test('a malformed policy blocks everything rather than degrading to allow', () => {
  const state = withPolicy('version: 1\nclasses:\n  identity:\n    action: maybe\n');
  assert.match(state.error, /unknown action "maybe"/);
  assert.equal(evaluate([{ type: 'name' }]).action, 'block');
});

test('break_glass without enough named approvers is rejected at load', () => {
  const state = withPolicy(`
version: 1
classes:
  identity:
    action: break_glass
    matches: [name]
    approvers: [only@test.ae]
    min_approvals: 2
`);
  assert.match(state.error, /lists 1 of 2 approvers/);
});

test('redact and allow need no ceremony to be released', () => {
  withPolicy(POLICY);
  assert.equal(checkRelease(evaluate([{ type: 'name' }])).granted, true);
});

test('block cannot be released at all', () => {
  withPolicy(POLICY);
  const verdict = checkRelease(evaluate([{ type: 'password' }]), {
    justification: 'the client urgently needs this and my manager said it is fine',
    approvals: ['dpo@test.ae', 'ciso@test.ae'],
  });
  assert.deepEqual(verdict, { granted: false, error: 'blocked_by_policy' });
});

test('a justification shorter than the policy minimum is refused', () => {
  withPolicy(POLICY);
  const decision = evaluate([{ type: 'iban' }]);
  assert.equal(checkRelease(decision, { justification: 'need it' }).error, 'justification_required');
  assert.equal(
    checkRelease(decision, { justification: 'Reconciling the customer statement for ticket 4471' }).granted,
    true,
  );
});

test('break-glass needs two distinct authorised approvers', () => {
  withPolicy(POLICY);
  const decision = evaluate([{ type: 'emirates_id' }]);
  const justification = 'Court order 88/2026 requires the unredacted identity document';

  const one = checkRelease(decision, { justification, approvals: ['dpo@test.ae'] });
  assert.equal(one.error, 'approval_required');
  assert.equal(one.received, 1);

  const duplicate = checkRelease(decision, { justification, approvals: ['dpo@test.ae', 'DPO@test.ae'] });
  assert.equal(duplicate.error, 'approval_required', 'the same person twice is one approval');

  const outsider = checkRelease(decision, { justification, approvals: ['dpo@test.ae', 'intern@test.ae'] });
  assert.equal(outsider.error, 'approval_required', 'an unlisted approver does not count');

  const granted = checkRelease(decision, { justification, approvals: ['dpo@test.ae', 'ciso@test.ae'] });
  assert.equal(granted.granted, true);
  assert.deepEqual(granted.approvedBy.sort(), ['ciso@test.ae', 'dpo@test.ae']);
});

test('the requester cannot approve their own break-glass', () => {
  withPolicy(POLICY);
  const decision = evaluate([{ type: 'passport' }]);
  const verdict = checkRelease(decision, {
    justification: 'Court order 88/2026 requires the unredacted identity document',
    approvals: ['dpo@test.ae', 'ciso@test.ae'],
    requester: 'DPO@test.ae',
  });
  assert.equal(verdict.error, 'approval_required');
  assert.equal(verdict.received, 1);
});

test('an approval granted long enough ago no longer releases anything', () => {
  withPolicy(POLICY);
  const decision = evaluate([{ type: 'iban' }]);
  decision.issuedAt -= RELEASE_WINDOW_MS + 1;
  assert.equal(
    checkRelease(decision, { justification: 'Reconciling the customer statement for ticket 4471' }).error,
    'decision_expired',
  );
});

test('an unknown decision is refused', () => {
  assert.equal(checkRelease(undefined).error, 'unknown_decision');
});
