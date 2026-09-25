import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseYaml } from '../src/yaml.js';

test('parses the shapes a policy file actually uses', () => {
  const doc = parseYaml(`
# a comment on its own line
version: 1
organization: "Emirates Health Services"   # and a trailing one
enabled: true
missing: ~
justification:
  min_length: 30
classes:
  credentials:
    action: block
    matches: [password, api_key]
  identity:
    action: redact
    matches:
      - name
      - email
approvers:
  - email: dpo@ehs.gov.ae
    role: DPO
  - email: ciso@ehs.gov.ae
    role: CISO
`);

  assert.equal(doc.version, 1);
  assert.equal(doc.organization, 'Emirates Health Services');
  assert.equal(doc.enabled, true);
  assert.equal(doc.missing, null);
  assert.equal(doc.justification.min_length, 30);
  assert.deepEqual(doc.classes.credentials.matches, ['password', 'api_key']);
  assert.deepEqual(doc.classes.identity.matches, ['name', 'email']);
  assert.deepEqual(doc.approvers, [
    { email: 'dpo@ehs.gov.ae', role: 'DPO' },
    { email: 'ciso@ehs.gov.ae', role: 'CISO' },
  ]);
});

test('an empty flow list is a list, not a string', () => {
  assert.deepEqual(parseYaml('matches: []').matches, []);
});

test('an empty document is an empty map rather than a crash', () => {
  assert.deepEqual(parseYaml('# nothing but a comment\n'), {});
});
