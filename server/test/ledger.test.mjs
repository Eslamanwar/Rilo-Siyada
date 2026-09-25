import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Ledger, verifyEvidencePack, GENESIS, PACK_FORMAT } from '../src/ledger.js';

const KEY = 'test-install-key';

const dirs = [];
function newLedger(key = KEY) {
  const dir = mkdtempSync(join(tmpdir(), 'siyada-ledger-'));
  dirs.push(dir);
  const ledger = new Ledger({ file: join(dir, 'ledger.jsonl'), key });
  ledger.open();
  return ledger;
}

function rewrite(ledger, mutate) {
  const records = ledger.read();
  mutate(records);
  writeFileSync(ledger.file, records.map(r => JSON.stringify(r)).join('\n') + '\n');
}

const analysis = (overrides = {}) => ({
  kind:         'analysis',
  channel:      'text',
  severity:     'critical',
  policyAction: 'block',
  policyHash:   'abc123',
  findings:     [{ type: 'emirates_id', class: 'emirates_id', fingerprint: 'f0f0f0f0f0f0f0f0' }],
  ...overrides,
});

test.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });

test('each entry commits to the one before it', () => {
  const ledger = newLedger();
  const first  = ledger.append(analysis());
  const second = ledger.append(analysis({ channel: 'image' }));

  assert.equal(first.prevHash, GENESIS);
  assert.equal(second.prevHash, first.hash);
  assert.equal(second.seq, 2);
  assert.equal(ledger.verify().ok, true);
  assert.equal(ledger.verify().headHash, second.hash);
});

test('editing an entry breaks the chain at that entry', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  ledger.append(analysis({ policyAction: 'block' }));
  ledger.append(analysis());

  rewrite(ledger, records => { records[1].event.policyAction = 'allow'; });

  const result = ledger.verify();
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt.seq, 2);
  assert.match(result.brokenAt.reason, /hash does not match/);
});

test('re-hashing an edited entry still fails — the link and the seal both have to hold', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  ledger.append(analysis());

  // An editor who recomputes the hash but has no key.
  rewrite(ledger, records => {
    records[0].event.policyAction = 'allow';
    records[0].hash = new Ledger({ file: join(tmpdir(), 'unused.jsonl'), key: 'wrong-key' })
      .seal(records[0].hash); // any plausible-looking hex
  });

  assert.equal(ledger.verify().ok, false);
});

test('deleting the middle of the chain is visible', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  ledger.append(analysis());
  ledger.append(analysis());

  rewrite(ledger, records => { records.splice(1, 1); });

  const result = ledger.verify();
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt.seq, 3);
  assert.match(result.brokenAt.reason, /sequence jumped/);
});

test('a reopened ledger continues the existing chain', () => {
  const ledger = newLedger();
  const first  = ledger.append(analysis());

  const reopened = new Ledger({ file: ledger.file, key: KEY });
  reopened.open();
  assert.equal(reopened.seq, 1);
  const next = reopened.append(analysis());
  assert.equal(next.prevHash, first.hash);
  assert.equal(reopened.verify().ok, true);
});

test('the ledger refuses to become a second copy of the leak', () => {
  const ledger = newLedger();
  assert.throws(
    () => ledger.append(analysis({ findings: [{ type: 'emirates_id', value: '784-1990-1234567-1' }] })),
    /refuses raw content at event\.findings\[0\]\.value/,
  );
  assert.throws(() => ledger.append({ kind: 'analysis', text: 'the whole prompt' }), /refuses raw content/);
  assert.equal(readFileSync(ledger.file, 'utf8'), '', 'a refused event must not be written');
});

test('a fingerprint links the same value across entries without storing it', () => {
  const ledger = newLedger();
  const a = ledger.fingerprint('784-1990-1234567-1');
  const b = ledger.fingerprint('784-1990-1234567-1');
  assert.equal(a, b);
  assert.notEqual(a, ledger.fingerprint('784-1990-1234567-2'));

  const other = newLedger('a-different-install');
  assert.notEqual(a, other.fingerprint('784-1990-1234567-1'), 'fingerprints do not travel between installs');
});

test('an evidence pack carries the range, the link it hangs off, and the head', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  const second = ledger.append(analysis());
  const third  = ledger.append(analysis({ kind: 'release', outcome: 'released' }));

  const pack = ledger.evidencePack({
    from: second.ts,
    caseId: 'CASE-7',
    requestedBy: 'dpo@ehs.gov.ae',
    policy: { policy: { organization: 'EHS', version: 1 }, hash: 'policyhash', path: '/p.yaml', error: null },
  });

  assert.equal(pack.format, PACK_FORMAT);
  assert.equal(pack.chain.startsAfter, pack.records[0].prevHash);
  assert.equal(pack.chain.headHash, third.hash);
  assert.equal(pack.chain.totalRecords, 3);
  assert.equal(pack.policy.organization, 'EHS');
  assert.equal(pack.caseId, 'CASE-7');

  const result = verifyEvidencePack(pack, { key: KEY });
  assert.equal(result.ok, true, result.problems.join('; '));
  assert.equal(result.seal, 'valid');
});

test('a pack verifies without the key, seals aside', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  const result = verifyEvidencePack(ledger.evidencePack({}));
  assert.equal(result.ok, true);
  assert.equal(result.seal, 'unchecked');
});

test('a pack edited after export fails verification', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  ledger.append(analysis());

  const edited = structuredClone(ledger.evidencePack({ caseId: 'CASE-9' }));
  edited.records[1].event.policyAction = 'allow';
  const result = verifyEvidencePack(edited, { key: KEY });
  assert.equal(result.ok, false);
  assert.ok(result.problems.some(p => /chain broken at record 2/.test(p)), result.problems.join('; '));
  assert.ok(result.problems.some(p => /records hash/.test(p)));
});

test('dropping an inconvenient entry from a pack fails verification', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  ledger.append(analysis({ kind: 'release', outcome: 'released' }));
  ledger.append(analysis());

  const trimmed = structuredClone(ledger.evidencePack({}));
  trimmed.records.splice(1, 1);
  assert.equal(verifyEvidencePack(trimmed, { key: KEY }).ok, false);
});

test('rewriting the pack header fails even when the records are untouched', () => {
  const ledger = newLedger();
  ledger.append(analysis());

  const forged = structuredClone(ledger.evidencePack({ caseId: 'CASE-1' }));
  forged.caseId = 'CASE-2';
  const result = verifyEvidencePack(forged, { key: KEY });
  assert.equal(result.ok, false);
  assert.ok(result.problems.some(p => /pack hash/.test(p)));
});

test('a pack resealed under another key names the key that sealed it', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  const pack = ledger.evidencePack({});

  const result = verifyEvidencePack(pack, { key: 'not-the-install-key' });
  assert.equal(result.seal, 'invalid');
  assert.equal(result.keyId, ledger.keyId);
});

test('an empty range still produces a checkable pack', () => {
  const ledger = newLedger();
  ledger.append(analysis());
  const pack = ledger.evidencePack({ from: Date.now() + 60_000 });
  assert.equal(pack.records.length, 0);
  assert.equal(pack.chain.startsAfter, GENESIS);
  assert.equal(verifyEvidencePack(pack, { key: KEY }).ok, true);
});
