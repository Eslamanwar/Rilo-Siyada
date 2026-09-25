#!/usr/bin/env node
/**
 * Verify a Siyada evidence pack offline.
 *
 * The point of the pack is that nobody has to take the server's word for it:
 * this script needs no server, no network and no policy file — only the JSON.
 *
 *   node server/tools/verify-evidence.js pack.json
 *   node server/tools/verify-evidence.js pack.json --key <install key>
 *   SIYADA_LEDGER_KEY=... node server/tools/verify-evidence.js pack.json
 *
 * Without the key the hash chain and the manifest are still checked in full;
 * only the HMAC seals are reported as unchecked. Exit code 0 means the pack
 * is internally consistent, 1 means it is not.
 */

import { readFileSync } from 'node:fs';
import { verifyEvidencePack } from '../src/ledger.js';

const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--'));
const keyIndex = args.indexOf('--key');
const key = keyIndex >= 0 ? args[keyIndex + 1] : process.env.SIYADA_LEDGER_KEY || null;

if (!file) {
  console.error('usage: verify-evidence.js <pack.json> [--key <install key>]');
  process.exit(2);
}

const pack   = JSON.parse(readFileSync(file, 'utf8'));
const result = verifyEvidencePack(pack, { key });

const range = [pack.range?.fromSeq, pack.range?.toSeq].filter(n => n != null).join('–') || 'empty';
console.log(`pack     : ${file}`);
console.log(`case     : ${pack.caseId || '(none)'}  requested by ${pack.requestedBy || '(unstated)'}`);
console.log(`generated: ${pack.generatedAt}`);
console.log(`policy   : ${pack.policy?.organization || '?'} v${pack.policy?.version ?? '?'} (${pack.policy?.hash || 'none'})`);
console.log(`records  : ${result.records} (entries ${range} of ${pack.chain?.totalRecords ?? '?'})`);
console.log(`chain    : ${result.chain.ok ? 'intact' : `BROKEN at ${result.chain.brokenAt.seq} — ${result.chain.brokenAt.reason}`}`);
console.log(`seals    : ${result.seal}${result.seal === 'unchecked' ? ' (pass --key to check)' : ''}`);
console.log(`manifest : ${result.problems.some(p => p.includes('hash')) ? 'MISMATCH' : 'matches'}`);

for (const problem of result.problems) console.log(`  ! ${problem}`);
console.log(result.ok ? '\nVERIFIED' : '\nFAILED');

process.exit(result.ok ? 0 : 1);
