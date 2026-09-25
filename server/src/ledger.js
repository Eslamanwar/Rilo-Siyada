/**
 * Hash-chained audit ledger and evidence packs.
 *
 * A compliance log that can be edited is a log nobody has to believe. Every
 * entry here commits to the entry before it:
 *
 *   hash(n) = sha256( seq | ts | hash(n-1) | canonical(event) )
 *
 * so changing, reordering or deleting one entry invalidates every entry after
 * it. The chain is plain SHA-256, which means an auditor with the file and no
 * secret can recompute it. On top of that each entry carries an HMAC seal under
 * an install-local key, so rewriting the whole chain — the one attack a public
 * hash chain does not stop — also requires the key.
 *
 * What the ledger deliberately does NOT hold: the sensitive values themselves.
 * An audit trail of leaks must not become a second copy of the leak, so events
 * carry a keyed fingerprint of each value and `append` refuses any event that
 * still contains raw content.
 *
 * An evidence pack is a slice of the chain plus everything needed to check it
 * offline: the link it continues from, the head it ends at, the policy that
 * governed the decisions, and a sealed manifest over the whole document.
 * `server/tools/verify-evidence.js` re-verifies a pack with no server running.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { dirname, resolve as resolvePath } from 'node:path';

export const GENESIS     = '0'.repeat(64);
export const PACK_FORMAT = 'siyada-evidence/1';
export const HASH_DOMAIN = 'siyada-ledger/1';

// Content that must never reach disk, whatever the caller thinks it is doing.
const RAW_CONTENT_KEYS = new Set(['value', 'text', 'redactedText', 'imageBase64', 'raw']);

/** Deterministic JSON: object keys sorted, so a hash depends on content only. */
export function canonical(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter(k => value[k] !== undefined).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

function equalHex(a, b) {
  const x = Buffer.from(String(a), 'utf8');
  const y = Buffer.from(String(b), 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

export function recordHash({ seq, ts, prevHash, event }) {
  return sha256(`${HASH_DOMAIN}\n${seq}\n${ts}\n${prevHash}\n${canonical(event)}`);
}

function assertRedacted(node, path = 'event') {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    node.forEach((child, i) => assertRedacted(child, `${path}[${i}]`));
    return;
  }
  for (const [key, child] of Object.entries(node)) {
    if (RAW_CONTENT_KEYS.has(key)) {
      throw new Error(`ledger refuses raw content at ${path}.${key} — fingerprint it instead`);
    }
    assertRedacted(child, `${path}.${key}`);
  }
}

/** Install-local key: explicit, from the environment, or generated once on disk. */
function resolveKey({ key, keyFile }) {
  if (key) return String(key);
  if (process.env.SIYADA_LEDGER_KEY) return process.env.SIYADA_LEDGER_KEY;
  if (existsSync(keyFile)) return readFileSync(keyFile, 'utf8').trim();
  const generated = randomBytes(32).toString('hex');
  mkdirSync(dirname(keyFile), { recursive: true });
  writeFileSync(keyFile, `${generated}\n`, { mode: 0o600 });
  return generated;
}

export class Ledger {
  constructor({ file, key = null, keyFile = null } = {}) {
    this.file    = resolvePath(file);
    this.keyFile = resolvePath(keyFile || `${this.file}.key`);
    this.key     = resolveKey({ key, keyFile: this.keyFile });
    this.keyId   = sha256(this.key).slice(0, 12);
    this.seq     = 0;
    this.head    = GENESIS;
    this.integrity = { ok: true, count: 0, brokenAt: null };
    this.lastVerification = null;
    this.verifiedAt = 0;
  }

  /** Load an existing chain and verify it before accepting new entries. */
  open() {
    mkdirSync(dirname(this.file), { recursive: true });
    if (!existsSync(this.file)) writeFileSync(this.file, '', { flag: 'a' });
    const result = this.verify();
    this.integrity = result;
    const last = result.headSeq > 0 ? result : null;
    this.seq  = last ? result.headSeq : 0;
    this.head = last ? result.headHash : GENESIS;
    return result;
  }

  seal(hash) {
    return createHmac('sha256', this.key).update(hash).digest('hex');
  }

  /** Keyed, so the same value is traceable across events but not recoverable. */
  fingerprint(value) {
    return createHmac('sha256', this.key).update(`fp:${String(value)}`).digest('hex').slice(0, 16);
  }

  append(event) {
    assertRedacted(event);
    const seq      = this.seq + 1;
    const ts       = Date.now();
    const prevHash = this.head;
    const hash     = recordHash({ seq, ts, prevHash, event });
    const record   = { seq, ts, prevHash, hash, seal: this.seal(hash), event };

    appendFileSync(this.file, `${JSON.stringify(record)}\n`);
    this.seq  = seq;
    this.head = hash;
    this.integrity = { ...this.integrity, count: this.integrity.count + 1, headSeq: seq, headHash: hash };
    this.lastVerification = null;
    return record;
  }

  read() {
    if (!existsSync(this.file)) return [];
    return readFileSync(this.file, 'utf8')
      .split('\n')
      .filter(line => line.trim())
      .map((line, i) => {
        try { return JSON.parse(line); }
        catch { throw new Error(`ledger line ${i + 1} is not valid JSON`); }
      });
  }

  /**
   * Recompute the whole chain from the file.
   * Returns the first break rather than throwing — a broken ledger is a finding
   * to report, not a crash.
   */
  verify() {
    let records;
    try { records = this.read(); }
    catch (err) { return { ok: false, count: 0, headSeq: 0, headHash: GENESIS, brokenAt: { seq: null, reason: String(err.message) } }; }

    const chain = verifyChain(records, GENESIS, (hash) => this.seal(hash));
    const last  = records[records.length - 1];
    this.verifiedAt = Date.now();
    return (this.lastVerification = {
      ok:       chain.ok,
      count:    records.length,
      headSeq:  last ? last.seq : 0,
      headHash: last ? last.hash : GENESIS,
      brokenAt: chain.brokenAt,
      keyId:    this.keyId,
    });
  }

  /** Re-hashing the whole file on every dashboard poll is wasteful; this isn't. */
  verifyCached(maxAgeMs = 30_000) {
    if (this.lastVerification && Date.now() - this.verifiedAt < maxAgeMs) {
      return { ...this.lastVerification, cachedAt: this.verifiedAt };
    }
    return this.verify();
  }

  /**
   * A self-contained, offline-verifiable export of a slice of the chain.
   * `from` and `to` are epoch ms, both ends inclusive, both optional.
   * `startsAfter` is the link the slice hangs off, so an auditor can see the
   * range was cut from the chain rather than assembled.
   */
  evidencePack({ from, to, caseId = '', requestedBy = '', policy = null } = {}) {
    const all      = this.read();
    const selected = all.filter(r =>
      r.ts >= (from ?? 0) && r.ts <= (to ?? Number.MAX_SAFE_INTEGER));
    const first    = selected[0];
    const before   = first ? all.find(r => r.seq === first.seq - 1) : null;
    const chainState = this.verify();

    const body = {
      format:      PACK_FORMAT,
      caseId:      String(caseId || ''),
      requestedBy: String(requestedBy || ''),
      generatedAt: new Date().toISOString(),
      range: {
        from: from ?? null,
        to:   to ?? null,
        fromSeq: first ? first.seq : null,
        toSeq:   selected.length ? selected[selected.length - 1].seq : null,
      },
      policy: policy
        ? {
            organization: policy.policy?.organization ?? null,
            version:      policy.policy?.version ?? null,
            hash:         policy.hash ?? null,
            path:         policy.path ?? null,
            error:        policy.error ?? null,
          }
        : null,
      chain: {
        algorithm:    'sha256',
        sealAlgorithm:'hmac-sha256',
        domain:       HASH_DOMAIN,
        genesis:      GENESIS,
        startsAfter:  first ? first.prevHash : GENESIS,
        totalRecords: all.length,
        headSeq:      chainState.headSeq,
        headHash:     chainState.headHash,
        verifiedAtExport: chainState.ok,
      },
      records: selected,
    };

    const recordsHash = sha256(canonical(selected));
    const packHash    = sha256(canonical({ ...body, recordsHash }));

    return {
      ...body,
      manifest: {
        recordsHash,
        packHash,
        seal:  this.seal(packHash),
        keyId: this.keyId,
      },
    };
  }
}

/** Walk a list of records and check each hash and each backward link. */
export function verifyChain(records, startsAfter = GENESIS, sealOf = null) {
  let prevHash = startsAfter;
  let prevSeq  = records.length ? records[0].seq - 1 : 0;

  for (const r of records) {
    if (r.seq !== prevSeq + 1) {
      return { ok: false, brokenAt: { seq: r.seq, reason: `sequence jumped from ${prevSeq} to ${r.seq}` } };
    }
    if (r.prevHash !== prevHash) {
      return { ok: false, brokenAt: { seq: r.seq, reason: 'prevHash does not match the previous record' } };
    }
    if (!equalHex(recordHash(r), r.hash)) {
      return { ok: false, brokenAt: { seq: r.seq, reason: 'record hash does not match its contents' } };
    }
    if (sealOf && !equalHex(sealOf(r.hash), r.seal)) {
      return { ok: false, brokenAt: { seq: r.seq, reason: 'seal does not match — record was re-hashed without the key' } };
    }
    prevHash = r.hash;
    prevSeq  = r.seq;
  }
  return { ok: true, brokenAt: null };
}

/**
 * Verify an evidence pack with nothing but the pack itself.
 * Without the install key the chain and the manifest are still checked — only
 * the seals are reported as unchecked.
 */
export function verifyEvidencePack(pack, { key = null } = {}) {
  const problems = [];
  if (pack?.format !== PACK_FORMAT) problems.push(`unknown pack format "${pack?.format}"`);

  const records  = Array.isArray(pack?.records) ? pack.records : [];
  const sealOf   = key ? (hash) => createHmac('sha256', String(key)).update(hash).digest('hex') : null;
  const chain    = verifyChain(records, pack?.chain?.startsAfter ?? GENESIS, sealOf);
  if (!chain.ok) problems.push(`chain broken at record ${chain.brokenAt.seq}: ${chain.brokenAt.reason}`);

  const { manifest, ...body } = pack || {};
  const recordsHash = sha256(canonical(records));
  if (!equalHex(recordsHash, manifest?.recordsHash ?? '')) problems.push('records hash does not match the manifest');

  const packHash = sha256(canonical({ ...body, recordsHash: manifest?.recordsHash }));
  if (!equalHex(packHash, manifest?.packHash ?? '')) problems.push('pack hash does not match the manifest');

  let seal = 'unchecked';
  if (key) {
    const expected = createHmac('sha256', String(key)).update(String(manifest?.packHash ?? '')).digest('hex');
    seal = equalHex(expected, manifest?.seal ?? '') ? 'valid' : 'invalid';
    if (seal === 'invalid') problems.push('manifest seal does not match — wrong key or a forged pack');
  }

  return {
    ok:       problems.length === 0,
    records:  records.length,
    range:    pack?.range ?? null,
    chain:    { ok: chain.ok, brokenAt: chain.brokenAt, startsAfter: pack?.chain?.startsAfter ?? null },
    seal,
    keyId:    manifest?.keyId ?? null,
    problems,
  };
}

// ─── Process-wide ledger ──────────────────────────────────────────────────────

let current = null;

export function openLedger(file, options = {}) {
  current = new Ledger({ file, ...options });
  current.open();
  return current;
}

export function getLedger() {
  return current;
}
