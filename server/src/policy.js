/**
 * Policy as code.
 *
 * Detection answers "what is in this data". Policy answers "what is this
 * organisation allowed to do with it" — and that answer belongs to the DPO in a
 * reviewable file, not to a constant in the extension.
 *
 * Every detected item is mapped to a data class, every class carries an action,
 * and the strictest action across the findings governs the whole message:
 *
 *   allow < redact < allow_with_justification < break_glass < block
 *
 * The file is hashed on load; the hash goes into every decision and every audit
 * event, so an event can be tied to the exact policy text that produced it.
 */

import { readFileSync, watch, existsSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { parseYaml } from './yaml.js';

export const ACTIONS = ['allow', 'redact', 'allow_with_justification', 'break_glass', 'block'];

// A decision is short-lived: an approval granted this morning must not release
// data this evening.
export const RELEASE_WINDOW_MS = 10 * 60_000;

const strictest = (a, b) => (ACTIONS.indexOf(a) >= ACTIONS.indexOf(b) ? a : b);

// Detector types are model-authored free text ("Emirates ID", "api key"), so
// normalise before matching them against the policy's class definitions.
const normalize = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');

const FALLBACK_POLICY = {
  version: 0,
  organization: 'unconfigured',
  default_action: 'block', // no policy file means nothing is released
  classes: {},
};

let active = { policy: FALLBACK_POLICY, hash: 'none', path: null, error: 'not loaded' };

export function loadPolicy(path) {
  if (!existsSync(path)) {
    active = { policy: FALLBACK_POLICY, hash: 'none', path, error: `no policy file at ${path}` };
    return active;
  }
  try {
    const text   = readFileSync(path, 'utf8');
    const parsed = parseYaml(text);
    validate(parsed);
    active = {
      policy: parsed,
      hash:   createHash('sha256').update(text).digest('hex').slice(0, 16),
      path,
      error:  null,
    };
  } catch (err) {
    // A malformed policy must not silently degrade into "allow everything".
    active = { policy: FALLBACK_POLICY, hash: 'none', path, error: String(err?.message ?? err) };
  }
  return active;
}

// Reload on edit, so a policy change is a file save rather than a deployment.
export function watchPolicy(path, onReload = () => {}) {
  if (!existsSync(path)) return;
  let pending = null;
  watch(path, () => {
    clearTimeout(pending);
    pending = setTimeout(() => onReload(loadPolicy(path)), 100);
  }).unref?.();
}

function validate(policy) {
  if (!policy || typeof policy !== 'object') throw new Error('policy must be a map');
  if (policy.default_action && !ACTIONS.includes(policy.default_action)) {
    throw new Error(`unknown default_action "${policy.default_action}"`);
  }
  for (const [name, rule] of Object.entries(policy.classes || {})) {
    if (!ACTIONS.includes(rule?.action)) {
      throw new Error(`class "${name}" has unknown action "${rule?.action}"`);
    }
    if (rule.action === 'break_glass') requireApprovers(name, rule);
  }
  for (const [channel, overrides] of Object.entries(policy.channels || {})) {
    for (const [name, action] of Object.entries(overrides || {})) {
      if (!ACTIONS.includes(action)) {
        throw new Error(`channel "${channel}" sets unknown action "${action}" for "${name}"`);
      }
      if (!policy.classes?.[name]) {
        throw new Error(`channel "${channel}" overrides undefined class "${name}"`);
      }
      if (action === 'break_glass') requireApprovers(name, policy.classes[name]);
    }
  }
}

function requireApprovers(name, rule) {
  const approvers = rule.approvers || [];
  const min = rule.min_approvals ?? 2;
  if (approvers.length < min) {
    throw new Error(`class "${name}" is break_glass but lists ${approvers.length} of ${min} approvers`);
  }
}

export function getPolicy() {
  return active;
}

export function classify(type, policy = active.policy) {
  const t = normalize(type);
  for (const [name, rule] of Object.entries(policy.classes || {})) {
    const matches = (rule.matches || []).map(normalize);
    if (matches.includes(t) || matches.some(m => t.includes(m) || m.includes(t))) return name;
  }
  return null;
}

/**
 * Decide what may happen to a set of findings on a given channel.
 * Returns a decision that is recorded and referenced by a later release call.
 */
export function evaluate(items, channel = 'text') {
  const { policy, hash } = active;
  const overrides = policy.channels?.[channel] || {};
  const fallback  = policy.default_action || 'block';

  const rules = [];
  let action = 'allow';
  let approvers = [];
  let minApprovals = 0;

  for (const item of items || []) {
    const cls  = classify(item.type);
    const rule = cls ? policy.classes[cls] : null;
    const act  = overrides[cls] || rule?.action || fallback;

    rules.push({
      type:   item.type,
      class:  cls || 'unclassified',
      action: act,
      reason: rule?.reason || (cls ? '' : 'no class matched — default action applied'),
    });

    if (act === 'break_glass' && strictest(action, act) === act) {
      approvers    = rule?.approvers || [];
      minApprovals = rule?.min_approvals ?? 2;
    }
    action = strictest(action, act);
  }

  return {
    id:            randomUUID(),
    action,
    channel,
    rules,
    approvers:     action === 'break_glass' ? approvers : [],
    minApprovals:  action === 'break_glass' ? minApprovals : 0,
    minJustification: policy.justification?.min_length ?? 20,
    organization:  policy.organization || '',
    policyVersion: policy.version ?? 0,
    policyHash:    hash,
    policyError:   active.error,
    issuedAt:      Date.now(),
  };
}

/**
 * Validate a request to release the *original* data under a decision.
 * Returns { granted: true } or { granted: false, error, ... } — never throws,
 * and never grants when the decision says block.
 */
export function checkRelease(decision, { justification = '', approvals = [], requester = '' } = {}) {
  if (!decision) return { granted: false, error: 'unknown_decision' };
  if (Date.now() - decision.issuedAt > RELEASE_WINDOW_MS) {
    return { granted: false, error: 'decision_expired' };
  }

  switch (decision.action) {
    case 'allow':
    case 'redact':
      return { granted: true };

    case 'block':
      return { granted: false, error: 'blocked_by_policy' };

    case 'allow_with_justification': {
      const text = String(justification).trim();
      if (text.length < decision.minJustification) {
        return { granted: false, error: 'justification_required', minLength: decision.minJustification };
      }
      return { granted: true, justification: text };
    }

    case 'break_glass': {
      const text = String(justification).trim();
      if (text.length < decision.minJustification) {
        return { granted: false, error: 'justification_required', minLength: decision.minJustification };
      }
      const allowed = decision.approvers.map(a => String(a).toLowerCase());
      const seen = new Set();
      for (const raw of approvals) {
        const who = String(raw?.approver || raw || '').trim().toLowerCase();
        if (!who || !allowed.includes(who)) continue;
        if (who === String(requester).trim().toLowerCase()) continue; // no self-approval
        seen.add(who);
      }
      if (seen.size < decision.minApprovals) {
        return {
          granted:  false,
          error:    'approval_required',
          required: decision.minApprovals,
          received: seen.size,
          approvers: decision.approvers,
        };
      }
      return { granted: true, justification: text, approvedBy: [...seen] };
    }

    default:
      return { granted: false, error: 'blocked_by_policy' };
  }
}
