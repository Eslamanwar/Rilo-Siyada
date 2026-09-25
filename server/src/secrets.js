/**
 * Siyada — deterministic secret scanner
 *
 * Source code pasted into a chat is the most common way a credential leaks:
 * a config file, a Terraform block, a .env, a stack trace with a connection
 * string. The LLM agent is asked to catch these too, but a probabilistic
 * detector is the wrong tool for a value whose shape is fully known — an AWS
 * access key ID is always 20 characters starting with AKIA/ASIA. Those are
 * matched here, exactly, before the model is consulted, and the findings are
 * merged into the model's verdict so a missed key can never slip through.
 *
 * Exports:
 *   scanSecrets(text)          → items[] in the same shape the PII agent returns
 *   redactSecrets(text, items) → text with every found value replaced by its mask
 *   mergeFindings(agentItems, secretItems) → deduplicated union, secrets first
 */

const REGULATION = 'UAE PDPL / Security Best Practice';

// Common prefixes for AWS key IDs: user keys, STS session keys, and the
// identifiers of roles, users, groups and policies (all reveal account layout).
const AWS_KEY_PREFIXES = '(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)';

// Keywords that mark the left-hand side of a credential assignment in code,
// env files, YAML, JSON and shell exports.
const ASSIGN_KEYS =
  '(?:password|passwd|pwd|secret|secret_key|client_secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|private[_-]?key|encryption[_-]?key|signing[_-]?key)';

/**
 * Each detector: { type, severity, masked, re, [group], [validate], [context] }
 *   group     capture group holding the secret value (default: whole match)
 *   validate  extra check on the captured value
 *   context   if set, the surrounding text (case-insensitive) must match — used
 *             for shapes that are otherwise too generic (e.g. 40 base64 chars)
 */
const DETECTORS = [
  {
    type: 'aws_access_key_id', severity: 'critical', masked: '[AWS-ACCESS-KEY-ID]',
    re: new RegExp(`\\b(${AWS_KEY_PREFIXES}[A-Z0-9]{16})\\b`, 'g'),
  },
  {
    type: 'aws_secret_access_key', severity: 'critical', masked: '[AWS-SECRET-ACCESS-KEY]',
    re: /(?:aws)?_?secret(?:_access)?_?key\s*['":=]+\s*['"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
  },
  {
    // Bare 40-char secret next to an AKIA key, e.g. a ~/.aws/credentials paste
    type: 'aws_secret_access_key', severity: 'critical', masked: '[AWS-SECRET-ACCESS-KEY]',
    re: /(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/g,
    group: 1,
    context: new RegExp(`${AWS_KEY_PREFIXES}[A-Z0-9]{16}`),
    validate: v => /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v) && !/^[A-Za-z]+$/.test(v),
  },
  {
    type: 'aws_session_token', severity: 'critical', masked: '[AWS-SESSION-TOKEN]',
    re: /(?:aws_)?session_token\s*['":=]+\s*['"]?([A-Za-z0-9/+=]{100,})/gi,
    group: 1,
  },
  {
    // 12-digit account IDs inside ARNs, IAM console URLs, or labelled as such
    type: 'aws_account_id', severity: 'high', masked: '[AWS-ACCOUNT-ID]',
    re: /(?:arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:|(?:aws_?)?account(?:_?id)?\s*['":=]+\s*['"]?|https?:\/\/)(\d{12})(?:\b|(?=\.signin\.aws))/gi,
    group: 1,
  },
  {
    type: 'aws_account_id', severity: 'high', masked: '[AWS-ACCOUNT-ID]',
    re: /\b(\d{12})\.dkr\.ecr\./g, group: 1,
  },
  {
    type: 'private_key', severity: 'critical', masked: '[PRIVATE-KEY]',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  },
  {
    type: 'github_token', severity: 'critical', masked: '[GITHUB-TOKEN]',
    re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, group: 1,
  },
  {
    type: 'gitlab_token', severity: 'critical', masked: '[GITLAB-TOKEN]',
    re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, group: 1,
  },
  {
    type: 'slack_token', severity: 'critical', masked: '[SLACK-TOKEN]',
    re: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g, group: 1,
  },
  {
    type: 'slack_webhook', severity: 'high', masked: '[SLACK-WEBHOOK]',
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g,
  },
  {
    type: 'google_api_key', severity: 'critical', masked: '[GOOGLE-API-KEY]',
    re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1,
  },
  {
    type: 'google_oauth_secret', severity: 'critical', masked: '[GOOGLE-OAUTH-SECRET]',
    re: /\b(GOCSPX-[0-9A-Za-z_-]{20,})\b/g, group: 1,
  },
  {
    type: 'stripe_secret_key', severity: 'critical', masked: '[STRIPE-KEY]',
    re: /\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b/g, group: 1,
  },
  {
    type: 'anthropic_api_key', severity: 'critical', masked: '[ANTHROPIC-API-KEY]',
    re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g, group: 1,
  },
  {
    type: 'openai_api_key', severity: 'critical', masked: '[OPENAI-API-KEY]',
    re: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g, group: 1,
    validate: v => !v.startsWith('sk-ant-'),
  },
  {
    type: 'sendgrid_api_key', severity: 'critical', masked: '[SENDGRID-API-KEY]',
    re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, group: 1,
  },
  {
    type: 'twilio_api_key', severity: 'critical', masked: '[TWILIO-API-KEY]',
    re: /\b(SK[0-9a-fA-F]{32})\b/g, group: 1,
  },
  {
    type: 'azure_storage_access_key', severity: 'critical', masked: '[AZURE-STORAGE-KEY]',
    re: /AccountKey=([A-Za-z0-9+/=]{86,88})/g, group: 1,
  },
  {
    type: 'jwt_token', severity: 'high', masked: '[JWT]',
    re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, group: 1,
  },
  {
    // user:password@host in any URL-style connection string
    type: 'connection_string', severity: 'critical', masked: '[CONNECTION-STRING]',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"]+:([^\s@'"]+)@[^\s'"]+/gi,
    validate: (_v, m) => !/^\$\{?[A-Z_]+\}?$/.test(m[1]) && m[1] !== 'password' && m[1] !== '<password>',
  },
  {
    type: 'bearer_token', severity: 'critical', masked: '[BEARER-TOKEN]',
    re: /\bBearer\s+([A-Za-z0-9._~+/=-]{20,})/g, group: 1,
    validate: v => !/^[<{$]/.test(v) && !/^(?:token|your[_-]?token)$/i.test(v),
  },
  {
    type: 'basic_auth_header', severity: 'critical', masked: '[BASIC-AUTH]',
    re: /\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})\b/g, group: 1,
  },
  {
    // password = "..." / API_KEY: '...' / export TOKEN=... in code and env files
    type: 'password', severity: 'critical', masked: '[SECRET-VALUE]',
    re: new RegExp(
      `\\b[\\w.-]*?${ASSIGN_KEYS}\\b['"]?\\s*(?::|=|=>|:=)\\s*['"\`]?([^\\s'"\`,;)}\\]]{6,})`, 'gi'),
    group: 1,
    validate: (v, m) => {
      const key = m[0].toLowerCase();
      if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v)) return false;          // $VAR / ${VAR}
      if (/^(?:\{\{|<|%\(|process\.env|os\.environ|env\(|getenv|secretsmanager|ssm:)/i.test(v)) return false;
      if (/^(?:null|none|nil|true|false|undefined|string|str|changeme|example|placeholder|redacted|xxx+|\*+|•+)$/i.test(v)) return false;
      if (/^(?:your[_-]|<your|my[_-]?(?:password|secret|token|key)$)/i.test(v)) return false;
      if (v.length < 8 && /^[a-z]+$/i.test(v)) return false;               // "token = value"
      return !key.includes('token_url') && !key.includes('key_id') && !key.includes('key_name');
    },
  },
];

function overlaps(a, b) {
  return a.start < b.end && b.start < a.end;
}

/**
 * Scan text for credentials. Returns items shaped like the PII agent's:
 *   { type, value, masked, regulation, severity, detector: 'secret-scan' }
 * Findings are ordered by position; overlapping matches keep the first (more
 * specific detectors are listed earlier).
 */
export function scanSecrets(text) {
  if (typeof text !== 'string' || !text) return [];

  const spans = [];
  for (const d of DETECTORS) {
    if (d.context && !d.context.test(text)) continue;
    d.re.lastIndex = 0;
    let m;
    while ((m = d.re.exec(text)) !== null) {
      if (m[0] === '') { d.re.lastIndex++; continue; }
      const value = d.group ? m[d.group] : m[0];
      if (!value) continue;
      if (d.validate && !d.validate(value, m)) continue;
      const start = m.index + (d.group ? m[0].indexOf(value) : 0);
      const span  = { start, end: start + value.length, type: d.type, value, masked: d.masked, severity: d.severity };
      if (spans.some(s => overlaps(s, span))) continue;
      spans.push(span);
    }
  }

  spans.sort((a, b) => a.start - b.start);
  const seen = new Set();
  const items = [];
  for (const s of spans) {
    const key = `${s.type}\u0000${s.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({
      type:       s.type,
      value:      s.value,
      masked:     s.masked,
      regulation: REGULATION,
      severity:   s.severity,
      detector:   'secret-scan',
    });
  }
  return items;
}

/** Replace every found value with its placeholder, longest values first. */
export function redactSecrets(text, items) {
  let out = String(text ?? '');
  const sorted = [...(items || [])].sort((a, b) => String(b.value).length - String(a.value).length);
  for (const item of sorted) {
    if (!item.value) continue;
    out = out.split(item.value).join(item.masked || '[REDACTED]');
  }
  return out;
}

/**
 * Union of the agent's findings and the scanner's. A value the scanner found
 * wins over the agent's description of the same value, so the type and mask
 * are stable and the policy classifies it as a credential.
 */
export function mergeFindings(agentItems, secretItems) {
  const merged = [...(secretItems || [])];
  const covered = (value) => merged.some(s =>
    s.value && value && (value.includes(s.value) || s.value.includes(value)));
  for (const item of agentItems || []) {
    if (!item || typeof item !== 'object') continue;
    if (covered(item.value)) continue;
    merged.push(item);
  }
  return merged;
}
