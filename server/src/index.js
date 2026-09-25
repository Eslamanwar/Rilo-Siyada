/**
 * Siyada Backend
 *
 * Routes:
 *   POST /analyze        → { text } → Claude PII agent → { hasPII, items, redactedText, policy, ... }
 *   POST /analyze-image  → { imageBase64, mediaType } → vision PII agent → { hasPII, items, boxes, policy, ... }
 *   POST /release        → { decisionId, justification, approvals } → grant or refusal for the original data
 *   GET  /policy         → the active policy, its hash, and any load error
 *   GET  /health         → service health
 *   GET  /               → simple dashboard HTML
 *
 * Zero npm dependencies. Based on Rilo Tutor server pattern.
 * SigV4-signs every Bedrock request directly.
 */

import { createServer }         from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { resolve as resolvePath } from 'node:path';
import { fileURLToPath }          from 'node:url';
import { evaluate, checkRelease, loadPolicy, watchPolicy, getPolicy, RELEASE_WINDOW_MS } from './policy.js';

const PORT          = Number(process.env.PORT || 3200);
// BEDROCK_REGION is used instead of AWS_REGION to avoid conflict with shell env vars
const AWS_REGION    = process.env.BEDROCK_REGION || process.env.AWS_REGION || 'eu-west-1';
const BEDROCK_MODEL = process.env.BEDROCK_MODEL  || 'eu.anthropic.claude-haiku-4-5-20251001-v1:0';

// Local vision model (Jetson / on-prem GPU). When set, images are analyzed here
// instead of Bedrock — the request never leaves the local network.
// The endpoint must accept { imageBase64, mediaType, prompt } and return the
// same JSON schema the vision agent produces.
const VISION_URL = process.env.VISION_URL || '';

// Bedrock accepts images up to ~5 MB. Base64 inflates by ~4/3.
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const ALLOWED_MEDIA_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];

// CORS — allow the extension (chrome-extension://*) and localhost for dev
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// ─── In-memory compliance log ────────────────────────────────────────────────
const events = [];
const MAX_EVENTS = 500;

// ─── Policy as code ──────────────────────────────────────────────────────────
const POLICY_FILE = resolvePath(
  process.env.POLICY_FILE || fileURLToPath(new URL('../../siyada-policy.yaml', import.meta.url)),
);

// Decisions live only long enough for the user to justify or get approval.
const decisions = new Map();

function recordDecision(decision) {
  decisions.set(decision.id, decision);
  const cutoff = Date.now() - RELEASE_WINDOW_MS;
  for (const [id, d] of decisions) if (d.issuedAt < cutoff) decisions.delete(id);
  return decision;
}

// ─── AWS SigV4 helpers ───────────────────────────────────────────────────────

const hmac      = (key, data) => createHmac('sha256', key).update(data).digest();
const sha256hex = (data)      => createHash('sha256').update(data).digest('hex');

let cachedCreds = null;

async function instanceCredentials() {
  if (cachedCreds && cachedCreds.expiresAt - 5 * 60_000 > Date.now()) return cachedCreds;

  const base = process.env.RILO_IMDS_BASE || 'http://169.254.169.254/latest';

  const token = await fetch(`${base}/api/token`, {
    method: 'PUT',
    headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '300' },
    signal: AbortSignal.timeout(2000),
  }).then(r => r.text());

  const headers = { 'X-aws-ec2-metadata-token': token };
  const role = await fetch(`${base}/meta-data/iam/security-credentials/`, {
    headers, signal: AbortSignal.timeout(2000),
  }).then(r => r.text());

  const c = await fetch(`${base}/meta-data/iam/security-credentials/${role.trim()}`, {
    headers, signal: AbortSignal.timeout(2000),
  }).then(r => r.json());

  cachedCreds = {
    accessKeyId:     c.AccessKeyId,
    secretAccessKey: c.SecretAccessKey,
    sessionToken:    c.Token,
    expiresAt:       new Date(c.Expiration).getTime(),
  };
  return cachedCreds;
}

// Falls back to env vars when not on EC2 (local dev)
async function getCredentials() {
  if (process.env.AWS_ACCESS_KEY_ID) {
    return {
      accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken:    process.env.AWS_SESSION_TOKEN || null,
    };
  }
  return instanceCredentials();
}

function signAws(creds, { method = 'POST', region, service, host, path, body = '', contentType = '' }) {
  const now       = new Date();
  const amzDate   = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const canonicalPath = '/' + path.slice(1).split('/').map(encodeURIComponent).join('/');

  const headers = {
    ...(contentType ? { 'content-type': contentType } : {}),
    host,
    'x-amz-content-sha256': sha256hex(body),
    'x-amz-date':           amzDate,
    ...(creds.sessionToken ? { 'x-amz-security-token': creds.sessionToken } : {}),
  };
  const signedHeaders   = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}\n`).join('');

  const canonicalRequest = [method, canonicalPath, '', canonicalHeaders, signedHeaders, sha256hex(body)].join('\n');
  const scope   = `${dateStamp}/${region}/${service}/aws4_request`;
  const toSign  = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');

  const kDate      = hmac(`AWS4${creds.secretAccessKey}`, dateStamp);
  const kRegion    = hmac(kDate, region);
  const kService   = hmac(kRegion, service);
  const signature  = createHmac('sha256', hmac(kService, 'aws4_request')).update(toSign).digest('hex');

  return {
    ...headers,
    Authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

// ─── Call Bedrock Claude ─────────────────────────────────────────────────────

async function callBedrock(messages, systemPrompt, maxTokens = 1024) {
  const creds   = await getCredentials();
  const host    = `bedrock-runtime.${AWS_REGION}.amazonaws.com`;
  const path    = `/model/${BEDROCK_MODEL}/invoke`;
  const body    = JSON.stringify({
    anthropic_version: 'bedrock-2023-05-31',
    max_tokens:        maxTokens,
    system:            systemPrompt,
    messages,
  });

  const signed  = signAws(creds, {
    region: AWS_REGION, service: 'bedrock', host, path, body, contentType: 'application/json',
  });

  // `signed` already includes 'content-type' as a signed header — don't duplicate it
  const res = await fetch(`https://${host}${path}`, {
    method:  'POST',
    headers: signed,
    body,
    signal:  AbortSignal.timeout(20_000),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    return { ok: false, status: res.status, detail };
  }

  const data = await res.json();
  const text = data?.content?.[0]?.text ?? '';
  return { ok: true, text };
}

// ─── PII Agent system prompt ─────────────────────────────────────────────────

const PII_SYSTEM_PROMPT = `You are a UAE data compliance AI agent. Your job is to analyze text for personally identifiable information (PII) that is protected under UAE law.

Sensitive data you must detect — be liberal, flag anything that looks sensitive:

PERSONAL / IDENTITY:
- Emirates ID numbers (format: 784-YYYY-NNNNNNN-C, 15 digits starting with 784)
- UAE phone numbers (+971-XX-XXXXXXX, 05X-XXXXXXX, 05XXXXXXXX)
- UAE IBAN numbers (AE followed by 21 digits)
- Full names of individuals (Arabic or English — "Ahmed Al-Mansouri", "أحمد المنصوري")
- Email addresses
- Passport numbers (letter + 7-8 digits)
- Credit card numbers (Visa, Mastercard, Amex patterns)
- Dates of birth, national ID numbers of any country
- Physical home/work addresses

HEALTH:
- Medical record numbers or patient identifiers
- Health diagnoses, treatments, prescriptions tied to an identifiable person

CREDENTIALS & SECRETS (treat as critical — these must never be shared):
- Passwords, even if described informally ("my password is abc123", "password = xyz")
- API keys, access keys, secret keys, auth tokens of any kind
- AWS access key IDs (start with AKIA, ASIA, etc.)
- Private keys, certificates, connection strings
- Database credentials ("DB password is ...", "mongodb://user:pass@...")
- Any string that looks like a secret value described as such in context

You must respond ONLY with valid JSON in this exact schema — no markdown, no explanation outside the JSON:

{
  "hasPII": boolean,
  "items": [
    {
      "type": "string",
      "value": "the exact matched text",
      "masked": "the replacement placeholder e.g. [EMIRATES-ID]",
      "regulation": "the specific UAE law violated",
      "severity": "low | medium | high | critical"
    }
  ],
  "redactedText": "the full original text with every PII value replaced by its masked placeholder",
  "regulations": ["list of UAE laws potentially violated"],
  "summary": "one sentence explaining what was found"
}

Severity guide:
- critical: credentials/passwords/keys (any kind), Emirates ID + health data together, any combination identifying a patient with a diagnosis
- high: Emirates ID alone, IBAN, credit card, health data alone, API keys
- medium: phone number, email, passport, name alone
- low: address fragments, partial information

Regulation references:
- Emirates ID / health data → "Federal Law 2/2019, Art. 13"
- Any personal data → "UAE PDPL (Decree-Law 45/2021)"
- Financial data → "CBUAE Consumer Protection Regulation / PCI-DSS"
- Credentials / secrets → "UAE PDPL / Security Best Practice"

If hasPII is false, set items to [], regulations to [], redactedText to the original text unchanged, and summary to "No PII detected".`;

// ─── Vision agent system prompt ──────────────────────────────────────────────

const IMAGE_SYSTEM_PROMPT = `You are a UAE data compliance AI agent analyzing an IMAGE before it is uploaded to a foreign AI service.

Step 1 — Read every piece of text in the image, Arabic and English, including handwriting, stamps, ID cards, forms, screenshots, tables, and small print.
Step 2 — Decide which of it is sensitive under UAE law.

Treat these as sensitive:
- Emirates ID cards or numbers (784-YYYY-NNNNNNN-C), and the card photo itself
- Passports, visas, residence permits, driving licences, vehicle registration (mulkiya)
- UAE phone numbers, IBANs (AE + 21 digits), bank statements, cheques, credit/debit cards
- Full names of individuals in Arabic or English, signatures, dates of birth, addresses
- Faces of identifiable people when shown together with any identifying document or record
- Medical reports, prescriptions, lab results, patient identifiers, diagnoses
- Credentials on screen: passwords, API keys, access keys, tokens, connection strings, private keys
- Internal or classified government markings and letterheads

For every sensitive finding return a normalized bounding box so the region can be masked before upload.
Boxes use fractions of the image dimensions, origin at the top-left: x and y are the top-left corner, w and h the size, each between 0 and 1.
Cover the whole value, not the field label: a box must start before the first character and end after the last one, and be tall enough to include ascenders and descenders. Then widen it further. A box that is too large costs nothing; a box that leaves one digit or one letter visible defeats the entire redaction.
If you cannot place a box confidently, omit the box field for that finding rather than guessing — a guessed box is worse than none.

Respond ONLY with valid JSON in this exact schema — no markdown, no prose outside the JSON:

{
  "hasPII": boolean,
  "imageDescription": "one sentence describing what the image is, with no sensitive values in it",
  "items": [
    {
      "type": "string",
      "value": "the exact text read from the image, or a short description for a non-text finding such as a face",
      "masked": "the replacement placeholder e.g. [EMIRATES-ID]",
      "regulation": "the specific UAE law involved",
      "severity": "low | medium | high | critical",
      "box": [x, y, w, h]
    }
  ],
  "regulations": ["list of UAE laws potentially involved"],
  "summary": "one sentence explaining what was found",
  "safeToSend": boolean
}

Severity guide:
- critical: credentials or keys on screen, an Emirates ID or passport image, a medical record identifying a patient
- high: IBAN, bank statement, payment card, health data, government document
- medium: phone number, email, name, address, face with a name
- low: fragments or partial information

If nothing sensitive is present set hasPII false, items [], regulations [], safeToSend true, and summary "No sensitive data detected in image".`;

// ─── Analyze route ────────────────────────────────────────────────────────────

async function analyzeText(text) {
  const messages = [{ role: 'user', content: `Analyze this text for UAE PII:\n\n${text}` }];
  const result   = await callBedrock(messages, PII_SYSTEM_PROMPT);

  if (!result.ok) return { ok: false, error: 'bedrock_error', detail: result.detail };

  // Parse the JSON the LLM returned
  let parsed;
  try {
    // Strip markdown fences if the model wraps in ```json ... ```
    const cleaned = result.text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/,'').trim();
    parsed = JSON.parse(cleaned);
  } catch (e) {
    return { ok: false, error: 'parse_error', raw: result.text, detail: String(e.message) };
  }

  return { ok: true, ...parsed };
}

// ─── Image analysis ──────────────────────────────────────────────────────────

function parseAgentJson(raw) {
  const cleaned = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
  return JSON.parse(cleaned);
}

// Keep only boxes that are actually usable as a mask.
function normalizeItems(items) {
  if (!Array.isArray(items)) return [];
  return items.map(item => {
    const box = item.box;
    const valid = Array.isArray(box) && box.length === 4 &&
      box.every(n => typeof n === 'number' && Number.isFinite(n)) &&
      box[2] > 0 && box[3] > 0;
    if (!valid) return { ...item, box: null };
    const [x, y, w, h] = box;
    const clamp = (n) => Math.min(1, Math.max(0, n));
    return { ...item, box: [clamp(x), clamp(y), clamp(Math.min(w, 1 - clamp(x))), clamp(Math.min(h, 1 - clamp(y)))] };
  });
}

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

function highestSeverity(items) {
  let rank = -1;
  for (const item of items || []) {
    const i = SEVERITY_ORDER.indexOf(item.severity);
    if (i > rank) rank = i;
  }
  return SEVERITY_ORDER[rank] || 'medium';
}

async function callLocalVision(imageBase64, mediaType) {
  const res = await fetch(VISION_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ imageBase64, mediaType, prompt: IMAGE_SYSTEM_PROMPT }),
    signal:  AbortSignal.timeout(60_000),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    return { ok: false, status: res.status, detail };
  }
  const data = await res.json();
  // Accept either the parsed schema directly or a { text } envelope from a raw LLM server
  return { ok: true, text: typeof data.text === 'string' ? data.text : JSON.stringify(data) };
}

async function analyzeImage(imageBase64, mediaType) {
  const messages = [{
    role: 'user',
    content: [
      { type: 'image', source: { type: 'base64', media_type: mediaType, data: imageBase64 } },
      { type: 'text',  text: 'Analyze this image for UAE sensitive data before it is uploaded to a foreign AI service.' },
    ],
  }];

  const result = VISION_URL
    ? await callLocalVision(imageBase64, mediaType)
    : await callBedrock(messages, IMAGE_SYSTEM_PROMPT, 2048);

  if (!result.ok) return { ok: false, error: 'vision_error', detail: result.detail };

  let parsed;
  try {
    parsed = parseAgentJson(result.text);
  } catch (e) {
    return { ok: false, error: 'parse_error', raw: result.text, detail: String(e.message) };
  }

  const items = normalizeItems(parsed.items);
  return {
    ok:               true,
    hasPII:           Boolean(parsed.hasPII),
    imageDescription: parsed.imageDescription || '',
    items,
    regulations:      Array.isArray(parsed.regulations) ? parsed.regulations : [],
    summary:          parsed.summary || '',
    // A mask can only be drawn for findings the model located in the image
    maskable:         items.length > 0 && items.every(i => i.box),
    engine:           VISION_URL ? 'local-vision' : `bedrock:${BEDROCK_MODEL}`,
  };
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  ()  => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

async function readBodyBuffer(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  ()  => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ─── Dashboard HTML ───────────────────────────────────────────────────────────

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Siyada — Compliance Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0D1117; color: #E6EDF3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; padding: 24px; }
  h1 { font-size: 22px; color: #00D4AA; margin-bottom: 4px; }
  .sub { color: #8B949E; font-size: 13px; margin-bottom: 24px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat { background: #161B22; border: 1px solid #21262D; border-radius: 10px; padding: 16px; }
  .stat-v { font-size: 28px; font-weight: 700; color: #00D4AA; }
  .stat-l { font-size: 11px; color: #8B949E; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: #161B22; border-radius: 10px; overflow: hidden; }
  th { padding: 10px 16px; text-align: left; font-size: 11px; color: #8B949E; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #21262D; }
  td { padding: 10px 16px; border-bottom: 1px solid #21262D; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
  .critical { background: rgba(255,59,59,.2); color: #FF6B6B; }
  .high     { background: rgba(255,107,53,.2); color: #FF8C61; }
  .medium   { background: rgba(255,193,7,.15); color: #FFD60A; }
  .low      { background: rgba(139,148,158,.2); color: #8B949E; }
  .act { font-size: 11px; font-weight: 700; color: #8B949E; }
  .act-block { color: #FF6B6B; }
  .act-break_glass { color: #FF8C61; }
  .act-allow_with_justification { color: #FFD60A; }
  .act-redact { color: #00D4AA; }
  .policy-bar { background: #161B22; border: 1px solid #21262D; border-left: 3px solid #00D4AA;
                border-radius: 8px; padding: 10px 16px; margin-bottom: 16px; font-size: 12px; color: #8B949E; }
  .policy-bar code { color: #E6EDF3; }
  .policy-bad { border-left-color: #FF6B6B; color: #FF6B6B; }
</style>
</head>
<body>
<h1>🛡️ Siyada — سيادة</h1>
<p class="sub">UAE AI Compliance Dashboard</p>
<div class="policy-bar" id="policyBar"></div>
<div class="stats" id="stats"></div>
<table><thead><tr><th>Time</th><th>Channel</th><th>Severity</th><th>PII Types</th><th>Policy</th><th>Summary</th></tr></thead>
<tbody id="tbody"></tbody></table>
<script>
async function load() {
  const r = await fetch('/stats');
  const d = await r.json();
  document.getElementById('stats').innerHTML =
    '<div class="stat"><div class="stat-v">'+d.total+'</div><div class="stat-l">Total Analyzed</div></div>' +
    '<div class="stat"><div class="stat-v" style="color:#FF6B6B">'+d.critical+'</div><div class="stat-l">Critical Events</div></div>' +
    '<div class="stat"><div class="stat-v">'+d.health+'</div><div class="stat-l">Health Data</div></div>' +
    '<div class="stat"><div class="stat-v">'+d.financial+'</div><div class="stat-l">Financial Data</div></div>' +
    '<div class="stat"><div class="stat-v">'+d.images+'</div><div class="stat-l">Images Scanned</div></div>' +
    '<div class="stat"><div class="stat-v" style="color:#FF8C61">'+d.released+'</div><div class="stat-l">Originals Released</div></div>';
  const bar = document.getElementById('policyBar');
  bar.className = 'policy-bar' + (d.policy.error ? ' policy-bad' : '');
  bar.innerHTML = d.policy.error
    ? 'Policy not enforceable — ' + d.policy.error
    : 'Governed by <code>' + d.policy.organization + '</code> policy <code>' + d.policy.hash + '</code>';
  document.getElementById('tbody').innerHTML = d.events.map(e =>
    '<tr><td>'+new Date(e.ts).toLocaleTimeString()+'</td>' +
    '<td>'+(e.src === 'image' ? '🖼️ image' : '💬 text')+'</td>' +
    '<td><span class="badge '+e.sev+'">'+e.sev+'</span></td>' +
    '<td>'+e.types+'</td>' +
    '<td><span class="act act-'+e.action+'">'+e.action+(e.outcome ? ' · '+e.outcome : '')+'</span></td>' +
    '<td style="color:#8B949E;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e.summary+'</td></tr>'
  ).join('');
}
load();
setInterval(load, 5000);
</script>
</body></html>`;

// ─── Server ────────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS); res.end(); return;
  }

  // Health
  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, {
      ok:      true,
      service: 'siyada',
      model:   BEDROCK_MODEL,
      region:  AWS_REGION,
      vision:  VISION_URL ? 'local' : 'bedrock',
      policy:  { hash: getPolicy().hash, version: getPolicy().policy.version, error: getPolicy().error },
      total:   events.length,
    });
    return;
  }

  // Dashboard
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { ...CORS_HEADERS, 'Content-Type': 'text/html' });
    res.end(DASHBOARD_HTML);
    return;
  }

  // Stats API for dashboard
  if (req.method === 'GET' && url.pathname === '/stats') {
    sendJson(res, 200, {
      total:    events.length,
      critical: events.filter(e => e.severity === 'critical').length,
      health:   events.filter(e => e.hasHealthData).length,
      financial:events.filter(e => e.hasFinancialData).length,
      images:   events.filter(e => e.source === 'image').length,
      released: events.filter(e => e.outcome === 'released').length,
      policy:   { organization: getPolicy().policy.organization, hash: getPolicy().hash, error: getPolicy().error },
      events:   events.slice(0, 50).map(e => ({
        ts:      e.timestamp,
        src:     e.source || 'text',
        sev:     e.severity || 'medium',
        types:   (e.items || []).map(i => i.type).join(', ') || '—',
        action:  e.policyAction || '—',
        outcome: e.outcome || '',
        summary: e.summary || '—',
      })),
    });
    return;
  }

  // ── POST /analyze — main LLM PII detection route ────────────────────────────
  if (req.method === 'POST' && url.pathname === '/analyze') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { sendJson(res, 400, { error: 'invalid_body' }); return; }

    const text = typeof body.text === 'string' ? body.text.trim() : '';
    if (!text) { sendJson(res, 400, { error: 'missing_text' }); return; }
    if (text.length > 4000) { sendJson(res, 400, { error: 'text_too_long', max: 4000 }); return; }

    let result;
    try {
      result = await analyzeText(text);
    } catch (err) {
      cachedCreds = null;
      sendJson(res, 500, { error: 'bedrock_error', message: String(err?.message ?? err) });
      return;
    }

    if (!result.ok) {
      sendJson(res, 500, { error: result.error, detail: result.detail, raw: result.raw });
      return;
    }

    // What the organisation permits is decided here, not in the extension.
    if (result.hasPII) {
      result.policy = recordDecision(evaluate(result.items, 'text'));

      const healthKeywords = ['patient','diagnosis','medication','treatment','hospital','clinic','مريض','تشخيص'];
      const financialKeywords = ['account','balance','transaction','iban','bank','حساب'];
      const lowerText = text.toLowerCase();
      events.unshift({
        timestamp:       Date.now(),
        source:          'text',
        severity:        highestSeverity(result.items),
        items:           result.items || [],
        hasHealthData:   healthKeywords.some(k => lowerText.includes(k)),
        hasFinancialData:financialKeywords.some(k => lowerText.includes(k)),
        summary:         result.summary || '',
        regulations:     result.regulations || [],
        policyAction:    result.policy.action,
        policyHash:      result.policy.policyHash,
        decisionId:      result.policy.id,
      });
      if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
    }

    sendJson(res, 200, result);
    return;
  }

  // ── POST /analyze-image — vision PII detection on an attachment ─────────────
  if (req.method === 'POST' && url.pathname === '/analyze-image') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { sendJson(res, 400, { error: 'invalid_body' }); return; }

    const imageBase64 = typeof body.imageBase64 === 'string' ? body.imageBase64 : '';
    const mediaType   = typeof body.mediaType === 'string' ? body.mediaType.toLowerCase() : '';

    if (!imageBase64) { sendJson(res, 400, { error: 'missing_image' }); return; }
    if (!ALLOWED_MEDIA_TYPES.includes(mediaType)) {
      sendJson(res, 400, { error: 'unsupported_media_type', allowed: ALLOWED_MEDIA_TYPES });
      return;
    }
    // base64 length → decoded byte count
    const bytes = Math.floor(imageBase64.length * 3 / 4);
    if (bytes > MAX_IMAGE_BYTES) {
      sendJson(res, 413, { error: 'image_too_large', max: MAX_IMAGE_BYTES, size: bytes });
      return;
    }

    let result;
    try {
      result = await analyzeImage(imageBase64, mediaType);
    } catch (err) {
      cachedCreds = null;
      sendJson(res, 500, { error: 'vision_error', message: String(err?.message ?? err) });
      return;
    }

    if (!result.ok) {
      sendJson(res, 500, { error: result.error, detail: result.detail, raw: result.raw });
      return;
    }

    if (result.hasPII) {
      result.policy = recordDecision(evaluate(result.items, 'image'));

      const typeText = result.items.map(i => `${i.type} ${i.value}`).join(' ').toLowerCase();
      const healthKeywords    = ['patient','diagnosis','medical','prescription','lab','hospital','clinic','مريض','تشخيص'];
      const financialKeywords = ['iban','bank','card','account','cheque','statement','حساب'];
      events.unshift({
        timestamp:        Date.now(),
        source:           'image',
        severity:         highestSeverity(result.items),
        items:            result.items.map(({ box: _box, ...rest }) => rest),
        hasHealthData:    healthKeywords.some(k => typeText.includes(k)),
        hasFinancialData: financialKeywords.some(k => typeText.includes(k)),
        summary:          result.summary,
        regulations:      result.regulations,
        policyAction:     result.policy.action,
        policyHash:       result.policy.policyHash,
        decisionId:       result.policy.id,
      });
      if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
    }

    sendJson(res, 200, result);
    return;
  }

  // ── GET /policy — the active policy, for the dashboard and for auditors ───
  if (req.method === 'GET' && url.pathname === '/policy') {
    const { policy, hash, path, error } = getPolicy();
    sendJson(res, error ? 503 : 200, { policy, hash, path, error });
    return;
  }

  // ── POST /release — may the ORIGINAL data be sent under this decision? ────
  if (req.method === 'POST' && url.pathname === '/release') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { sendJson(res, 400, { error: 'invalid_body' }); return; }

    const decision = decisions.get(String(body.decisionId || ''));
    const verdict  = checkRelease(decision, {
      justification: body.justification,
      approvals:     Array.isArray(body.approvals) ? body.approvals : [],
      requester:     body.requester,
    });

    // Refusals are logged too — an attempted release is the interesting event.
    events.unshift({
      timestamp:    Date.now(),
      source:       decision?.channel || 'release',
      severity:     'high',
      items:        [],
      summary:      verdict.granted
        ? `Original released under ${decision.action}: ${verdict.justification || ''}`
        : `Release refused (${verdict.error})`,
      policyAction: decision?.action || 'unknown',
      policyHash:   decision?.policyHash || 'none',
      decisionId:   body.decisionId || null,
      outcome:      verdict.granted ? 'released' : 'refused',
      justification: verdict.justification || '',
      approvedBy:   verdict.approvedBy || [],
    });
    if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;

    if (verdict.granted) decisions.delete(decision.id); // one grant per decision
    sendJson(res, verdict.granted ? 200 : 403, verdict);
    return;
  }

  // ── POST /transcribe — proxy raw audio to Jetson Whisper server ─────────────
  if (req.method === 'POST' && url.pathname === '/transcribe') {
    const WHISPER_URL = process.env.WHISPER_URL || 'http://192.168.1.133:5000/transcribe';
    let audioBuffer;
    try {
      audioBuffer = await readBodyBuffer(req);
    } catch (err) {
      sendJson(res, 400, { error: 'read_error', message: String(err?.message ?? err) });
      return;
    }

    try {
      const whisperRes = await fetch(WHISPER_URL, {
        method:  'POST',
        headers: { 'Content-Type': req.headers['content-type'] || 'audio/webm' },
        body:    audioBuffer,
        signal:  AbortSignal.timeout(30_000),
      });
      const data = await whisperRes.json();
      sendJson(res, whisperRes.ok ? 200 : 500, data);
    } catch (err) {
      sendJson(res, 503, { error: 'whisper_unavailable', message: String(err?.message ?? err) });
    }
    return;
  }

  sendJson(res, 404, { error: 'not_found' });
});

loadPolicy(POLICY_FILE);
watchPolicy(POLICY_FILE, ({ hash, error }) => {
  console.log(error ? `  policy : RELOAD FAILED — ${error}` : `  policy : reloaded (${hash})`);
});

server.listen(PORT, () => {
  const { hash, error } = getPolicy();
  console.log(`Siyada backend listening on http://localhost:${PORT}`);
  console.log(`  policy : ${error ? `UNENFORCEABLE — ${error}` : `${POLICY_FILE} (${hash})`}`);
  console.log(`  model  : ${BEDROCK_MODEL}`);
  console.log(`  vision : ${VISION_URL || `bedrock (${BEDROCK_MODEL})`}`);
  console.log(`  region : ${AWS_REGION}`);
  console.log(`  dashboard: http://localhost:${PORT}/`);
});
