/**
 * Siyada Backend
 *
 * Routes:
 *   POST /analyze  → { text } → Claude PII agent → { hasPII, items, redactedText, ... }
 *   GET  /health   → service health
 *   GET  /         → simple dashboard HTML
 *
 * Zero npm dependencies. Based on Rilo Tutor server pattern.
 * SigV4-signs every Bedrock request directly.
 */

import { createServer }         from 'node:http';
import { createHash, createHmac } from 'node:crypto';

const PORT          = Number(process.env.PORT || 3200);
// BEDROCK_REGION is used instead of AWS_REGION to avoid conflict with shell env vars
const AWS_REGION    = process.env.BEDROCK_REGION || process.env.AWS_REGION || 'eu-west-1';
const BEDROCK_MODEL = process.env.BEDROCK_MODEL  || 'eu.anthropic.claude-haiku-4-5-20251001-v1:0';

// CORS — allow the extension (chrome-extension://*) and localhost for dev
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// ─── In-memory compliance log ────────────────────────────────────────────────
const events = [];
const MAX_EVENTS = 500;

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

async function callBedrock(messages, systemPrompt) {
  const creds   = await getCredentials();
  const host    = `bedrock-runtime.${AWS_REGION}.amazonaws.com`;
  const path    = `/model/${BEDROCK_MODEL}/invoke`;
  const body    = JSON.stringify({
    anthropic_version: 'bedrock-2023-05-31',
    max_tokens:        1024,
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
</style>
</head>
<body>
<h1>🛡️ Siyada — سيادة</h1>
<p class="sub">UAE AI Compliance Dashboard</p>
<div class="stats" id="stats"></div>
<table><thead><tr><th>Time</th><th>Severity</th><th>PII Types</th><th>Summary</th></tr></thead>
<tbody id="tbody"></tbody></table>
<script>
async function load() {
  const r = await fetch('/stats');
  const d = await r.json();
  document.getElementById('stats').innerHTML =
    '<div class="stat"><div class="stat-v">'+d.total+'</div><div class="stat-l">Total Analyzed</div></div>' +
    '<div class="stat"><div class="stat-v" style="color:#FF6B6B">'+d.critical+'</div><div class="stat-l">Critical Events</div></div>' +
    '<div class="stat"><div class="stat-v">'+d.health+'</div><div class="stat-l">Health Data</div></div>' +
    '<div class="stat"><div class="stat-v">'+d.financial+'</div><div class="stat-l">Financial Data</div></div>';
  document.getElementById('tbody').innerHTML = d.events.map(e =>
    '<tr><td>'+new Date(e.ts).toLocaleTimeString()+'</td>' +
    '<td><span class="badge '+e.sev+'">'+e.sev+'</span></td>' +
    '<td>'+e.types+'</td>' +
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
    sendJson(res, 200, { ok: true, service: 'siyada', model: BEDROCK_MODEL, region: AWS_REGION, total: events.length });
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
      events:   events.slice(0, 50).map(e => ({
        ts:      e.timestamp,
        sev:     e.severity || 'medium',
        types:   (e.items || []).map(i => i.type).join(', ') || '—',
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

    // Log the event
    if (result.hasPII) {
      const healthKeywords = ['patient','diagnosis','medication','treatment','hospital','clinic','مريض','تشخيص'];
      const financialKeywords = ['account','balance','transaction','iban','bank','حساب'];
      const lowerText = text.toLowerCase();
      events.unshift({
        timestamp:       Date.now(),
        severity:        result.items?.[0]?.severity || 'medium',
        items:           result.items || [],
        hasHealthData:   healthKeywords.some(k => lowerText.includes(k)),
        hasFinancialData:financialKeywords.some(k => lowerText.includes(k)),
        summary:         result.summary || '',
        regulations:     result.regulations || [],
      });
      if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
    }

    sendJson(res, 200, result);
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

server.listen(PORT, () => {
  console.log(`Siyada backend listening on http://localhost:${PORT}`);
  console.log(`  model  : ${BEDROCK_MODEL}`);
  console.log(`  region : ${AWS_REGION}`);
  console.log(`  dashboard: http://localhost:${PORT}/`);
});
