# Siyada (سيادة) — UAE AI Data Shield

> **Your data never leaves.**

A Chrome extension that intercepts UAE-sensitive PII before employees send it to
AI tools (Gemini, ChatGPT, Claude, Copilot). Detects, masks, and offers a
compliant alternative — answers the question without exporting the data.

## Why

Federal Law 2/2019, Article 13 prohibits sending UAE health data outside the
country. UAE PDPL (Decree-Law 45/2021) restricts cross-border personal data
transfers. Fine: **AED 500,000 – 2,000,000 per violation.**

Every existing DLP tool (Nightfall, Cyberhaven, Microsoft Purview) is US-based
cloud — it sends your data to Virginia to check if it should leave the UAE.
None of them know what an Emirates ID looks like.

## What It Detects

| Type | Pattern | Regulation |
|------|---------|------------|
| Emirates ID | `784-YYYY-NNNNNNN-C` | Federal Law 2/2019, Art. 13 |
| UAE IBAN | `AExx xxxx xxxx xxxx xxxx xxx` | CBUAE Consumer Protection |
| UAE Phone | `+971-XX-XXXXXXX`, `05X-XXXXXXX` | UAE PDPL |
| Credit Card | Visa / MC / Amex patterns | PCI-DSS / UAE PDPL |
| Email | Standard RFC pattern | UAE PDPL |
| Passport | Letter + 7-8 digits | UAE PDPL |
| Arabic Names | 2-4 Arabic-script words | UAE PDPL |
| Health Data | PII + medical keywords combo | Federal Law 2/2019, Art. 13 |

## How It Works

1. Extension is injected into Gemini, ChatGPT, Claude, Copilot
2. As you type, it scans for UAE PII patterns (debounced, no lag)
3. When you press Enter/Send — if PII found, the message is **blocked**
4. A panel shows exactly what was detected and which law it violates
5. You can **Redact & Continue** — PII replaced with `[EMIRATES-ID]` etc.
6. The redacted version is sent instead; your original stays in the browser

## Image Scanning

Images are the biggest leak channel — a photo of an Emirates ID carries every
field at once and no regex can see it. Siyada holds the attachment before the
AI site receives it.

1. Paste, drag-drop, or file-picker an image on a supported AI site
2. The event is cancelled; a downscaled copy (long edge ≤ 1568px) goes to the
   vision agent — never the site
3. The agent reads Arabic + English text, IDs, cards, faces and returns findings
   with normalized bounding boxes
4. The overlay shows your image with the sensitive regions marked
5. You choose: **Discard**, **Attach masked copy** (regions black-boxed and
   labelled `[EMIRATES-ID]`), or **Send original** (logged as an override)

If the agent is unreachable the image is **not** attached — fail closed.

### Masking is verified, not assumed

A model's bounding box is approximate — it clips a digit, drifts a few percent,
and the "masked" file still reads. So Siyada does not trust its own redaction:

- every box is grown before it is burned in (18% of its own size, min 8px)
- the masked copy is sent back through the agent and re-read
- if anything sensitive is still legible, the copy is **dropped, not attached**,
  and the event is logged as `mask_failed`

That costs one extra inference per masked image — cheap on a local GPU, and the
only way "masked" means anything.

Supported: `image/png`, `image/jpeg`, `image/webp`, `image/gif`, up to 5 MiB.

## Policy as Code (`siyada-policy.yaml`)

Detection says *what* the data is. The policy file says what **this organisation**
is allowed to do with it — and that decision belongs to the DPO in a reviewable
file, not to a constant inside a browser extension.

```yaml
version: 1
organization: "Emirates Health Services"
default_action: redact          # anything no class matches

justification:
  min_length: 30

classes:
  credentials:
    action: block
    matches: [password, api_key, access_key, token]

  emirates_id:
    action: break_glass
    reason: "Federal Law 2/2019, Art. 13 — dual sign-off"
    matches: [emirates_id, passport, national_id]
    approvers: [dpo@ehs.gov.ae, ciso@ehs.gov.ae, compliance@ehs.gov.ae]
    min_approvals: 2

  financial:
    action: allow_with_justification
    matches: [iban, bank_account, credit_card]

  identity:
    action: redact
    matches: [name, email, phone, face]

channels:                        # a channel may only tighten a class
  image:
    emirates_id: block
```

| Action | What the user can do |
|--------|----------------------|
| `allow` | send as-is |
| `redact` | send the redacted text / masked image; the original stays local |
| `allow_with_justification` | send the original after writing a recorded reason |
| `break_glass` | send the original after a reason **and** *N* named approvers sign off |
| `block` | the original never leaves, and the panel offers no override |

Rules that make it enforcement rather than decoration:

- **The strictest action wins.** One `break_glass` finding in a message full of
  `redact` findings governs the whole message —
  `allow < redact < allow_with_justification < break_glass < block`.
- **The server decides, the extension obeys.** The decision is made in
  `/analyze`; the panel only renders the buttons that decision permits, and the
  original is released only after `/release` grants it. There is no client-side
  "approved" flag to forge.
- **Fail closed.** A missing or malformed policy does not degrade to "allow" —
  it blocks everything, `/policy` returns 503, and the dashboard says so.
- **No self-approval**, duplicate approvers count once, unlisted approvers count
  zero, and a decision expires 10 minutes after it is issued.
- **The hash is the evidence.** The file is SHA-256'd on load; every decision and
  every audit event carries `policyHash` and `version`, so an event can be tied
  to the exact policy text that produced it. Edit the file and the hash changes.
- **Editing is a file save, not a deployment.** The server watches the file and
  reloads it live — change `emirates_id` to `block` mid-demo and the next send
  is refused.

Use `POLICY_FILE=/etc/siyada/policy.yaml` to point at a policy outside the repo
(a sector pack, a mounted ConfigMap).

```bash
curl localhost:3000/policy            # active policy, hash, load error
cd server && npm test                 # policy engine, ledger, masking geometry
```

## Audit Ledger and Evidence Packs

A compliance log that can be edited is a log nobody has to believe. Every
decision — each analysis, each release, each *refused* release — is appended to
`server/data/ledger.jsonl`, and each entry commits to the one before it:

```
hash(n) = sha256( seq | ts | hash(n-1) | canonical(event) )
seal(n) = hmac-sha256( install key, hash(n) )
```

Change, reorder or delete one entry and every entry after it stops verifying.
The chain itself is plain SHA-256, so an auditor holding the file and no secret
can recompute it; the seal means that rewriting the *whole* chain — the one
attack a public hash chain does not stop — also needs the install key
(`SIYADA_LEDGER_KEY`, or a `0600` file generated next to the ledger on first
run).

**The ledger is not a second copy of the leak.** An entry records the finding's
type, class, severity, regulation, placeholder and a keyed fingerprint of the
value — never the value, the prompt or the image. `append` walks the event and
refuses anything still carrying raw content, so a future careless caller cannot
turn the audit trail into the breach. The fingerprint is an HMAC, so the same
Emirates ID is traceable across entries within one install and meaningless
outside it.

**An unrecordable decision is not a decision.** If the append fails, `/analyze`,
`/analyze-image` and `/release` answer `503 ledger_unavailable` rather than
letting an unlogged release happen — the same fail-closed rule the policy
engine follows.

An **evidence pack** is what leaves the building: a time-ranged slice of the
chain plus everything needed to check it without this server running — the link
the slice hangs off (`startsAfter`), the chain head it ends at, the governing
policy and its hash, and a sealed manifest over the whole document.

```bash
curl 'localhost:3000/evidence?from=2026-09-01&to=2026-09-30&case=DPA-114&requestedBy=dpo@ehs.gov.ae' -o pack.json

node server/tools/verify-evidence.js pack.json                 # chain + manifest
node server/tools/verify-evidence.js pack.json --key $KEY      # + seals
```

```
chain    : intact
seals    : valid
manifest : matches

VERIFIED
```

Editing a record, dropping an inconvenient one, or rewriting the case number
all fail the check and name the entry that broke.

A host that can rewrite the ledger can also rewrite its own head, so for
non-repudiation against the operator, publish the head somewhere the operator
does not control — `GET /ledger/head` returns `{ seq, hash }` for a daily anchor
into a ticket, a signed email, or a notary service. Any pack whose head predates
the anchor is checkable against it.

## Backend / Vision Agent

```bash
cd server && npm start          # http://localhost:3000, dashboard at /
```

| Route | Purpose |
|-------|---------|
| `POST /analyze` | Text prompt analysis |
| `POST /analyze-image` | Image analysis — `{ imageBase64, mediaType }` |
| `POST /release` | Release the original — `{ decisionId, justification, requester, approvals }` |
| `GET /policy` | Active policy, its hash, and any load error |
| `GET /ledger/verify` | Recompute the audit chain; `409` and the first break if tampered |
| `GET /ledger/head` | Current head `{ seq, hash }` — anchor this off-host |
| `GET /evidence` | Sealed evidence pack — `?from=&to=&case=&requestedBy=` |
| `GET /stats` | Compliance events (text + image channels, policy action per event) |
| `GET /health` | Model, region, active vision engine, policy hash |

Default engine is Claude Haiku vision on Bedrock — a **simulation** while the
local model is being built. Point `VISION_URL` at your own service to take the
image off the cloud entirely:

```bash
VISION_URL=http://jetson.local:8000/vision npm start
```

Jetson Orin Nano / local GPU contract — accept `POST` with:

```json
{ "imageBase64": "...", "mediaType": "image/png", "prompt": "..." }
```

and return either `{ "text": "<json string>" }` or the JSON directly:

```json
{
  "hasPII": true,
  "imageDescription": "Emirates ID card, front",
  "items": [{
    "type": "emirates_id",
    "value": "784-1990-1234567-1",
    "masked": "[EMIRATES-ID]",
    "regulation": "Federal Law 2/2019, Art. 13",
    "severity": "critical",
    "box": [0.10, 0.62, 0.45, 0.08]
  }],
  "regulations": ["Federal Law 2/2019, Art. 13"],
  "summary": "Emirates ID detected",
  "safeToSend": false
}
```

A stand-in for that service ships with the repo, so the whole image flow can be
demoed with no cloud call and no credentials:

```bash
node server/tools/mock-vision.js          # MOCK_CLEAN=1  clean verdict
                                          # MOCK_STRICT=1 mask verification always fails
VISION_URL=http://localhost:3999 npm start
```

`box` is `[x, y, w, h]` as fractions of image width/height. Items without a
valid box cannot be masked, so the image is discard-or-override only.

## Loading the Extension

```
1. Open chrome://extensions
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the extension/ folder
5. Open https://gemini.google.com and try a prompt with an Emirates ID
```

**Test paste:**
```
Patient Ahmed Al-Mansouri, Emirates ID 784-1990-1234567-1,
diagnosed with type 2 diabetes at Mediclinic Al Noor.
His phone is +971-50-1234567. What medication should I prescribe?
```

## Project Structure

```
siyada-policy.yaml     Organisational policy — the DPO edits this, not the code
server/
  src/index.js         HTTP routes, agents, dashboard
  src/policy.js        Policy engine — classes, actions, release checks
  src/ledger.js        Hash-chained audit ledger and evidence packs
  tools/verify-evidence.js  Offline pack verifier (no server, no network)
  data/ledger.jsonl    The chain itself (gitignored, created on first run)
extension/
  manifest.json        Chrome extension manifest (MV3)
  lib/scanner.js       PII detection engine (zero deps, content-script safe)
  interceptor.js       DOM hooks for AI chat sites
  background.js        Service worker — compliance log storage
  popup/
    popup.html         Extension popup dashboard
    popup.js           Loads stats from background
  icons/               Shield icons (16/48/128px)
```

## Roadmap

- [x] Image/screenshot scanning (vision agent, bounding-box masking)
- [x] Policy as code with justification and break-glass dual approval
- [x] Hash-chained audit ledger with sealed, offline-verifiable evidence packs
- [ ] Signed sector policy packs (PDPL, DHA/MOH, CBUAE, DIFC/ADGM)
- [ ] Voice call monitoring (Sensor 2)
- [ ] Jetson Orin Nano vision service behind `VISION_URL`
- [ ] Backend with AWS Bedrock UAE region for compliant LLM answers
- [ ] Malaffi / NABIDH integration for healthcare orgs
- [ ] On-premise GPU deployment

## Legal

Detection is best-effort. Not a substitute for legal advice or a formal DLP
solution. Laws cited are accurate as of 2025; verify current enforcement status.
