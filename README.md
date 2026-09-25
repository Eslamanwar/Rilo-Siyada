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

## Backend / Vision Agent

```bash
cd server && npm start          # http://localhost:3000, dashboard at /
```

| Route | Purpose |
|-------|---------|
| `POST /analyze` | Text prompt analysis |
| `POST /analyze-image` | Image analysis — `{ imageBase64, mediaType }` |
| `GET /stats` | Compliance events (text + image channels) |
| `GET /health` | Model, region, active vision engine |

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
- [ ] Voice call monitoring (Sensor 2)
- [ ] Jetson Orin Nano vision service behind `VISION_URL`
- [ ] Backend with AWS Bedrock UAE region for compliant LLM answers
- [ ] Malaffi / NABIDH integration for healthcare orgs
- [ ] On-premise GPU deployment

## Legal

Detection is best-effort. Not a substitute for legal advice or a formal DLP
solution. Laws cited are accurate as of 2025; verify current enforcement status.
