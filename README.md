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

- [ ] Image/screenshot scanning (Tesseract.js OCR)
- [ ] Voice call monitoring (Sensor 2)
- [ ] Backend with AWS Bedrock UAE region for compliant LLM answers
- [ ] Malaffi / NABIDH integration for healthcare orgs
- [ ] On-premise GPU deployment

## Legal

Detection is best-effort. Not a substitute for legal advice or a formal DLP
solution. Laws cited are accurate as of 2025; verify current enforcement status.
