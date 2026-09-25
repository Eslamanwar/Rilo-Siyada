---
name: testing-siyada
description: Run Siyada MV3 image interception browser tests with mock vision and clearly distinguish live-site delivery from a local attachment harness.
---

# Siyada browser testing

## Runtime
- Check `SIYADA_API` in `extension/interceptor.js` and match `PORT`; do not assume port 3000.
- If Node is missing from PATH, inspect installed NVM versions. This environment has `/home/ubuntu/.nvm/versions/node/v24.19.0/bin`.
- No dependency install is needed for the backend or mock:
  - `node server/tools/mock-vision.js` (default port 3999, flagged mode).
  - `PORT=3200 VISION_URL=http://localhost:3999 node server/src/index.js`.
- Use direct Node startup to avoid requiring a `.env` file through the npm script.
- Inspect occupied ports before starting; an existing backend may already be correctly configured.
- Restart only the mock with `MOCK_CLEAN=1` to exercise clean verdicts; stop the backend for fail-closed.

## Extension and real-site access
- Load `extension/` using Chrome Developer mode → Load unpacked. After code changes use **Reload**, then refresh target tabs to replace old content-script contexts.
- A real signed-out Gemini composer may be available while its Upload files control remains disabled. Claude may redirect to login; Copilot may be region-gated. Never equate an empty signed-out composer with proof that image delivery was blocked.
- An authenticated live-site test is required to prove synthetic events are accepted by that site's real handlers.
- Use Chrome's image context menu → Copy image, then native Ctrl+V; synthetic paste events are deliberately ignored by the interceptor.
- For drop, drag a real image file from the OS file manager and capture the gesture before releasing. For picker, use the native file dialog.

## Authorized local harness
- If explicitly authorized, a localhost page can expose a contenteditable composer, file input and drop zone with handlers that render the actual received File objects, filenames, byte lengths and SHA-256 values.
- Temporarily add localhost to both manifest `host_permissions` and content-script `matches`, reload extension, and refresh harness. Revert these additions and reload before finishing; do not commit them.
- Harness results prove extension event delivery only, not Gemini/Claude framework compatibility.
- Generate fictional ID art aligned to `mock-vision.js` boxes. Save the delivered masked PNG and open that file to inspect opaque pixels.
- Browser clipboard PNG encoding may differ from the disk fixture. Compare picker override bytes directly to the disk fixture; compare paste override to clean paste from the same clipboard.

## Audit checks
- Check discard, masked and override outcomes separately in the popup; count must advance once per decision and discard must still deliver zero files.
- Reload the unpacked extension after on-disk script changes before interpreting an empty popup. If empty, read storage and runtime stats to distinguish rendering failure from data loss; never clear the log to diagnose it.
- The popup currently uses readable IMAGE/TEXT badges and outcome tags; systems without emoji fonts may show placeholder glyphs elsewhere.
- Backend dashboard `/` contains image analysis rows, not extension approval outcomes. Backend events are in memory and reset on process restart.

## Devin Secrets Needed
- None when using mock vision.
- A user-authenticated supported AI-site browser session is needed for live attachment delivery tests; do not assume credentials or attempt login without authorization.
