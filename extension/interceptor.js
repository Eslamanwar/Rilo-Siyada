/**
 * Siyada Interceptor
 *
 * Injected into AI chat sites (Gemini, ChatGPT, Claude, Copilot).
 *
 * Text flow:
 *   1. While typing  → fast regex scan (scanner.js) updates the badge
 *   2. On Enter/Send → text sent to Siyada backend LLM agent
 *   3. LLM decides   → if PII found, overlay shows what was caught
 *   4. User chooses  → "Keep Editing" or "Send Redacted Version"
 *
 * Image flow:
 *   1. Paste / drop / file picker → the attachment is held before the site sees it
 *   2. Downscaled copy sent to the vision agent, which reads the image and
 *      returns findings with normalized bounding boxes
 *   3. If sensitive → overlay shows the image with the regions marked
 *   4. User chooses  → discard, attach a masked copy, or override (logged)
 */

(() => {
  'use strict';

  if (window.__siyadaLoaded) return;
  window.__siyadaLoaded = true;

  // ─── Config ────────────────────────────────────────────────────────────────
  // Change to deployed URL when running on a server
  const SIYADA_API = 'http://localhost:3200';

  // ─── Site selectors ────────────────────────────────────────────────────────

  const SITE_SELECTORS = {
    'gemini.google.com': {
      inputs: [
        'rich-textarea .ql-editor',
        'rich-textarea div[contenteditable="true"]',
        'div.ql-editor[contenteditable="true"]',
        'div[contenteditable="true"]',
        'textarea',
      ],
      sendBtns: [
        'button[aria-label="Send message"]',
        'button[aria-label="Send Message"]',
        'button.send-button',
        'button[data-test-id="send-button"]',
      ],
    },
    'chatgpt.com': {
      inputs: ['#prompt-textarea', 'div[contenteditable="true"][data-id]', 'textarea[placeholder]'],
      sendBtns: ['button[data-testid="send-button"]', 'button[aria-label="Send message"]'],
    },
    'chat.openai.com': {
      inputs: ['#prompt-textarea', 'textarea[placeholder]'],
      sendBtns: ['button[data-testid="send-button"]'],
    },
    'claude.ai': {
      inputs: ['div.ProseMirror[contenteditable="true"]', 'div[contenteditable="true"]'],
      sendBtns: ['button[aria-label="Send Message"]', 'button[aria-label="Send message"]'],
    },
    'copilot.microsoft.com': {
      inputs: ['textarea[id*="userInput"]', 'textarea', 'div[contenteditable="true"]'],
      sendBtns: ['button[aria-label*="send" i]', 'button[type="submit"]'],
    },
  };

  function getSiteSelectors() {
    const host = location.hostname;
    for (const key of Object.keys(SITE_SELECTORS)) {
      if (host.includes(key)) return SITE_SELECTORS[key];
    }
    return {
      inputs:   ['div[contenteditable="true"]', 'textarea'],
      sendBtns: ['button[type="submit"]', 'button[aria-label*="send" i]'],
    };
  }

  function querySelector(selectors) {
    for (const sel of selectors) {
      try { const el = document.querySelector(sel); if (el) return el; } catch { /**/ }
    }
    return null;
  }

  function getInputText(el) {
    if (!el) return '';
    if (el.isContentEditable) return el.innerText || el.textContent || '';
    return el.value || '';
  }

  // ─── Overlay (Shadow DOM) ──────────────────────────────────────────────────

  let overlayHost = null;
  let shadow      = null;
  let pendingData = null; // { redactedText, inputEl }

  const CSS = `
    * { box-sizing: border-box; margin: 0; padding: 0; }

    #panel {
      display: none;
      width: 440px;
      background: #0D1117;
      border: 1px solid #21262D;
      border-radius: 14px;
      overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      color: #E6EDF3;
      box-shadow: 0 12px 40px rgba(0,0,0,0.7);
      animation: slideIn .22s ease-out;
    }
    #panel.visible { display: block; }

    @keyframes slideIn {
      from { opacity: 0; transform: translateY(14px) scale(.98); }
      to   { opacity: 1; transform: translateY(0) scale(1); }
    }

    /* Loading state */
    #loading {
      display: none;
      padding: 28px 20px;
      text-align: center;
    }
    #loading.visible { display: block; }
    .spinner {
      width: 32px; height: 32px;
      border: 3px solid #21262D;
      border-top-color: #00D4AA;
      border-radius: 50%;
      animation: spin .8s linear infinite;
      margin: 0 auto 12px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .loading-text { color: #8B949E; font-size: 13px; }

    /* Header */
    .hdr {
      display: flex; align-items: center; gap: 10px;
      padding: 14px 16px;
      background: linear-gradient(135deg,#161B22,#0D1117);
      border-bottom: 1px solid #21262D;
    }
    .hdr-title { font-weight: 700; font-size: 15px; color: #00D4AA; flex: 1; }
    .hdr-close {
      background: none; border: none; color: #8B949E;
      cursor: pointer; font-size: 18px; line-height: 1; padding: 0 4px;
    }
    .hdr-close:hover { color: #E6EDF3; }

    /* Alert */
    .alert {
      padding: 10px 16px; font-size: 13px; font-weight: 600;
      display: flex; align-items: center; gap: 8px;
    }
    .alert.critical { background: rgba(255,59,59,.15);  color: #FF6B6B; border-bottom: 1px solid rgba(255,59,59,.3); }
    .alert.high     { background: rgba(255,107,53,.15); color: #FF8C61; border-bottom: 1px solid rgba(255,107,53,.3); }
    .alert.medium   { background: rgba(255,193,7,.12);  color: #FFD60A; border-bottom: 1px solid rgba(255,193,7,.25); }
    .alert.low      { background: rgba(139,148,158,.1); color: #8B949E; border-bottom: 1px solid #21262D; }

    /* Summary from LLM */
    .summary {
      padding: 10px 16px; font-size: 12px; color: #8B949E;
      border-bottom: 1px solid #21262D; font-style: italic;
    }

    /* Items */
    .items { padding: 12px 16px; display: flex; flex-direction: column; gap: 7px; max-height: 200px; overflow-y: auto; }
    .item {
      background: #161B22; border: 1px solid #21262D;
      border-radius: 8px; padding: 9px 12px;
    }
    .item-row { display: flex; align-items: center; gap: 8px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .dot-critical { background: #FF3B3B; }
    .dot-high     { background: #FF8C61; }
    .dot-medium   { background: #FFD60A; }
    .dot-low      { background: #8B949E; }
    .item-type {
      font-size: 11px; font-weight: 700; text-transform: uppercase;
      letter-spacing: .5px; color: #8B949E;
    }
    .item-value {
      font-family: 'Courier New', monospace; font-size: 12px; color: #E6EDF3;
      flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .item-reg { font-size: 11px; color: #8B949E; padding-left: 16px; margin-top: 3px; }

    /* Fine notice */
    .fine { padding: 8px 16px; font-size: 11px; color: #8B949E; border-top: 1px solid #21262D; }
    .fine strong { color: #FF6B6B; }

    /* Actions */
    .actions { display: flex; gap: 10px; padding: 12px 16px; border-top: 1px solid #21262D; }
    .btn { flex: 1; padding: 10px 12px; border-radius: 8px; border: none; cursor: pointer; font-size: 13px; font-weight: 600; transition: opacity .15s; }
    .btn:hover { opacity: .85; }
    .btn-block  { background: #21262D; color: #E6EDF3; border: 1px solid #30363D; }
    .btn-redact { background: #00D4AA; color: #0D1117; }

    /* Redacted preview */
    #preview { display: none; border-top: 1px solid #21262D; padding: 12px 16px; }
    #preview.visible { display: block; }
    .preview-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; color: #00D4AA; margin-bottom: 8px; }
    .preview-box {
      background: #161B22; border: 1px solid #21262D; border-radius: 6px;
      padding: 10px 12px; font-size: 12px; color: #8B949E; line-height: 1.5;
      max-height: 110px; overflow-y: auto; word-break: break-word;
    }
    .preview-actions { display: flex; gap: 8px; margin-top: 10px; }
    .btn-send {
      flex: 1; padding: 9px 12px; background: #1F6FEB; color: #fff;
      border: none; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    }
    .btn-send:hover { background: #388BFD; }
    .btn-copy {
      padding: 9px 12px; background: #21262D; color: #E6EDF3;
      border: 1px solid #30363D; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    }

    /* Badge */
    #badge {
      width: 38px; height: 38px; border-radius: 50%;
      background: #0D1117; border: 2px solid #00D4AA;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; font-size: 18px;
      box-shadow: 0 2px 8px rgba(0,0,0,.5);
      transition: border-color .2s, transform .15s;
      margin-top: 8px; float: right;
    }
    #badge:hover { transform: scale(1.08); }
    #badge.safe     { border-color: #00D4AA; }
    #badge.scanning { border-color: #FFD60A; }
    #badge.danger   { border-color: #FF6B6B; animation: pulse 1.5s infinite; }
    @keyframes pulse {
      0%,100% { box-shadow: 0 0 0 0 rgba(255,107,107,.4); }
      50%      { box-shadow: 0 0 0 6px rgba(255,107,107,0); }
    }

    /* Mic button */
    #mic-btn {
      width: 38px; height: 38px; border-radius: 50%;
      background: #0D1117; border: 2px solid #3B82F6;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; font-size: 18px;
      box-shadow: 0 2px 8px rgba(0,0,0,.5);
      transition: border-color .2s, transform .15s;
      margin-top: 6px; float: right; clear: right;
      user-select: none;
    }
    #mic-btn:hover { transform: scale(1.08); }
    #mic-btn.idle     { border-color: #3B82F6; }
    #mic-btn.recording {
      border-color: #FF3B3B;
      animation: micpulse 1s infinite;
    }
    #mic-btn.processing { border-color: #FFD60A; }
    @keyframes micpulse {
      0%,100% { box-shadow: 0 0 0 0 rgba(255,59,59,.5); }
      50%      { box-shadow: 0 0 0 8px rgba(255,59,59,0); }
    }
    #mic-toast {
      display: none;
      position: absolute; bottom: 52px; right: 0;
      background: #161B22; border: 1px solid #21262D;
      border-radius: 8px; padding: 6px 10px;
      font-size: 12px; color: #8B949E;
      white-space: nowrap;
      box-shadow: 0 4px 12px rgba(0,0,0,.5);
    }
    #mic-toast.visible { display: block; }

    /* Image review */
    .img-preview {
      padding: 12px 16px 0;
      display: flex; justify-content: center;
    }
    .img-preview canvas {
      max-width: 100%; border-radius: 8px;
      border: 1px solid #21262D; background: #161B22;
    }
    .img-note {
      padding: 8px 16px 0; font-size: 11px; color: #8B949E;
    }
    .override { padding: 0 16px 12px; }
    .btn-override {
      width: 100%; background: none; border: none; cursor: pointer;
      color: #8B949E; font-size: 11px; text-decoration: underline; padding: 4px;
    }
    .btn-override:hover { color: #FF8C61; }
  `;

  function createOverlay() {
    if (overlayHost) return;
    overlayHost = document.createElement('div');
    overlayHost.id = 'siyada-overlay-host';
    overlayHost.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2147483647;';
    document.documentElement.appendChild(overlayHost);
    shadow = overlayHost.attachShadow({ mode: 'open' });

    shadow.innerHTML = `<style>${CSS}</style>
      <div id="panel">
        <!-- Loading state -->
        <div id="loading">
          <div class="spinner"></div>
          <div class="loading-text" id="loadingText">Siyada is analyzing for UAE PII…</div>
        </div>

        <!-- Results (hidden until analysis done) -->
        <div id="results" style="display:none">
          <div class="hdr">
            <span style="font-size:20px">🛡️</span>
            <span class="hdr-title">Siyada — Data Protected</span>
            <button class="hdr-close" id="closeBtn">✕</button>
          </div>
          <div class="alert" id="alertBanner">
            <span id="alertIcon">⚠️</span>
            <span id="alertText"></span>
          </div>
          <div class="summary" id="summaryText"></div>
          <div class="items" id="itemsList"></div>
          <div class="fine">
            Sending may violate <strong id="topReg"></strong> — fine up to <strong>AED 2,000,000</strong>
          </div>
          <div class="actions">
            <button class="btn btn-block"  id="blockBtn">✕ Keep Editing</button>
            <button class="btn btn-redact" id="redactBtn">🛡️ Show Redacted</button>
          </div>
          <div id="preview">
            <div class="preview-label">✅ Redacted version — safe to send</div>
            <div class="preview-box" id="previewBox"></div>
            <div class="preview-actions">
              <button class="btn-send" id="sendBtn">Send Redacted Version</button>
              <button class="btn-copy" id="copyBtn">Copy</button>
            </div>
          </div>
        </div>

        <!-- Image review (hidden until an attachment is analyzed) -->
        <div id="imgResults" style="display:none">
          <div class="hdr">
            <span style="font-size:20px">🖼️</span>
            <span class="hdr-title">Siyada — Attachment Blocked</span>
            <button class="hdr-close" id="imgCloseBtn">✕</button>
          </div>
          <div class="alert" id="imgAlert">
            <span>⚠️</span>
            <span id="imgAlertText"></span>
          </div>
          <div class="summary" id="imgSummary"></div>
          <div class="img-preview"><canvas id="imgCanvas"></canvas></div>
          <div class="img-note" id="imgNote"></div>
          <div class="items" id="imgItems"></div>
          <div class="fine">
            Uploading may violate <strong id="imgTopReg"></strong> — fine up to <strong>AED 2,000,000</strong>
          </div>
          <div class="actions">
            <button class="btn btn-block"  id="imgDiscardBtn">✕ Discard Image</button>
            <button class="btn btn-redact" id="imgMaskBtn">🛡️ Attach Masked Copy</button>
          </div>
          <div class="override">
            <button class="btn-override" id="imgOverrideBtn">Attach original anyway — recorded as a policy override</button>
          </div>
        </div>
      </div>
      <div id="badge" title="Siyada — UAE AI Shield">🛡️</div>
      <div id="mic-btn" class="idle" title="Voice input — Arabic &amp; English">🎤</div>
      <div id="mic-toast"></div>`;

    bindEvents();
  }

  function bindEvents() {
    const panel    = shadow.getElementById('panel');
    const badge    = shadow.getElementById('badge');
    shadow.getElementById('closeBtn').addEventListener('click', () => {
      panel.classList.remove('visible');
      if (pendingData?.inputEl) pendingData.inputEl.focus();
    });
    shadow.getElementById('blockBtn').addEventListener('click', () => {
      panel.classList.remove('visible');
      if (pendingData?.inputEl) pendingData.inputEl.focus();
    });
    shadow.getElementById('redactBtn').addEventListener('click', () => {
      const text = pendingData?.redactedText;
      if (!text) return;
      shadow.getElementById('previewBox').textContent = text;
      shadow.getElementById('preview').classList.add('visible');
    });
    shadow.getElementById('sendBtn').addEventListener('click', () => {
      if (!pendingData) return;
      injectAndSend(pendingData.inputEl, pendingData.redactedText);
      panel.classList.remove('visible');
    });
    shadow.getElementById('copyBtn').addEventListener('click', () => {
      const text = shadow.getElementById('previewBox').textContent;
      navigator.clipboard.writeText(text).catch(() => {});
      const btn = shadow.getElementById('copyBtn');
      btn.textContent = '✓ Copied';
      setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
    });
    badge.addEventListener('click', () => panel.classList.toggle('visible'));

    // ── Image review actions ────────────────────────────────────────────────
    shadow.getElementById('imgCloseBtn').addEventListener('click',    () => resolveImageReview('discard'));
    shadow.getElementById('imgDiscardBtn').addEventListener('click',  () => resolveImageReview('discard'));
    shadow.getElementById('imgMaskBtn').addEventListener('click',     () => resolveImageReview('mask'));
    shadow.getElementById('imgOverrideBtn').addEventListener('click', () => resolveImageReview('override'));

    // ── Voice recording ──────────────────────────────────────────────────────
    const micBtn   = shadow.getElementById('mic-btn');
    const micToast = shadow.getElementById('mic-toast');
    let mediaRec   = null;
    let audioChunks = [];

    function setMicToast(msg) {
      if (!msg) { micToast.classList.remove('visible'); return; }
      micToast.textContent = msg;
      micToast.classList.add('visible');
    }

    async function startRecording() {
      let stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      } catch {
        setMicToast('Microphone access denied');
        setTimeout(() => setMicToast(''), 2500);
        return;
      }

      audioChunks = [];
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : 'audio/webm';

      mediaRec = new MediaRecorder(stream, { mimeType });
      mediaRec.ondataavailable = e => { if (e.data.size) audioChunks.push(e.data); };
      mediaRec.onstop = () => {
        stream.getTracks().forEach(t => t.stop());
        processAudio(new Blob(audioChunks, { type: mimeType }), mimeType);
      };
      mediaRec.start();
      micBtn.className = 'recording';
      micBtn.textContent = '⏹️';
      setMicToast('Recording… click to stop');
    }

    function stopRecording() {
      if (mediaRec && mediaRec.state === 'recording') {
        mediaRec.stop();
        micBtn.className = 'processing';
        micBtn.textContent = '⏳';
        setMicToast('Transcribing…');
      }
    }

    async function processAudio(blob, mimeType) {
      try {
        const res = await fetch(`${SIYADA_API}/transcribe`, {
          method:  'POST',
          headers: { 'Content-Type': mimeType },
          body:    blob,
          signal:  AbortSignal.timeout(30_000),
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);

        const text = data.text || '';
        const lang = data.language === 'ar' ? 'Arabic' : (data.language || '').toUpperCase();
        setMicToast(text ? `${lang}: "${text.slice(0, 50)}${text.length > 50 ? '…' : ''}"` : 'Nothing heard');

        if (text) {
          const target = findActiveInput() || inputEl;
          if (target) injectText(target, text);
        }
      } catch (err) {
        setMicToast(`Voice error: ${err.message}`);
      } finally {
        micBtn.className = 'idle';
        micBtn.textContent = '🎤';
        setTimeout(() => setMicToast(''), 4000);
      }
    }

    micBtn.addEventListener('click', () => {
      if (mediaRec && mediaRec.state === 'recording') stopRecording();
      else startRecording();
    });
  }

  function injectText(el, text) {
    if (el.isContentEditable) {
      el.focus();
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand('insertText', false, text);
    } else {
      const descriptor = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
      if (descriptor?.set) descriptor.set.call(el, text);
      else el.value = text;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  // ─── Show loading / show results ──────────────────────────────────────────

  function showLoading(inputEl) {
    createOverlay();
    pendingData = { inputEl, redactedText: '' };
    setBadge('scanning');
    shadow.getElementById('loading').classList.add('visible');
    shadow.getElementById('results').style.display = 'none';
    shadow.getElementById('preview').classList.remove('visible');
    shadow.getElementById('panel').classList.add('visible');
  }

  function showResults(analysis, inputEl) {
    shadow.getElementById('loading').classList.remove('visible');
    shadow.getElementById('results').style.display = 'block';
    shadow.getElementById('imgResults').style.display = 'none';

    const { items = [], summary = '', regulations = [] } = analysis;
    const severity = items[0]?.severity || 'medium';

    pendingData = { inputEl, redactedText: analysis.redactedText || '' };

    // Alert banner
    const banner = shadow.getElementById('alertBanner');
    banner.className = `alert ${severity}`;
    shadow.getElementById('alertText').textContent =
      `${items.length} PII item${items.length !== 1 ? 's' : ''} detected`;

    // Summary
    shadow.getElementById('summaryText').textContent = summary;

    // Items list
    const list = shadow.getElementById('itemsList');
    list.innerHTML = items.map(item => {
      const display = (item.value || '').length > 32
        ? (item.value || '').slice(0, 30) + '…'
        : (item.value || '—');
      return `<div class="item">
        <div class="item-row">
          <div class="dot dot-${item.severity || 'medium'}"></div>
          <div class="item-type">${esc(item.type || '').replace(/_/g,' ')}</div>
          <div class="item-value">${esc(display)}</div>
        </div>
        <div class="item-reg">${esc(item.regulation || '')}</div>
      </div>`;
    }).join('');

    // Top regulation
    shadow.getElementById('topReg').textContent = regulations[0] || items[0]?.regulation || 'UAE PDPL';

    setBadge('danger');
  }

  function showClean() {
    shadow.getElementById('panel').classList.remove('visible');
    shadow.getElementById('imgResults').style.display = 'none';
    setBadge('safe');
    pendingData = null;
  }

  function showBackendError(err) {
    createOverlay();
    pendingData = null;
    setBadge('danger');

    // Re-use the panel but show error state
    shadow.getElementById('loading').classList.remove('visible');
    shadow.getElementById('results').style.display = 'block';
    shadow.getElementById('imgResults').style.display = 'none';
    shadow.getElementById('preview').classList.remove('visible');

    shadow.getElementById('alertBanner').className = 'alert critical';
    shadow.getElementById('alertIcon').textContent = '🔴';
    shadow.getElementById('alertText').textContent = 'Siyada backend unreachable — send blocked';
    shadow.getElementById('summaryText').textContent =
      'Cannot verify this message for PII. Start the Siyada server to continue.';
    shadow.getElementById('itemsList').innerHTML =
      `<div class="item"><div class="item-row">
        <div class="dot dot-critical"></div>
        <div class="item-type">server error</div>
        <div class="item-value">${esc(String(err?.message || 'Connection refused'))}</div>
      </div>
      <div class="item-reg">Run: cd server &amp;&amp; npm run dev</div></div>`;
    shadow.getElementById('topReg').textContent = 'Siyada server required';
    // Hide the redact button — nothing to redact without analysis
    shadow.getElementById('redactBtn').style.display = 'none';

    shadow.getElementById('panel').classList.add('visible');
  }

  function setBadge(state) {
    createOverlay();
    const badge = shadow.getElementById('badge');
    if (badge) badge.className = state;
  }

  function esc(str) {
    return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ─── Inject redacted text and trigger send ────────────────────────────────

  function injectAndSend(el, text) {
    if (!el) return;
    if (el.isContentEditable) {
      el.focus();
      // Modern: select all text via Selection API then replace via insertText
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);
      // insertText is still the right input-event approach for contenteditables
      // eslint-disable-next-line no-restricted-globals
      document.execCommand('insertText', false, text); // still works in Chrome MV3 content scripts
    } else {
      // Textarea: use native setter so React/Vue state updates fire
      const descriptor = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
      if (descriptor?.set) descriptor.set.call(el, text);
      else el.value = text;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
    setTimeout(() => {
      el.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true,
      }));
    }, 120);
  }

  // ─── Image interception ─────────────────────────────────────────────────
  // The attachment is held before the page ever receives it: the paste, drop or
  // file-picker event is cancelled, the image is analyzed, and only an approved
  // copy is re-injected through a synthetic event.

  const VISION_MEDIA_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
  const MAX_ANALYSIS_EDGE  = 1568; // Claude's recommended long edge — larger buys nothing
  const MAX_ANALYSIS_BYTES = 4 * 1024 * 1024;
  const BOX_PAD_RATIO      = 0.18;  // grow each box by 18% of its own size
  const MIN_BOX_PAD_PX     = 8;     // …and never by less than 8px

  let imageReview  = null; // { results, allFiles, reinject }
  let scanningImage = false;

  const isImageFile = f => f instanceof File && f.type.startsWith('image/');

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = () => resolve(String(reader.result).split(',')[1] || '');
      reader.onerror = () => reject(new Error('Could not read the image'));
      reader.readAsDataURL(file);
    });
  }

  function canvasToBlob(canvas, type, quality) {
    return new Promise((resolve, reject) => {
      canvas.toBlob(b => b ? resolve(b) : reject(new Error('Could not encode the image')), type, quality);
    });
  }

  // Downscale and re-encode only when needed, so a small PNG is analyzed as-is.
  async function prepareForAnalysis(file) {
    const bitmap = await createImageBitmap(file);
    const edge   = Math.max(bitmap.width, bitmap.height);
    const scale  = Math.min(1, MAX_ANALYSIS_EDGE / edge);
    const keepAsIs = scale === 1 &&
      VISION_MEDIA_TYPES.includes(file.type) &&
      file.size <= MAX_ANALYSIS_BYTES;

    if (keepAsIs) {
      return { base64: await fileToBase64(file), mediaType: file.type, bitmap };
    }

    const canvas = document.createElement('canvas');
    canvas.width  = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);

    const blob = await canvasToBlob(canvas, 'image/jpeg', 0.9);
    const b64  = await fileToBase64(new File([blob], 'scan.jpg', { type: 'image/jpeg' }));
    return { base64: b64, mediaType: 'image/jpeg', bitmap };
  }

  // A model's box is approximate: it clips ascenders, stops short of the last
  // digit, drifts a few percent. Grow every box before burning it in.
  function padBox(box, w, h) {
    const [x, y, bw, bh] = box;
    const padX = Math.max(bw * BOX_PAD_RATIO, MIN_BOX_PAD_PX / w);
    const padY = Math.max(bh * BOX_PAD_RATIO, MIN_BOX_PAD_PX / h);
    const x0 = Math.max(0, x - padX);
    const y0 = Math.max(0, y - padY);
    const x1 = Math.min(1, x + bw + padX);
    const y1 = Math.min(1, y + bh + padY);
    return [x0, y0, x1 - x0, y1 - y0];
  }

  // Burn opaque boxes over every located finding, at full resolution.
  async function maskImageFile(file, items) {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement('canvas');
    canvas.width  = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0);

    const fontSize = Math.max(11, Math.round(bitmap.height / 45));
    ctx.font = `700 ${fontSize}px sans-serif`;
    ctx.textBaseline = 'middle';

    for (const item of items) {
      if (!item.box) continue;
      const [x, y, w, h] = padBox(item.box, bitmap.width, bitmap.height);
      const px = x * bitmap.width;
      const py = y * bitmap.height;
      const pw = w * bitmap.width;
      const ph = h * bitmap.height;
      ctx.fillStyle = '#000000';
      ctx.fillRect(px, py, pw, ph);
      ctx.fillStyle = '#00D4AA';
      const label = item.masked || `[${String(item.type || 'REDACTED').toUpperCase()}]`;
      if (pw > label.length * fontSize * 0.5) {
        ctx.fillText(label, px + 4, py + ph / 2);
      }
    }

    const blob = await canvasToBlob(canvas, 'image/png');
    const stem = (file.name || 'image').replace(/\.[^.]+$/, '');
    return new File([blob], `siyada-masked-${stem}.png`, { type: 'image/png' });
  }

  function showMaskingProgress() {
    shadow.getElementById('imgResults').style.display = 'none';
    shadow.getElementById('loadingText').textContent = 'Masking and re-checking the copy…';
    shadow.getElementById('loading').classList.add('visible');
    shadow.getElementById('panel').classList.add('visible');
    setBadge('scanning');
  }

  function showMaskFailure(count) {
    shadow.getElementById('loading').classList.remove('visible');
    shadow.getElementById('imgResults').style.display = 'block';
    shadow.getElementById('imgAlert').className = 'alert critical';
    shadow.getElementById('imgAlertText').textContent =
      `${count} image${count !== 1 ? 's' : ''} still readable after masking — not attached`;
    shadow.getElementById('imgSummary').textContent =
      'The masked copy was re-read and sensitive data was still visible, so it was dropped.';
    shadow.getElementById('imgMaskBtn').style.display = 'none';
    shadow.getElementById('imgNote').textContent =
      'Crop or redact the image yourself before attaching it.';
    shadow.getElementById('panel').classList.add('visible');
  }

  function showImageLoading() {
    createOverlay();
    setBadge('scanning');
    shadow.getElementById('results').style.display = 'none';
    shadow.getElementById('imgResults').style.display = 'none';
    shadow.getElementById('loading').classList.add('visible');
    shadow.getElementById('panel').classList.add('visible');
  }

  function drawPreview(bitmap, items) {
    const canvas = shadow.getElementById('imgCanvas');
    const scale  = Math.min(1, 400 / bitmap.width);
    canvas.width  = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);

    // Opaque, like the real mask: a see-through preview reads as a failed
    // redaction, and the padded box is what actually gets covered.
    ctx.lineWidth   = 2;
    ctx.strokeStyle = '#FF3B3B';
    ctx.fillStyle   = '#000000';
    for (const item of items) {
      if (!item.box) continue;
      const [x, y, w, h] = padBox(item.box, bitmap.width, bitmap.height);
      const px = x * canvas.width;
      const py = y * canvas.height;
      const pw = w * canvas.width;
      const ph = h * canvas.height;
      ctx.fillRect(px, py, pw, ph);
      ctx.strokeRect(px, py, pw, ph);
    }
  }

  function showImageResults(review) {
    const { results } = review;
    const flagged = results.filter(r => r.analysis.hasPII);
    const items   = flagged.flatMap(r => r.analysis.items || []);
    const first   = flagged[0];

    shadow.getElementById('loading').classList.remove('visible');
    shadow.getElementById('results').style.display = 'none';
    shadow.getElementById('imgResults').style.display = 'block';

    const severity = ['critical','high','medium','low']
      .find(s => items.some(i => i.severity === s)) || 'medium';

    shadow.getElementById('imgAlert').className = `alert ${severity}`;
    shadow.getElementById('imgAlertText').textContent =
      `${items.length} sensitive item${items.length !== 1 ? 's' : ''} found in ${flagged.length} image${flagged.length !== 1 ? 's' : ''}`;
    shadow.getElementById('imgSummary').textContent =
      first.analysis.summary || first.analysis.imageDescription || '';

    drawPreview(first.bitmap, first.analysis.items || []);

    const maskable = flagged.every(r => r.analysis.maskable);
    shadow.getElementById('imgMaskBtn').style.display = maskable ? '' : 'none';
    shadow.getElementById('imgNote').textContent = maskable
      ? 'Preview only — masking burns these regions out of the file, then re-reads the copy to confirm nothing is still legible.'
      : 'The model could not locate every finding precisely, so a masked copy is not offered for this image.';

    shadow.getElementById('imgItems').innerHTML = items.map(item => {
      const value = String(item.value || '');
      const display = value.length > 32 ? `${value.slice(0, 30)}…` : (value || '—');
      return `<div class="item">
        <div class="item-row">
          <div class="dot dot-${item.severity || 'medium'}"></div>
          <div class="item-type">${esc(String(item.type || '').replace(/_/g, ' '))}</div>
          <div class="item-value">${esc(display)}</div>
        </div>
        <div class="item-reg">${esc(item.regulation || '')}</div>
      </div>`;
    }).join('');

    shadow.getElementById('imgTopReg').textContent =
      first.analysis.regulations?.[0] || items[0]?.regulation || 'UAE PDPL';

    shadow.getElementById('panel').classList.add('visible');
    setBadge('danger');
  }

  async function resolveImageReview(choice) {
    const review = imageReview;
    if (!review) return;
    imageReview = null;
    shadow.getElementById('panel').classList.remove('visible');

    if (choice === 'discard') {
      logImageEvent(review, 'discarded');
      setBadge('safe');
      return;
    }

    if (choice === 'override') {
      logImageEvent(review, 'override');
      review.reinject(review.allFiles);
      setBadge('danger');
      return;
    }

    // mask: clean images pass through untouched, flagged ones are masked —
    // then re-read to prove the redaction actually landed on the data.
    showMaskingProgress();
    const approved = [];
    let unverified = 0;
    for (const file of review.allFiles) {
      const result = review.results.find(r => r.file === file);
      if (!result || !result.analysis.hasPII) { approved.push(file); continue; }
      if (!result.analysis.maskable) { unverified++; continue; }
      try {
        const masked = await maskImageFile(file, result.analysis.items || []);
        if (await maskHolds(masked)) approved.push(masked);
        else unverified++;
      } catch {
        unverified++; // drop the image rather than attach it unmasked
      }
    }

    logImageEvent(review, unverified ? 'mask_failed' : 'masked');
    if (approved.length) review.reinject(approved);

    if (unverified) {
      showMaskFailure(unverified);
      setBadge('danger');
      return;
    }
    shadow.getElementById('panel').classList.remove('visible');
    setBadge('safe');
  }

  // Send the masked copy back through the same agent. Anything still readable
  // comes back flagged, and the copy is dropped instead of attached.
  async function maskHolds(maskedFile) {
    try {
      const { base64, mediaType } = await prepareForAnalysis(maskedFile);
      const res = await fetch(`${SIYADA_API}/analyze-image`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ imageBase64: base64, mediaType }),
        signal:  AbortSignal.timeout(60_000),
      });
      if (!res.ok) return false;
      return !(await res.json()).hasPII;
    } catch {
      return false; // unverified means blocked, same as everywhere else
    }
  }

  function logImageEvent(review, outcome) {
    const items = review.results.flatMap(r => r.analysis.items || []);
    chrome.runtime.sendMessage({
      type:      'SIYADA_INTERCEPTION',
      source:    'image',
      outcome,
      items:     items.map(i => ({ type: i.type, regulation: i.regulation, severity: i.severity })),
      url:       location.href,
      timestamp: Date.now(),
      severity:  ['critical','high','medium','low'].find(s => items.some(i => i.severity === s)) || 'medium',
    }).catch(() => {});
  }

  // Returns true when Siyada has taken ownership of the attachment.
  async function guardImageAttachment(fileList, reinject) {
    const files  = Array.from(fileList || []);
    const images = files.filter(isImageFile);
    if (!images.length) return false;
    if (scanningImage) return true;

    scanningImage = true;
    showImageLoading();

    const results = [];
    try {
      for (const file of images) {
        const { base64, mediaType, bitmap } = await prepareForAnalysis(file);
        const res = await fetch(`${SIYADA_API}/analyze-image`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ imageBase64: base64, mediaType }),
          signal:  AbortSignal.timeout(60_000),
        });
        if (!res.ok) throw new Error(`Server error ${res.status}`);
        results.push({ file, bitmap, analysis: await res.json() });
      }
    } catch (err) {
      // Same posture as text: unverified means blocked, never attached.
      scanningImage = false;
      showBackendError(err);
      return true;
    }
    scanningImage = false;

    if (!results.some(r => r.analysis.hasPII)) {
      showClean();
      reinject(files);
      return true;
    }

    imageReview = { results, allFiles: files, reinject };
    showImageResults(imageReview);
    return true;
  }

  function toDataTransfer(files) {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    return dt;
  }

  // ─── Core intercept ────────────────────────────────────────────────────────

  let inputEl      = null;
  let analyzing    = false;

  async function handleBeforeSend(e) {
    // Always block first — never let the event through before we've checked.
    // If the input turns out to be empty we'll re-fire it below.
    e.preventDefault();
    e.stopImmediatePropagation();

    if (analyzing) return; // already checking a previous send

    const text = getInputText(inputEl);
    if (!text.trim()) {
      // Nothing typed — re-fire so a blank Enter still works (e.g. new line in some sites)
      inputEl?.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true,
      }));
      return;
    }

    analyzing = true;
    showLoading(inputEl);

    let analysis;
    try {
      const res = await fetch(`${SIYADA_API}/analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ text }),
        signal:  AbortSignal.timeout(18_000),
      });
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      analysis = await res.json();
    } catch (err) {
      // Backend unreachable — block the send and show an error.
      // Never silently pass through: "failed open" is not a compliance posture.
      analyzing = false;
      showBackendError(err);
      return;
    }

    analyzing = false;

    if (!analysis.hasPII) {
      // LLM confirmed clean — dismiss overlay and allow the send
      showClean();
      setTimeout(() => {
        inputEl?.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true,
        }));
      }, 80);
      return;
    }

    showResults(analysis, inputEl);

    // Log to background
    chrome.runtime.sendMessage({
      type:            'SIYADA_INTERCEPTION',
      items:           (analysis.items || []).map(i => ({ type: i.type, regulation: i.regulation, severity: i.severity })),
      url:             location.href,
      timestamp:       Date.now(),
      severity:        ['critical','high','medium','low'].find(s => (analysis.items || []).some(i => i.severity === s)) || 'medium',
      source:          'text',
      outcome:         'blocked',
      hasHealthData:   analysis.hasHealthData || false,
      hasFinancialData:analysis.hasFinancialData || false,
    }).catch(() => {});
  }

  // ─── Find the active chat input at fire time ──────────────────────────────
  // Called fresh on every send event — never relies on a cached element.
  // Gemini (and other SPAs) can re-render the input at any time.

  const selectors = getSiteSelectors();

  function findActiveInput() {
    // 1. Focused element if it's a chat input
    const focused = document.activeElement;
    if (focused && (focused.isContentEditable || focused.tagName === 'TEXTAREA')) {
      const text = getInputText(focused);
      if (text.trim()) return focused;
    }
    // 2. Walk the selector list and return the first non-empty one
    for (const sel of selectors.inputs) {
      try {
        const els = document.querySelectorAll(sel);
        for (const el of els) {
          if (getInputText(el).trim()) return el;
        }
      } catch { /**/ }
    }
    // 3. Any non-empty contenteditable on the page
    for (const el of document.querySelectorAll('[contenteditable="true"]')) {
      if (getInputText(el).trim()) return el;
    }
    return null;
  }

  // ─── Document-level intercept ──────────────────────────────────────────────
  // Attaches once to document — survives SPA re-renders, never goes stale.

  let scanDebounce = null;

  // Enter key — capture phase so we fire before the site's own handler.
  // isTrusted guard: only intercept real user keystrokes, not our own re-fired events.
  document.addEventListener('keydown', (e) => {
    if (!e.isTrusted) return;    // skip programmatic re-fires (clean-send, inject-and-send)
    if (e.key !== 'Enter' || e.shiftKey) return;
    const input = findActiveInput();
    if (!input) return;          // not a chat input — don't interfere
    inputEl = input;
    handleBeforeSend(e);
  }, { capture: true });

  // Send-button click — capture phase on document.
  // isTrusted guard prevents loops if we ever programmatically click a send button.
  document.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    const btn = e.target.closest('button');
    if (!btn) return;

    // Check if it looks like a send button by aria-label or test id
    const label  = (btn.getAttribute('aria-label') || '').toLowerCase();
    const testId = btn.getAttribute('data-testid') || '';
    const isSend = label.includes('send') || testId.includes('send') ||
                   btn.classList.contains('send-button');
    if (!isSend) return;

    const input = findActiveInput();
    if (!input) return;
    inputEl = input;
    handleBeforeSend(e);
  }, { capture: true });

  // Live badge — keyword hint while typing
  document.addEventListener('input', (e) => {
    const el = e.target;
    if (!el || (!el.isContentEditable && el.tagName !== 'TEXTAREA')) return;
    clearTimeout(scanDebounce);
    scanDebounce = setTimeout(() => {
      const text = getInputText(el);
      if (!text.trim()) { setBadge('safe'); return; }
      setBadge(window.SiyadaScanner?.mightBeSensitive(text) ? 'scanning' : 'safe');
    }, 300);
  }, { capture: false });

  // ─── Attachment intercepts ─────────────────────────────────────────────
  // Each one cancels the real event and re-fires a synthetic copy after review.
  // The isTrusted guard keeps our own re-injection from being intercepted again.

  document.addEventListener('paste', (e) => {
    if (!e.isTrusted) return;
    const files = e.clipboardData?.files;
    if (!files?.length || !Array.from(files).some(isImageFile)) return;

    const target = e.target;
    const captured = Array.from(files);
    e.preventDefault();
    e.stopImmediatePropagation();

    guardImageAttachment(captured, (approved) => {
      if (!approved.length) return;
      target.dispatchEvent(new ClipboardEvent('paste', {
        clipboardData: toDataTransfer(approved), bubbles: true, cancelable: true,
      }));
    });
  }, { capture: true });

  document.addEventListener('drop', (e) => {
    if (!e.isTrusted) return;
    const files = e.dataTransfer?.files;
    if (!files?.length || !Array.from(files).some(isImageFile)) return;

    const target = e.target;
    const captured = Array.from(files);
    e.preventDefault();
    e.stopImmediatePropagation();

    guardImageAttachment(captured, (approved) => {
      if (!approved.length) return;
      target.dispatchEvent(new DragEvent('drop', {
        dataTransfer: toDataTransfer(approved), bubbles: true, cancelable: true,
      }));
    });
  }, { capture: true });

  // A file picker cannot be cancelled, so the selection is pulled off the input
  // and the input is emptied before the site's own change handler runs.
  document.addEventListener('change', (e) => {
    if (!e.isTrusted) return;
    const input = e.target;
    if (!(input instanceof HTMLInputElement) || input.type !== 'file') return;
    const files = input.files;
    if (!files?.length || !Array.from(files).some(isImageFile)) return;

    const captured = Array.from(files);
    e.stopImmediatePropagation();
    input.value = '';

    guardImageAttachment(captured, (approved) => {
      if (!approved.length) return;
      input.files = toDataTransfer(approved).files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
  }, { capture: true });

  // Ensure badge is present as soon as the page loads
  createOverlay();
})();
