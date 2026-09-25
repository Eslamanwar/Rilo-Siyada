/**
 * Siyada Service Worker
 *
 * Stores compliance interception events from content scripts.
 * Provides them to the popup dashboard.
 */

'use strict';

const MAX_LOG_ENTRIES = 200;

// ─── Compliance log in memory ───────────────────────────────────────────────
// For the hackathon we keep events in chrome.storage.local (persists across
// service worker restarts, lost on browser restart — fine for demo).

async function logInterception(event) {
  const { events = [] } = await chrome.storage.local.get('events');
  events.unshift({
    id:               Date.now().toString(36) + Math.random().toString(36).slice(2),
    timestamp:        event.timestamp || Date.now(),
    url:              event.url || '',
    items:            event.items || [],
    source:           event.source || 'text',
    outcome:          event.outcome || 'blocked',
    severity:         event.severity || 'medium',
    hasHealthData:    event.hasHealthData || false,
    hasFinancialData: event.hasFinancialData || false,
  });
  // Keep last MAX_LOG_ENTRIES
  if (events.length > MAX_LOG_ENTRIES) events.length = MAX_LOG_ENTRIES;
  await chrome.storage.local.set({ events });
}

async function getStats() {
  const { events = [] } = await chrome.storage.local.get('events');
  const today = new Date().toDateString();
  const todayEvents = events.filter(e =>
    new Date(e.timestamp).toDateString() === today
  );

  const piiTypes = {};
  for (const ev of todayEvents) {
    for (const item of (ev.items || [])) {
      piiTypes[item.type] = (piiTypes[item.type] || 0) + 1;
    }
  }

  const topRegulation = (() => {
    const counts = {};
    for (const ev of todayEvents) {
      for (const item of (ev.items || [])) {
        counts[item.regulation] = (counts[item.regulation] || 0) + 1;
      }
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || '—';
  })();

  return {
    totalToday:      todayEvents.length,
    critical:        todayEvents.filter(e => e.severity === 'critical').length,
    high:            todayEvents.filter(e => e.severity === 'high').length,
    healthData:      todayEvents.filter(e => e.hasHealthData).length,
    financialData:   todayEvents.filter(e => e.hasFinancialData).length,
    images:          todayEvents.filter(e => e.source === 'image').length,
    overrides:       todayEvents.filter(e => e.outcome === 'override').length,
    piiTypes,
    topRegulation,
    recentEvents:    todayEvents.slice(0, 20),
  };
}

// ─── Message handling ────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'SIYADA_INTERCEPTION') {
    logInterception(message).then(() => sendResponse({ ok: true }));
    return true; // keep channel open for async
  }

  if (message.type === 'SIYADA_GET_STATS') {
    getStats().then(stats => sendResponse({ ok: true, stats }));
    return true;
  }

  if (message.type === 'SIYADA_CLEAR_LOG') {
    chrome.storage.local.set({ events: [] }).then(() => sendResponse({ ok: true }));
    return true;
  }
});
