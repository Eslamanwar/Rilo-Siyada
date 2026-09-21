'use strict';

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return url || '—';
  }
}

function renderEvents(events) {
  const list = document.getElementById('eventList');

  if (!events || events.length === 0) {
    list.innerHTML = `
      <div class="empty">
        <span class="empty-icon">✅</span>
        No interceptions yet today.<br>Siyada is watching.
      </div>`;
    return;
  }

  list.innerHTML = events.map(ev => {
    const tags = (ev.items || [])
      .map(i => `<span class="tag">${i.type.replace(/_/g, ' ')}</span>`)
      .slice(0, 4)
      .join('');

    return `
      <div class="event">
        <div class="event-top">
          <span class="sev-badge sev-${ev.severity}">${ev.severity}</span>
          <span class="event-time">${formatTime(ev.timestamp)}</span>
          <span class="event-url" title="${ev.url}">${formatUrl(ev.url)}</span>
        </div>
        <div class="event-tags">${tags}</div>
      </div>`;
  }).join('');
}

async function loadStats() {
  const response = await chrome.runtime.sendMessage({ type: 'SIYADA_GET_STATS' });
  if (!response?.ok) return;

  const s = response.stats;
  document.getElementById('statTotal').textContent    = s.totalToday;
  document.getElementById('statCritical').textContent = s.critical;
  document.getElementById('statHealth').textContent   = s.healthData;
  document.getElementById('statFinancial').textContent = s.financialData;

  if (s.topRegulation && s.topRegulation !== '—') {
    document.getElementById('topReg').textContent = s.topRegulation;
    document.getElementById('regBanner').style.display = 'block';
  }

  renderEvents(s.recentEvents);
}

document.getElementById('clearBtn').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'SIYADA_CLEAR_LOG' });
  loadStats();
});

loadStats();
