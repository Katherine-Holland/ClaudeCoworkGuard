/**
 * CoworkGuard — Popup Script
 * © 2026 Katherine Weston. MIT + Commons Clause.
 */

let showingSkills = false;

function openDashboard() {
  chrome.tabs.create({ url: 'http://localhost:7070' });
  window.close();
}

function openSkillsTab() {
  chrome.tabs.create({ url: 'http://localhost:7070#skills' });
  window.close();
}

function showSkillsTab() {
  showingSkills = true;
  document.getElementById('event-list').style.display = 'none';
  document.getElementById('skill-list').style.display = 'block';
  document.getElementById('tab-toggle').textContent = 'EVENTS';
}

function toggleTab() {
  showingSkills = !showingSkills;
  document.getElementById('event-list').style.display = showingSkills ? 'none' : 'block';
  document.getElementById('skill-list').style.display = showingSkills ? 'block' : 'none';
  document.getElementById('tab-toggle').textContent = showingSkills ? 'EVENTS' : 'SKILLS';
}

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function clearData() {
  await chrome.runtime.sendMessage({ type: 'CLEAR_LOG' });
  document.getElementById('s-blocked').textContent = '0';
  document.getElementById('s-flagged').textContent = '0';
  document.getElementById('s-clean').textContent   = '0';
  document.getElementById('event-list').innerHTML  = '<div class="empty">Cleared</div>';
}

async function loadSkillScans() {
  try {
    const res = await fetch('http://localhost:7070/api/skill-scans?limit=50');
    if (!res.ok) return;
    const data = await res.json();
    const scans = (data.scans || []).filter(s => s.action !== 'CLEAN').slice(0, 8);
    const allScans = data.scans || [];

    const notable = allScans.filter(s => s.action !== 'CLEAN');
    const blocked = notable.filter(s => s.action === 'BLOCKED').length;
    const alertEl = document.getElementById('skill-alert');
    const alertText = document.getElementById('skill-alert-text');
    if (notable.length > 0) {
      alertEl.style.display = 'block';
      alertText.textContent = blocked > 0
        ? `${blocked} skill${blocked > 1 ? 's' : ''} blocked — supply chain risk`
        : `${notable.length} skill${notable.length > 1 ? 's' : ''} flagged for review`;
    }

    const list = document.getElementById('skill-list');
    if (!scans.length) {
      list.innerHTML = '<div class="empty">No skill findings</div>';
      return;
    }
    list.innerHTML = scans.map(s => {
      const ts = new Date(s.timestamp).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
      const filename = esc(s.file_path.split('/').pop());
      const topFinding = s.findings?.[0]?.type || '';
      const detail = topFinding ? `${esc(s.skill_type)} — ${esc(topFinding)}` : esc(s.skill_type);
      return `<div class="event-item">
        <span class="badge ${esc(s.action)}">${esc(s.action)}</span>
        <span class="event-detail" title="${esc(s.file_path)}">${filename} ${detail}</span>
        <span style="color:var(--muted);font-size:10px;white-space:nowrap">${ts}</span>
      </div>`;
    }).join('');
  } catch (e) {
    // Server not available — silently skip
  }
}

async function load() {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, resp => {
    if (!resp) return;

    const pill   = document.getElementById('status-pill');
    const text   = document.getElementById('status-text');
    const banner = document.getElementById('partial-banner');
    const { claudeSessionActive, proxyActive, sessionStats: s } = resp;

    if (claudeSessionActive && proxyActive) {
      pill.className = 'pill full';
      text.textContent = 'FULL PROTECTION';
      banner.style.display = 'none';
    } else if (claudeSessionActive && !proxyActive) {
      pill.className = 'pill partial';
      text.textContent = 'PARTIAL PROTECTION';
      banner.style.display = 'block';
    } else if (!claudeSessionActive) {
      pill.className = 'pill inactive';
      text.textContent = 'NO AI SESSION';
      banner.style.display = 'none';
    } else {
      pill.className = 'pill unknown';
      text.textContent = 'CHECKING';
    }

    document.getElementById('s-blocked').textContent = s?.blocked ?? '0';
    document.getElementById('s-flagged').textContent = s?.flagged ?? '0';
    document.getElementById('s-clean').textContent   = s?.clean   ?? '0';
  });

  chrome.storage.local.get(['auditLog'], result => {
    const log  = result.auditLog || [];
    const list = document.getElementById('event-list');
    if (!log.length) { list.innerHTML = '<div class="empty">No events yet</div>'; return; }
    list.innerHTML = log.slice(0, 8).map(e => {
      const action = e.action || 'UNKNOWN';
      const ts     = new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
      const detail = e.type === 'DOMAIN_WARNING'
        ? `Domain: ${esc(e.domain || '–')}`
        : (e.findings?.length ? esc(e.findings.map(f => f.type).join(', ')) : 'Clean');
      return `<div class="event-item">
        <span class="badge ${esc(action)}">${esc(action)}</span>
        <span class="event-detail">${detail}</span>
        <span style="color:var(--muted);font-size:10px;white-space:nowrap">${ts}</span>
      </div>`;
    }).join('');
  });

  await loadSkillScans();
}

document.addEventListener('DOMContentLoaded', () => {
  load();
  const get = id => document.getElementById(id);
  get('btn-dashboard')?.addEventListener('click', openDashboard);
  get('btn-skills')?.addEventListener('click', openSkillsTab);
  get('btn-clear')?.addEventListener('click', clearData);
  get('tab-toggle')?.addEventListener('click', toggleTab);
  get('btn-show-skills')?.addEventListener('click', showSkillsTab);
});
