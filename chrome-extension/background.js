/**
 * Copyright (c) 2026 Katherine Weston. All rights reserved.
 * Licensed under MIT with Commons Clause — see LICENSE for details.
 * Commercial use prohibited without a separate commercial license.
 *
 * CoworkGuard - Background Service Worker
 * Monitors tab navigation and API requests, enforces domain blocklist,
 * communicates with local proxy audit log.
 */

// ─────────────────────────────────────────────
// Sensitive domain list — loaded from shared domains.json
// Single source of truth with scanner.py
// Falls back to hardcoded list if server not running
// ─────────────────────────────────────────────
let SENSITIVE_DOMAINS = [
  "console.aws.amazon.com", "app.datadoghq.com", "grafana.",
  "jenkins.", "gitlab.", "github.com/settings", "github.com/orgs", "github.com/enterprises", "bitbucket.",
  "jira.", "confluence.", "notion.so", "linear.app",
  "stripe.com/dashboard", "twilio.com/console",
  "mail.google.com", "outlook.live.com", "outlook.office",
  "payroll.", "hr.", "workday.com", "bamboohr.",
  "salesforce.com", "hubspot.com",
];

async function loadDomains() {
  try {
    const resp = await fetch("http://localhost:7070/api/domains", {
      signal: AbortSignal.timeout(2000)
    });
    const data = await resp.json();
    if (Array.isArray(data?.sensitive_domains) && data.sensitive_domains.length) {
      SENSITIVE_DOMAINS = data.sensitive_domains;
    }
  } catch {
    // Server not running — use fallback list above
  }
}

// ─────────────────────────────────────────────
// State
// ─────────────────────────────────────────────
let claudeSessionActive = false;
let proxyActive = false;
let sessionStats = {
  blocked: 0,
  flagged: 0,
  clean: 0,
  domainWarnings: 0,
  windowAiDetections: 0,
  suspiciousWraps: 0,
};

// ─────────────────────────────────────────────
// Session detection
// ─────────────────────────────────────────────

// Maps a URL fragment to a human-readable app name for dashboard logging.
// Order matters — more specific entries first.
const AI_SESSION_APPS = [
  { match: "claude.ai",              name: "Claude",         id: "claude_web" },
  { match: "chat.openai.com",        name: "ChatGPT",        id: "chatgpt" },
  { match: "chatgpt.com",            name: "ChatGPT",        id: "chatgpt" },
  { match: "gemini.google.com",      name: "Gemini",         id: "gemini" },
  { match: "perplexity.ai",          name: "Perplexity",     id: "perplexity" },
  { match: "github.com/copilot",     name: "GitHub Copilot", id: "copilot_web" },
  { match: "copilot.microsoft.com",  name: "Microsoft Copilot", id: "ms_copilot" },
  { match: "mistral.ai",             name: "Mistral Le Chat", id: "mistral_web" },
  { match: "groq.com",               name: "Groq",           id: "groq_web" },
  { match: "poe.com",                name: "Poe",            id: "poe" },
  { match: "character.ai",           name: "Character.AI",   id: "character_ai" },
  { match: "coze.com",               name: "Coze",           id: "coze" },
  { match: "huggingface.co/chat",    name: "HuggingChat",    id: "huggingchat" },
  { match: "you.com",                name: "You.com",        id: "you_com" },
  { match: "phind.com",              name: "Phind",          id: "phind" },
  { match: "cursor.sh",              name: "Cursor",         id: "cursor_web" },
  { match: "cowork",                 name: "CoworkGuard",    id: "coworkguard" },
];

const AI_SESSION_URLS = AI_SESSION_APPS.map(a => a.match);

// Track which app IDs have already been logged this session to avoid
// flooding the dashboard with repeated SESSION_STARTED events.
const _loggedSessions = new Set();

function matchSessionApp(url) {
  if (!url) return null;
  return AI_SESSION_APPS.find(a => url.includes(a.match)) || null;
}

async function detectClaudeSession() {
  try {
    const tabs = await chrome.tabs.query({});
    const activeApps = new Map(); // id -> app entry, deduped
    for (const t of tabs) {
      const app = matchSessionApp(t.url);
      if (app && !activeApps.has(app.id)) {
        activeApps.set(app.id, app);
      }
    }
    claudeSessionActive = activeApps.size > 0;
    chrome.storage.local.set({ claudeSessionActive, sessionStats });
    updateIcon();
    return activeApps;
  } catch (e) {
    console.error("[CoworkGuard] Detection error:", e);
    return new Map();
  }
}

// Log a SESSION_STARTED event the first time each AI web app tab is opened.
// Fires from onUpdated so it captures the moment the tab loads, not just polls.
async function logSessionStarted(url) {
  const app = matchSessionApp(url);
  if (!app || _loggedSessions.has(app.id)) return;
  _loggedSessions.add(app.id);
  const event = {
    type:      "AI_SESSION_STARTED",
    severity:  "LOW",
    action:    "FLAGGED",
    source:    "chrome_extension",
    app_name:  app.name,
    app_id:    app.id,
    url,
    timestamp: new Date().toISOString(),
    message:   `${app.name} session opened in browser`,
  };
  logEvent(event);
  fetch("http://localhost:7070/api/log-event", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...event, finding_count: 1, findings: [{ type: "AI_SESSION_STARTED", severity: "LOW", preview: `${app.name} opened`, blocked: false }] }),
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});
}

// Clear logged session IDs when all tabs for that app are closed so the
// next time the user opens it they get a fresh log entry.
// Also fires AI_SESSION_ENDED for apps that are no longer open.
chrome.tabs.onRemoved.addListener(async () => {
  const tabs = await chrome.tabs.query({});
  const stillOpen = new Set(tabs.map(t => matchSessionApp(t.url)?.id).filter(Boolean));
  for (const id of [..._loggedSessions]) {
    if (!stillOpen.has(id)) {
      _loggedSessions.delete(id);
      // Find the app entry to get the name
      const app = AI_SESSION_APPS.find(a => a.id === id);
      if (!app) continue;
      const event = {
        type:      "AI_SESSION_ENDED",
        action:    "CLEAN",
        severity:  "LOW",
        timestamp: new Date().toISOString(),
        url:       app.match,
        ai_provider: app.name,
        app_name:  app.name,
        app_id:    app.id,
        message:   `${app.name} session closed`,
      };
      fetch("http://localhost:7070/api/log-event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...event, finding_count: 0, findings: [] }),
      }).catch(() => {});
    }
  }
});

// ─────────────────────────────────────────────
// Icon state
// ─────────────────────────────────────────────
function updateIcon() {
  if (claudeSessionActive && proxyActive) {
    chrome.action.setBadgeBackgroundColor({ color: "#e05a20" });
    chrome.action.setBadgeText({ text: "ON" });
  } else if (claudeSessionActive && !proxyActive) {
    chrome.action.setBadgeBackgroundColor({ color: "#f0a030" });
    chrome.action.setBadgeText({ text: "!" });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: "#3dd68c" });
    chrome.action.setBadgeText({ text: "" });
  }
}

// ─────────────────────────────────────────────
// Domain guard
// ─────────────────────────────────────────────
function isSensitiveDomain(url) {
  try {
    const { hostname } = new URL(url);
    const parts = hostname.split('.');
    return SENSITIVE_DOMAINS.find(d => {
      if (d.endsWith('.')) {
        const label = d.slice(0, -1);
        return parts[0] === label || parts.includes(label);
      }
      if (d.includes('/')) return url.includes(d);
      return hostname === d || hostname.endsWith('.' + d);
    });
  } catch { return null; }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  // Log when a new AI web app tab finishes loading
  await logSessionStarted(tab.url);
  await detectClaudeSession();
  if (!claudeSessionActive) return;
  const matched = isSensitiveDomain(tab.url);
  if (matched) {
    sessionStats.domainWarnings++;
    chrome.storage.local.set({ sessionStats });
    chrome.tabs.sendMessage(tabId, {
      type: "COWORKGUARD_DOMAIN_WARNING",
      domain: matched,
      url: tab.url,
    });
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ CoworkGuard Warning",
      message: `An AI session is active and you have navigated to ${matched}. Page content may be sent to connected AI providers.`,
      priority: 2,
    });
    logEvent({
      type: "DOMAIN_WARNING",
      severity: "HIGH",
      url: tab.url,
      domain: matched,
      timestamp: new Date().toISOString(),
    });
  }
});

// ─────────────────────────────────────────────
// Monitor outbound requests to AI APIs
// ─────────────────────────────────────────────
const AI_API_URLS = [
  "https://api.anthropic.com/*",
  "https://api.openai.com/*",
  "https://generativelanguage.googleapis.com/*",
  "https://api.perplexity.ai/*",
  "https://api.cursor.sh/*",
  "https://copilot-proxy.githubusercontent.com/*",
  "https://api.mistral.ai/*",
  "https://api.cohere.com/*",
  "https://api.groq.com/*",
  "https://api.x.ai/*",
];

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const guardHeader = details.requestHeaders?.find(
      (h) => h.name === "X-CoworkGuard-Action"
    );
    if (guardHeader) {
      proxyActive = true;
      const action = guardHeader.value;
      if (action === "BLOCKED") sessionStats.blocked++;
      else if (action === "FLAGGED") sessionStats.flagged++;
      else sessionStats.clean++;
      chrome.storage.local.set({ proxyActive, sessionStats });
      updateIcon();
    }
    logEvent({
      type: "API_REQUEST",
      url: details.url,
      method: details.method,
      action: guardHeader?.value || "NO_PROXY",
      proxyRunning: !!guardHeader,
      timestamp: new Date().toISOString(),
    });
  },
  { urls: AI_API_URLS },
  ["requestHeaders"]
);

// ─────────────────────────────────────────────
// window.ai / Prompt API detection
// Handles messages from window-ai-detector.js content script
// ─────────────────────────────────────────────

function handleWindowAI(msg) {
  sessionStats.windowAiDetections = (sessionStats.windowAiDetections || 0) + 1;
  chrome.storage.local.set({ sessionStats });

  logEvent({
    type: "WINDOW_AI_DETECTED",
    severity: "HIGH",
    url: msg.url,
    path: msg.path,
    timestamp: msg.timestamp,
    action: "FLAGGED",
  });

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon48.png",
    title: "⚠️ CoworkGuard: Local AI Detected",
    message: `This page is using Chrome's built-in AI (Gemini Nano) via ${msg.path}. The interaction runs locally with no outbound API call.`,
    priority: 2,
  });

  fetch("http://localhost:7070/api/log-event", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      type: "WINDOW_AI_DETECTED",
      severity: "HIGH",
      url: msg.url,
      path: msg.path,          // consistent with local log shape
      timestamp: msg.timestamp,
      action: "FLAGGED",
    }),
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});
}

// ─────────────────────────────────────────────
// Suspicious fetch/XHR wrap detection
// Catches extensions harvesting AI conversations (Urban VPN pattern)
// ─────────────────────────────────────────────

function handleSuspiciousWrap(msg) {
  sessionStats.suspiciousWraps = (sessionStats.suspiciousWraps || 0) + 1;
  chrome.storage.local.set({ sessionStats });

  logEvent({
    type: "SUSPICIOUS_API_WRAP",
    severity: "CRITICAL",
    url: msg.url,
    fetchWrapped: msg.fetchWrapped,
    xhrWrapped: msg.xhrWrapped,
    timestamp: msg.timestamp,
    action: "CRITICAL_ALERT",  // detection only — not an enforcement block
    message: "fetch() or XMLHttpRequest has been overridden. Another extension may be harvesting your AI conversations.",
  });

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon48.png",
    title: "🚨 CoworkGuard: Suspicious Extension Detected",
    message: "fetch() or XMLHttpRequest has been overridden on this AI page. Another extension may be harvesting your AI conversations. Check your installed extensions.",
    priority: 2,
  });

  fetch("http://localhost:7070/api/log-event", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      type: "SUSPICIOUS_API_WRAP",
      severity: "CRITICAL",
      url: msg.url,
      fetchWrapped: msg.fetchWrapped,
      xhrWrapped: msg.xhrWrapped,
      timestamp: msg.timestamp,
      action: "CRITICAL_ALERT",
    }),
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});
}

// ─────────────────────────────────────────────
// Audit log
// ─────────────────────────────────────────────
let _logQueue = Promise.resolve();
function logEvent(event) {
  _logQueue = _logQueue.then(async () => {
    const { auditLog = [] } = await chrome.storage.local.get("auditLog");
    auditLog.unshift(event);
    if (auditLog.length > 500) auditLog.splice(500);
    await chrome.storage.local.set({ auditLog });
  });
}

// ─────────────────────────────────────────────
// Message handler
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    sendResponse({ claudeSessionActive, proxyActive, sessionStats });
  }
  if (msg.type === "CLEAR_LOG") {
    sessionStats = { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0, windowAiDetections: 0, suspiciousWraps: 0 };
    chrome.storage.local.set({ auditLog: [], sessionStats });
    sendResponse({ ok: true });
  }
  if (msg.type === "WINDOW_AI_DETECTED") {
    handleWindowAI(msg);
  }
  if (msg.type === "SUSPICIOUS_API_WRAP") {
    handleSuspiciousWrap(msg);
  }
  return true;
});

// ─────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────
loadDomains();
// On startup, log sessions for any AI web app tabs already open
(async () => {
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.url) await logSessionStarted(tab.url);
    }
  } catch(e) {}
})();
detectClaudeSession();
setInterval(detectClaudeSession, 10000);

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.notifications.create('first-run', {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: '🛡️ CoworkGuard installed',
      message: 'Domain protection is active. Download the macOS app for full payload scanning and blocking at coworkguard.com',
      buttons: [{ title: 'Get macOS App' }],
      priority: 2,
    });
  }
});

chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (notifId === 'first-run' && btnIdx === 0) {
    chrome.tabs.create({ url: 'https://coworkguard.com' });
  }
});

async function pollProxyStatus() {
  try {
    const resp = await fetch("http://localhost:7070/api/status", {
      signal: AbortSignal.timeout(2000)
    });
    const data = await resp.json();
    const wasActive = proxyActive;
    proxyActive = data?.proxy?.running === true;
    if (wasActive !== proxyActive) {
      chrome.storage.local.set({ proxyActive });
      updateIcon();
    }
  } catch {
    if (proxyActive) {
      proxyActive = false;
      chrome.storage.local.set({ proxyActive });
      updateIcon();
    }
  }
}

pollProxyStatus();
setInterval(pollProxyStatus, 15000);
