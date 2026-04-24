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
let claudeSessionActive = false;  // A Claude tab is open in the browser
let proxyActive = false;          // CoworkGuard proxy is running and scanning
let sessionStats = { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 };

// ─────────────────────────────────────────────
// Session detection
// Detects if any AI-related tab is open in the browser.
// Note: does NOT detect the Claude desktop app — that requires
// the local server.py (psutil process detection) to be running.
// ─────────────────────────────────────────────
// AI provider URLs — defined once at module scope
const AI_SESSION_URLS = [
  "claude.ai", "cowork",
  "chat.openai.com", "chatgpt.com",
  "perplexity.ai",
  "gemini.google.com",
  "cursor.sh",
  "github.com/copilot",
  "mistral.ai",
  "groq.com",
];

async function detectClaudeSession() {
  try {
    const tabs = await chrome.tabs.query({});
    const claudeTab = tabs.find(t =>
      AI_SESSION_URLS.some(u => t.url?.includes(u)) ||
      t.title?.toLowerCase().includes("claude") ||
      t.title?.toLowerCase().includes("chatgpt") ||
      t.title?.toLowerCase().includes("copilot")
    );
    claudeSessionActive = !!claudeTab;
    chrome.storage.local.set({ claudeSessionActive, sessionStats });
    updateIcon();
  } catch (e) {
    console.error("[CoworkGuard] Detection error:", e);
  }
}

// ─────────────────────────────────────────────
// Icon state — reflects protection level
// ─────────────────────────────────────────────
function updateIcon() {
  if (claudeSessionActive && proxyActive) {
    // Full protection — proxy scanning + domain guard
    chrome.action.setBadgeBackgroundColor({ color: "#e05a20" });
    chrome.action.setBadgeText({ text: "ON" });
  } else if (claudeSessionActive && !proxyActive) {
    // Partial protection — domain guard only, no payload scanning
    chrome.action.setBadgeBackgroundColor({ color: "#f0a030" });
    chrome.action.setBadgeText({ text: "!" });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: "#3dd68c" });
    chrome.action.setBadgeText({ text: "" });
  }
}

// ─────────────────────────────────────────────
// Domain guard — warns when navigating to sensitive pages
// ─────────────────────────────────────────────
function isSensitiveDomain(url) {
  try {
    const { hostname } = new URL(url);
    const parts = hostname.split('.');
    return SENSITIVE_DOMAINS.find(d => {
      if (d.endsWith('.')) {
        // Subdomain-prefix entries e.g. "hr." — match any hostname whose
        // leftmost label equals the prefix, avoiding partial-word matches.
        // "hr." matches hr.acme.com and sub.hr.acme.com but NOT xhr.acme.com.
        const label = d.slice(0, -1);
        return parts[0] === label || parts.includes(label);
      }
      // Path-qualified entries e.g. "stripe.com/dashboard" — use url.includes
      if (d.includes('/')) return url.includes(d);
      // Plain hostname entries — exact match or subdomain
      return hostname === d || hostname.endsWith('.' + d);
    });
  } catch { return null; }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  await detectClaudeSession();

  if (!claudeSessionActive) return;

  const matched = isSensitiveDomain(tab.url);
  if (matched) {
    sessionStats.domainWarnings++;
    chrome.storage.local.set({ sessionStats });

    // Inject warning banner into the page
    chrome.tabs.sendMessage(tabId, {
      type: "COWORKGUARD_DOMAIN_WARNING",
      domain: matched,
      url: tab.url,
    });

    // Show notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ CoworkGuard Warning",
      message: `An AI session is active and you've navigated to ${matched}. Page content may be sent to connected AI providers.`,
      priority: 2,
    });

    // Log to storage
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
// Also uses header presence to detect if proxy is running
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

    // If proxy tagged this request, it's running — update state
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
// Audit log (stored locally in chrome.storage)
// A queue serializes writes so concurrent calls don't race and drop entries.
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
// Message handler — popup and content script comms
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    sendResponse({ claudeSessionActive, proxyActive, sessionStats });
  }
  if (msg.type === "CLEAR_LOG") {
    sessionStats = { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 };
    chrome.storage.local.set({ auditLog: [], sessionStats });
    sendResponse({ ok: true });
  }
  return true;
});

// Init
loadDomains();
detectClaudeSession();
setInterval(detectClaudeSession, 10000);

// First-run notification — show once on install
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.notifications.create('first-run', {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: '🛡️ CoworkGuard installed',
      message: 'Domain protection is active. Download the macOS app for full payload scanning and blocking.',
      buttons: [{ title: 'Finish Installation' }],
      priority: 2,
    });
  }
});

// Handle notification button click
chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (notifId === 'first-run' && btnIdx === 0) {
    chrome.tabs.create({
      url: 'https://github.com/Katherine-Holland/ClaudeCoworkGuard/releases'
    });
  }
});

// Poll local server for proxy status every 15 seconds
// This is more reliable than resetting proxyActive on a timer
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
    // Server not running — proxy is off
    if (proxyActive) {
      proxyActive = false;
      chrome.storage.local.set({ proxyActive });
      updateIcon();
    }
  }
}

pollProxyStatus();
setInterval(pollProxyStatus, 15000);
