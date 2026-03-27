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
// Sensitive domain list (mirrors Python scanner)
// ─────────────────────────────────────────────
const SENSITIVE_DOMAINS = [
  "console.aws.amazon.com",
  "app.datadoghq.com",
  "grafana.",
  "jenkins.",
  "gitlab.",
  "github.com",
  "bitbucket.",
  "jira.",
  "confluence.",
  "notion.so",
  "linear.app",
  "stripe.com/dashboard",
  "twilio.com/console",
  "mail.google.com",
  "outlook.live.com",
  "outlook.office",
  "payroll.",
  "hr.",
  "workday.com",
  "bamboohr.",
  "salesforce.com",
  "hubspot.com",
];

// ─────────────────────────────────────────────
// State
// ─────────────────────────────────────────────
let claudeSessionActive = false;  // A Claude tab is open in the browser
let proxyActive = false;          // CoworkGuard proxy is running and scanning
let sessionStats = { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 };

// ─────────────────────────────────────────────
// Claude session detection
// Detects if any Claude-related tab is open in the browser.
// Note: this does NOT detect the Claude desktop app — that requires
// the local server.py (psutil process detection) to be running.
// ─────────────────────────────────────────────
async function detectClaudeSession() {
  try {
    const tabs = await chrome.tabs.query({});
    const claudeTab = tabs.find(
      (t) =>
        t.url?.includes("claude.ai") ||
        t.url?.includes("cowork") ||
        t.title?.toLowerCase().includes("claude")
    );
    claudeSessionActive = !!claudeTab;
    chrome.storage.local.set({ claudeSessionActive, proxyActive, sessionStats });
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
  return SENSITIVE_DOMAINS.find((d) => url.includes(d));
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
      message: `A Claude session is active and you've navigated to ${matched}. Page content may be sent to Claude.`,
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
      proxyAction: guardHeader?.value || "NO_PROXY",
      proxyRunning: !!guardHeader,
      timestamp: new Date().toISOString(),
    });
  },
  { urls: AI_API_URLS },
  ["requestHeaders"]
);

// ─────────────────────────────────────────────
// Audit log (stored locally in chrome.storage)
// ─────────────────────────────────────────────
async function logEvent(event) {
  const { auditLog = [] } = await chrome.storage.local.get("auditLog");
  auditLog.unshift(event);
  if (auditLog.length > 500) auditLog.splice(500);
  chrome.storage.local.set({ auditLog });
}

// ─────────────────────────────────────────────
// Message handler — popup and content script comms
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    sendResponse({ claudeSessionActive, proxyActive, sessionStats });
  }
  if (msg.type === "CLEAR_LOG") {
    chrome.storage.local.set({
      auditLog: [],
      sessionStats: { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 }
    });
    sendResponse({ ok: true });
  }
  return true;
});

// Init
detectClaudeSession();
setInterval(detectClaudeSession, 10000);

// Reset proxy active state every 30s — will be re-set if proxy is still running
setInterval(() => {
  proxyActive = false;
  updateIcon();
}, 30000);
