/**
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
let coworkActive = false;
let sessionStats = { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 };

// ─────────────────────────────────────────────
// Cowork detection — looks for the Cowork extension ID in installed extensions
// and for Claude desktop app websocket connections
// ─────────────────────────────────────────────
async function detectCowork() {
  try {
    const tabs = await chrome.tabs.query({});
    const coworkTab = tabs.find(
      (t) =>
        t.url?.includes("claude.ai") ||
        t.url?.includes("cowork") ||
        t.title?.toLowerCase().includes("claude")
    );
    coworkActive = !!coworkTab;
    chrome.storage.local.set({ coworkActive, sessionStats });
    updateIcon();
  } catch (e) {
    console.error("[CoworkGuard] Detection error:", e);
  }
}

// ─────────────────────────────────────────────
// Icon state
// ─────────────────────────────────────────────
function updateIcon() {
  const color = coworkActive ? "#ff4444" : "#22cc88";
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text: coworkActive ? "ON" : "" });
}

// ─────────────────────────────────────────────
// Domain guard — warns when navigating to sensitive pages while Cowork is active
// ─────────────────────────────────────────────
function isSensitiveDomain(url) {
  return SENSITIVE_DOMAINS.find((d) => url.includes(d));
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  await detectCowork();

  if (!coworkActive) return;

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
      message: `Claude Cowork is active and you've navigated to ${matched}. Page content may be sent to Claude.`,
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
// Monitor outbound requests to Anthropic API
// ─────────────────────────────────────────────
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!details.url.includes("api.anthropic.com")) return;

    const guardHeader = details.requestHeaders?.find(
      (h) => h.name === "X-CoworkGuard-Action"
    );

    // If proxy is running, it will have tagged the request
    if (guardHeader) {
      const action = guardHeader.value;
      if (action === "BLOCKED") sessionStats.blocked++;
      else if (action === "FLAGGED") sessionStats.flagged++;
      else sessionStats.clean++;
      chrome.storage.local.set({ sessionStats });
    }

    logEvent({
      type: "API_REQUEST",
      url: details.url,
      method: details.method,
      proxyAction: guardHeader?.value || "NO_PROXY",
      timestamp: new Date().toISOString(),
    });
  },
  { urls: ["https://api.anthropic.com/*"] },
  ["requestHeaders"]
);

// ─────────────────────────────────────────────
// Audit log (stored locally in chrome.storage)
// ─────────────────────────────────────────────
async function logEvent(event) {
  const { auditLog = [] } = await chrome.storage.local.get("auditLog");
  auditLog.unshift(event); // newest first
  // Keep last 500 events
  if (auditLog.length > 500) auditLog.splice(500);
  chrome.storage.local.set({ auditLog });
}

// ─────────────────────────────────────────────
// Message handler — popup and content script comms
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    sendResponse({ coworkActive, sessionStats });
  }
  if (msg.type === "CLEAR_LOG") {
    chrome.storage.local.set({ auditLog: [], sessionStats: { blocked: 0, flagged: 0, clean: 0, domainWarnings: 0 } });
    sendResponse({ ok: true });
  }
  return true;
});

// Init
detectCowork();
setInterval(detectCowork, 10000);

//Copyright (c) 2026 [Katherine Weston]. All rights reserved.
//Licensed under MIT with Commons Clause — see LICENSE for details.
//Commercial use prohibited without a separate commercial license.
