/**
 * CoworkGuard - Content Script
 * Injected into every page. Listens for domain warnings from background worker
 * and injects a visible warning banner.
 */

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "COWORKGUARD_DOMAIN_WARNING") {
    injectWarningBanner(msg.domain, msg.url);
  }
});

function injectWarningBanner(domain, url) {
  // Don't inject twice
  if (document.getElementById("coworkguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "coworkguard-banner";
  banner.innerHTML = `
    <div style="
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #1a0a0a, #2d0f0f);
      border-bottom: 2px solid #ff4444;
      color: #fff;
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 13px;
      padding: 10px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 24px rgba(255,68,68,0.4);
      animation: slideDown 0.3s ease;
    ">
      <div style="display:flex;align-items:center;gap:12px;">
        <span style="font-size:18px;">🛡️</span>
        <div>
          <strong style="color:#ff6666;">CoworkGuard Warning</strong>
          <span style="color:#ffaaaa;margin-left:8px;">
            Claude Cowork is active — page content on <strong>${domain}</strong> may be sent to Claude
          </span>
        </div>
      </div>
      <div style="display:flex;gap:8px;">
        <button onclick="this.closest('#coworkguard-banner').remove()" style="
          background:#ff4444;border:none;color:#fff;
          padding:4px 12px;border-radius:4px;cursor:pointer;
          font-family:inherit;font-size:12px;
        ">Dismiss</button>
        <button onclick="window.open('http://localhost:7070','_blank')" style="
          background:transparent;border:1px solid #ff4444;color:#ff6666;
          padding:4px 12px;border-radius:4px;cursor:pointer;
          font-family:inherit;font-size:12px;
        ">View Dashboard</button>
      </div>
    </div>
    <style>
      @keyframes slideDown {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    </style>
  `;

  document.documentElement.prepend(banner);

  // Auto-dismiss after 15 seconds
  setTimeout(() => banner.remove(), 15000);
}

//Copyright (c) 2026 [Katherine Weston]. All rights reserved.
//Licensed under MIT with Commons Clause — see LICENSE for details.
//Commercial use prohibited without a separate commercial license.
