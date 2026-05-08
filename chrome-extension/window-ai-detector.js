/**
 * CoworkGuard - window.ai / Prompt API Detector
 * Injected into every page as a content script (MAIN world).
 * Detects calls to Chrome's built-in Prompt API (window.ai / LanguageModel)
 * and reports them back to background.js for logging and alerting.
 *
 * Also detects suspicious fetch() / XMLHttpRequest wrapping using
 * iframe-isolated native reference comparison — harder to spoof than
 * toString() checks which can be overridden by attackers.
 */

(function() {
  'use strict';

  // ── Detect window.ai / Prompt API usage ──
  function patchLanguageModel(obj, path) {
    if (!obj || typeof obj.create !== 'function') return;
    const original = obj.create.bind(obj);
    obj.create = function(...args) {
      chrome.runtime.sendMessage({
        type: 'WINDOW_AI_DETECTED',
        path: path,
        url: window.location.href,
        timestamp: new Date().toISOString(),
        // Do NOT send prompt content — could contain PII or secrets
      });
      return original.apply(this, args);
    };
  }

  function tryPatch() {
    if (typeof LanguageModel !== 'undefined') {
      patchLanguageModel(LanguageModel, 'LanguageModel');
    }
    if (window.ai?.languageModel) {
      patchLanguageModel(window.ai.languageModel, 'window.ai.languageModel');
    }
  }

  tryPatch();
  if (document.readyState !== 'complete') {
    window.addEventListener('load', tryPatch);
  }

  // ── Detect suspicious fetch/XHR wrapping ──
  // Uses iframe-isolated native reference comparison.
  // Harder to spoof than toString() checks — attacker would need to
  // intercept the iframe's window context too.
  // Only runs on AI provider pages to minimise false positives.

  const AI_HOSTS = [
    'claude.ai', 'chat.openai.com', 'chatgpt.com',
    'gemini.google.com', 'perplexity.ai', 'cursor.sh',
    'mistral.ai', 'groq.com',
  ];

  if (AI_HOSTS.some(h => window.location.hostname.includes(h))) {
    try {
      const iframe = document.createElement('iframe');
      // Use display:none to avoid layout impact
      iframe.style.display = 'none';
      document.documentElement.appendChild(iframe);
      const iWin = iframe.contentWindow;
      const nativeFetch = iWin.fetch;
      const nativeOpen  = iWin.XMLHttpRequest.prototype.open;
      iframe.remove();

      const fetchWrapped = (typeof fetch !== 'undefined') && (fetch !== nativeFetch);
      const xhrWrapped   = XMLHttpRequest.prototype.open !== nativeOpen;

      if (fetchWrapped || xhrWrapped) {
        chrome.runtime.sendMessage({
          type: 'SUSPICIOUS_API_WRAP',
          fetchWrapped,
          xhrWrapped,
          url: window.location.href,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (e) {
      // Sandboxed page or iframe blocked — skip check silently
    }
  }

})();
