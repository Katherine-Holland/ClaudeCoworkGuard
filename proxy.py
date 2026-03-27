"""
Copyright (c) 2026 Katherine Holland. All rights reserved.
Licensed under MIT with Commons Clause — see LICENSE for details.
Commercial use prohibited without a separate commercial license.

CoworkGuard - mitmproxy Interceptor
Monitors outbound requests to all major AI agent APIs and scans
payloads for PII, secrets, and sensitive data before they leave
your machine.

Originally built for Claude Cowork — extended to cover the full
AI agent ecosystem.

Monitored endpoints:
  • api.anthropic.com        (Claude Cowork, Claude Code, Claude in Chrome)
  • api.openai.com           (ChatGPT, GPT-4, Assistants API)
  • generativelanguage.googleapis.com  (Google Gemini)
  • api.perplexity.ai        (Perplexity)
  • api.cursor.sh            (Cursor IDE)
  • copilot-proxy.githubusercontent.com (GitHub Copilot)
  • api.mistral.ai           (Mistral)
  • api.cohere.com           (Cohere)
  • api.groq.com             (Groq)
  • api.x.ai                (xAI / Grok)

Usage:
  pip install mitmproxy
  mitmproxy -s proxy.py --listen-port 8080

Then set your system proxy to 127.0.0.1:8080
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http

from scanner import CoworkScanner, ScanResult

# ─────────────────────────────────────────────
# AI API endpoints to monitor
# ─────────────────────────────────────────────

AI_HOSTS = [
    # Anthropic — primary case study, Claude Cowork / Code / Chrome
    "api.anthropic.com",
    # OpenAI — ChatGPT, GPT-4, Assistants, DALL-E
    "api.openai.com",
    # Google Gemini
    "generativelanguage.googleapis.com",
    # Perplexity
    "api.perplexity.ai",
    # Cursor IDE
    "api.cursor.sh",
    # GitHub Copilot
    "copilot-proxy.githubusercontent.com",
    # Mistral
    "api.mistral.ai",
    # Cohere
    "api.cohere.com",
    # Groq
    "api.groq.com",
    # xAI / Grok
    "api.x.ai",
]

# Label map for cleaner log output
HOST_LABELS = {
    "api.anthropic.com":                    "Claude (Anthropic)",
    "api.openai.com":                       "OpenAI",
    "generativelanguage.googleapis.com":    "Gemini (Google)",
    "api.perplexity.ai":                    "Perplexity",
    "api.cursor.sh":                        "Cursor",
    "copilot-proxy.githubusercontent.com":  "GitHub Copilot",
    "api.mistral.ai":                       "Mistral",
    "api.cohere.com":                       "Cohere",
    "api.groq.com":                         "Groq",
    "api.x.ai":                             "xAI / Grok",
}

LOG_DIR = Path.home() / ".coworkguard" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"

# Tune these to your risk tolerance
scanner = CoworkScanner(
    block_on_critical=True,   # Block SSNs, raw private keys, CC numbers
    block_on_high=False,      # Flag but don't block JWTs, bearer tokens etc
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CoworkGuard] %(message)s")
log = logging.getLogger("coworkguard")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def matched_host(pretty_host: str):
    """Return the matched AI host string, or None if not an AI endpoint."""
    for host in AI_HOSTS:
        if host in pretty_host:
            return host
    return None

def host_label(host: str) -> str:
    return HOST_LABELS.get(host, host)


# ─────────────────────────────────────────────
# Audit log writer (JSONL — one event per line)
# ─────────────────────────────────────────────

def write_audit(result: ScanResult, url: str, method: str, ai_provider: str):
    entry = {
        "timestamp": result.timestamp,
        "url": url,
        "method": method,
        "ai_provider": ai_provider,
        "action": result.action,
        "blocked": result.blocked,
        "payload_hash": result.payload_hash,
        "payload_size_bytes": result.payload_size_bytes,
        "finding_count": len(result.findings),
        "findings": [
            {
                "type": f.pattern_name,
                "severity": f.severity,
                "preview": f.match_preview,  # redacted
                "blocked": f.blocked,
            }
            for f in result.findings
        ],
    }
    with open(LOG_FILE, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


# ─────────────────────────────────────────────
# Blocked response
# ─────────────────────────────────────────────

def blocked_response(flow: http.HTTPFlow, result: ScanResult):
    findings_summary = ", ".join(
        f"{f.pattern_name}({f.severity})" for f in result.findings if f.blocked
    )
    body = json.dumps({
        "error": {
            "type": "coworkguard_blocked",
            "message": f"CoworkGuard blocked this request — sensitive data detected: {findings_summary}",
            "payload_hash": result.payload_hash,
            "timestamp": result.timestamp,
        }
    })
    flow.response = http.Response.make(
        403,
        body,
        {"Content-Type": "application/json", "X-CoworkGuard": "BLOCKED"},
    )


# ─────────────────────────────────────────────
# mitmproxy hooks
# ─────────────────────────────────────────────

def request(flow: http.HTTPFlow):
    """Intercept outbound requests to all monitored AI API endpoints."""

    host = matched_host(flow.request.pretty_host)
    if not host:
        return

    url = flow.request.pretty_url
    method = flow.request.method
    provider = host_label(host)

    # Only scan POST requests (completions, messages, generations)
    if method != "POST":
        return

    raw_body = flow.request.content
    if not raw_body:
        return

    # Run scan
    result = scanner.scan_json_payload(raw_body)

    # Always write to audit log
    write_audit(result, url, method, provider)

    if result.blocked:
        log.warning(
            f"BLOCKED [{provider}] {url} — {len(result.findings)} findings "
            f"({', '.join(f.pattern_name for f in result.findings if f.blocked)})"
        )
        blocked_response(flow, result)
        return

    if result.findings:
        log.info(
            f"FLAGGED [{provider}] {url} — {len(result.findings)} findings "
            f"({', '.join(f.pattern_name for f in result.findings)})"
        )
        flow.request.headers["X-CoworkGuard-Findings"] = str(len(result.findings))
        flow.request.headers["X-CoworkGuard-Action"] = "FLAGGED"
        flow.request.headers["X-CoworkGuard-Provider"] = provider
    else:
        flow.request.headers["X-CoworkGuard-Action"] = "CLEAN"
        flow.request.headers["X-CoworkGuard-Provider"] = provider


def response(flow: http.HTTPFlow):
    """Tag responses so the dashboard knows which were intercepted."""
    if not matched_host(flow.request.pretty_host):
        return
    action = flow.request.headers.get("X-CoworkGuard-Action", "UNKNOWN")
    provider = flow.request.headers.get("X-CoworkGuard-Provider", "Unknown")
    flow.response.headers["X-CoworkGuard-Intercepted"] = "true"
    flow.response.headers["X-CoworkGuard-Action"] = action
    flow.response.headers["X-CoworkGuard-Provider"] = provider