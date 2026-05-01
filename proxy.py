"""
Copyright (c) 2026 Katherine Weston. All rights reserved.
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
from server import load_settings, check_payload_folders

# MCP Trust Gateway — scans tool responses before they reach the LLM
try:
    from mcp_trust.policy_engine import PolicyEngine
    _policy_engine = PolicyEngine()
    MCP_TRUST_AVAILABLE = True
except ImportError:
    MCP_TRUST_AVAILABLE = False
    log_placeholder = None

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

# MCP HTTP/SSE tool server patterns — intercept tool responses
MCP_TOOL_HOSTS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
]

def is_mcp_tool_host(host: str) -> bool:
    """Return True if this looks like a local MCP tool server."""
    for h in MCP_TOOL_HOSTS:
        if h in host:
            return True
    return False


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

# Initialized with safe defaults; block thresholds are refreshed from
# settings.json on every request so dashboard changes take effect immediately.
scanner = CoworkScanner(
    block_on_critical=True,
    block_on_high=False,
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

    # Reload settings on every request so dashboard changes take effect
    # without restarting the proxy.
    settings = load_settings()
    scanner.block_on_critical = settings.get("block_on_critical", True)
    scanner.block_on_high     = settings.get("block_on_high", False)

    # ── Folder allowlist check ──
    # If user has configured allowed_folders, check payload for paths
    # originating outside those folders before the request leaves the machine.
    allowed_folders = settings.get("allowed_folders", [])
    if allowed_folders:
        try:
            payload_dict = json.loads(raw_body)
            blocked_paths = check_payload_folders(payload_dict, allowed_folders)
            if blocked_paths:
                body = json.dumps({
                    "error": {
                        "type": "coworkguard_folder_policy",
                        "message": f"CoworkGuard blocked this request — content from outside allowed folders detected",
                        "blocked_paths": blocked_paths[:5],  # cap list length
                        "allowed_folders": allowed_folders,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                })
                flow.response = http.Response.make(
                    403, body,
                    {"Content-Type": "application/json", "X-CoworkGuard": "FOLDER_BLOCKED"}
                )
                log.warning(
                    f"FOLDER_BLOCKED [{provider}] {url} — paths outside allowed folders: "
                    f"{blocked_paths[:3]}"
                )
                # Write to audit log
                from dataclasses import field as dc_field
                import hashlib
                fake_result = ScanResult(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    payload_hash=hashlib.sha256(raw_body).hexdigest()[:16],
                    payload_size_bytes=len(raw_body),
                    blocked=True,
                    action="BLOCKED",
                )
                write_audit(fake_result, url, method, provider)
                return
        except Exception:
            pass  # if we can't parse JSON, fall through to normal scan

    # Run scan
    result = scanner.scan_json_payload(raw_body, url=url)

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


def write_mcp_audit(decision, url: str, tool_name: str):
    """Write MCP trust gateway decision to audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "MCP_TOOL_RESPONSE",
        "url": url,
        "tool_name": tool_name,
        "action": decision.recommended_action,
        "blocked": decision.is_blocked,
        "payload_hash": decision.merged.results[0].payload_hash if decision.merged.results else "",
        "finding_count": len(decision.merged.all_findings),
        "reasons": decision.merged.all_reasons,
        "findings": [
            {
                "type": f.pattern_name,
                "severity": f.severity,
                "preview": f.match_preview,
                "blocked": f.blocked,
            }
            for f in decision.merged.all_findings
        ],
    }
    with open(LOG_FILE, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def response(flow: http.HTTPFlow):
    """
    Intercept responses:
    1. Tag AI API responses with CoworkGuard action headers
    2. Scan MCP tool responses through the policy engine before
       they can reach the LLM context
    """
    host = flow.request.pretty_host

    # ── AI API responses — tag headers ──
    if matched_host(host):
        action = flow.request.headers.get("X-CoworkGuard-Action", "UNKNOWN")
        provider = flow.request.headers.get("X-CoworkGuard-Provider", "Unknown")
        flow.response.headers["X-CoworkGuard-Intercepted"] = "true"
        flow.response.headers["X-CoworkGuard-Action"] = action
        flow.response.headers["X-CoworkGuard-Provider"] = provider
        return

    # ── MCP tool responses — scan through policy engine ──
    if not MCP_TRUST_AVAILABLE:
        return
    if not is_mcp_tool_host(host):
        return
    if flow.response.status_code not in (200, 201):
        return

    raw_body = flow.response.content
    if not raw_body:
        return

    try:
        body_text = raw_body.decode("utf-8", errors="replace")
    except Exception:
        return

    # Extract tool name from request path or headers
    tool_name = flow.request.path.strip("/").split("/")[-1] or "unknown_tool"
    tool_server = f"http://{host}"

    # Extract tool metadata from request if available
    tool_description = ""
    tool_schema = None
    try:
        req_body = json.loads(flow.request.content or b"{}")
        tool_description = req_body.get("description", "")
        tool_schema = req_body.get("inputSchema") or req_body.get("schema")
    except Exception:
        pass

    # Run through policy engine
    decision = _policy_engine.evaluate(
        tool_output=body_text,
        tool_name=tool_name,
        tool_description=tool_description,
        tool_schema=tool_schema,
        tool_server=tool_server,
    )

    # Write to audit log
    write_mcp_audit(decision, flow.request.pretty_url, tool_name)

    # Take action
    if decision.is_blocked or decision.is_quarantined:
        log.warning(
            f"MCP_BLOCKED [{tool_name}] {flow.request.pretty_url} — "
            f"{decision.merged.all_reasons}"
        )
        flow.response = http.Response.make(
            403,
            decision.safe_response or "{}",
            {"Content-Type": "application/json", "X-CoworkGuard": "MCP_BLOCKED"}
        )
    elif decision.requires_confirmation:
        log.info(
            f"MCP_CONFIRM [{tool_name}] {flow.request.pretty_url} — "
            f"held for user review"
        )
        # Tag response — dashboard will show confirm UI
        flow.response.headers["X-CoworkGuard-MCP"] = "CONFIRM"
        flow.response.headers["X-CoworkGuard-MCP-Message"] = decision.user_message[:200]
    else:
        flow.response.headers["X-CoworkGuard-MCP"] = "CLEAN"