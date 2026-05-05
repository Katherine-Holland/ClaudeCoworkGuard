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

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

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

# MCP HTTP/SSE tool server patterns — intercept tool responses.
# Use exact hostname matching (not substring) to prevent bypass via
# hostnames like "notlocalhost.com" or "localhost.evil.com".
MCP_TOOL_HOSTS = {
    "localhost",
    "127.0.0.1",
}

def is_mcp_tool_host(host: str) -> bool:
    """Return True if this is a local MCP tool server (exact host match)."""
    # Strip port if present
    bare = host.split(":")[0].lower()
    return bare in MCP_TOOL_HOSTS


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

def _log_file() -> Path:
    """Return today's audit log path — computed at write time so the proxy
    never writes to a stale previous-day file after midnight."""
    return LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"

# Initialized with safe defaults; block thresholds are refreshed from
# settings.json on every request so dashboard changes take effect immediately.
# A lock guards the two mutable attributes against concurrent mitmproxy threads.
scanner = CoworkScanner(
    block_on_critical=True,
    block_on_high=False,
)
_scanner_lock = threading.Lock()

# Cache of tool metadata from MCP tools/list responses, keyed by server host.
# Populated when we see a tools/list response; consumed when evaluating
# tool/call responses from the same server.
# { "host": { "tool_name": {"description": str, "inputSchema": dict} } }
_tool_metadata_cache: Dict[str, Dict] = {}
_cache_lock = threading.Lock()

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
    with open(_log_file(), "a") as fh:
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
    # without restarting the proxy. Lock guards concurrent attribute mutation.
    settings = load_settings()
    with _scanner_lock:
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
    with open(_log_file(), "a") as fh:
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
        resp_json = json.loads(body_text)
    except Exception:
        return

    tool_server = f"http://{host}"
    path = flow.request.path

    # ── Cache tools/list responses ──
    # MCP tools/list returns {"tools": [{"name":..., "description":..., "inputSchema":...}]}
    # Store per server so we can look up metadata when tool/call responses arrive.
    if "tools/list" in path or (
        isinstance(resp_json, dict) and "tools" in resp_json
        and isinstance(resp_json.get("tools"), list)
        and resp_json["tools"]
        and "name" in resp_json["tools"][0]
    ):
        tools_list = resp_json.get("tools", [])
        if tools_list:
            with _cache_lock:
                _tool_metadata_cache[host] = {
                    t["name"]: {
                        "description": t.get("description", ""),
                        "inputSchema": t.get("inputSchema"),
                    }
                    for t in tools_list
                    if isinstance(t, dict) and "name" in t
                }
            log.info(f"MCP_CACHE [{host}] cached metadata for {len(tools_list)} tool(s)")
        return  # tools/list itself is not a tool output — nothing to scan

    # ── Resolve tool name and metadata ──
    # Try JSON-RPC 2.0 result format: {"result": {"content": [...]}, "id": ...}
    # or plain {"content": [...]} for simpler servers.
    tool_name = "unknown_tool"
    try:
        req_body = json.loads(flow.request.content or b"{}")
        # JSON-RPC 2.0: method="tools/call", params={"name": "tool_name", ...}
        params = req_body.get("params", {})
        if isinstance(params, dict) and "name" in params:
            tool_name = params["name"]
        else:
            # Fall back to last path segment
            tool_name = path.strip("/").split("/")[-1] or "unknown_tool"
    except Exception:
        tool_name = path.strip("/").split("/")[-1] or "unknown_tool"

    # Look up description and schema from cached tools/list data
    tool_description = ""
    tool_schema = None
    with _cache_lock:
        server_cache = _tool_metadata_cache.get(host, {})
        if tool_name in server_cache:
            tool_description = server_cache[tool_name].get("description", "")
            tool_schema = server_cache[tool_name].get("inputSchema")

    # Extract the actual text content from the tool response
    # JSON-RPC 2.0 wraps it: {"result": {"content": [{"type":"text","text":"..."}]}}
    tool_output = body_text
    try:
        result_obj = resp_json.get("result", resp_json)
        content_blocks = result_obj.get("content", [])
        if content_blocks and isinstance(content_blocks, list):
            text_parts = [
                b.get("text", "") for b in content_blocks
                if isinstance(b, dict) and b.get("type") == "text"
            ]
            if text_parts:
                tool_output = "\n".join(text_parts)
    except Exception:
        pass

    # Run secret scanner on tool output — catches PII, credentials, SSNs
    # This runs alongside the policy engine (injection/metadata/unicode)
    secret_result = scanner.scan(tool_output)
    if secret_result.blocked:
        log.warning(
            f"MCP_SECRET_BLOCKED [{tool_name}] {flow.request.pretty_url} — "
            f"{[f.pattern_name for f in secret_result.findings if f.blocked]}"
        )
        findings_summary = ", ".join(
            f"{f.pattern_name}({f.severity})" for f in secret_result.findings if f.blocked
        )
        body = json.dumps({
            "error": {
                "type": "coworkguard_mcp_secret_blocked",
                "tool": tool_name,
                "message": f"CoworkGuard blocked this tool response — sensitive data detected: {findings_summary}",
                "payload_hash": secret_result.payload_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        })
        flow.response = http.Response.make(
            403, body,
            {"Content-Type": "application/json", "X-CoworkGuard": "MCP_SECRET_BLOCKED"}
        )
        return

    # Run through policy engine
    decision = _policy_engine.evaluate(
        tool_output=tool_output,
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