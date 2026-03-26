"""
CoworkGuard - mitmproxy Interceptor
Sits between browser/Cowork desktop app and api.anthropic.com.
Scans all outbound payloads before they leave your machine.

Usage:
  pip install mitmproxy
  mitmproxy -s proxy.py --listen-port 8080

Then set your system proxy to 127.0.0.1:8080
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from mitmproxy import http
from mitmproxy.net.http import Headers

from scanner import CoworkScanner, ScanResult

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

ANTHROPIC_HOST = "api.anthropic.com"
LOG_DIR = Path.home() / ".coworkguard" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"audit_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"

# Tune these to your risk tolerance
scanner = CoworkScanner(
    block_on_critical=True,   # Block SSNs, raw private keys, CC numbers
    block_on_high=False,      # Flag but don't block JWTs, bearer tokens etc (set True for max protection)
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CoworkGuard] %(message)s")
log = logging.getLogger("coworkguard")


# ─────────────────────────────────────────────
# Audit log writer (JSONL — one event per line)
# ─────────────────────────────────────────────

def write_audit(result: ScanResult, url: str, method: str):
    entry = {
        "timestamp": result.timestamp,
        "url": url,
        "method": method,
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
    """Intercept outbound requests to api.anthropic.com"""

    if ANTHROPIC_HOST not in flow.request.pretty_host:
        return

    url = flow.request.pretty_url
    method = flow.request.method

    # Only scan POST requests (completions, messages)
    if method != "POST":
        return

    raw_body = flow.request.content
    if not raw_body:
        return

    # Run scan
    result = scanner.scan_json_payload(raw_body)

    # Always write to audit log
    write_audit(result, url, method)

    if result.blocked:
        log.warning(
            f"BLOCKED {url} — {len(result.findings)} findings "
            f"({', '.join(f.pattern_name for f in result.findings if f.blocked)})"
        )
        blocked_response(flow, result)
        return

    if result.findings:
        log.info(
            f"FLAGGED {url} — {len(result.findings)} findings "
            f"({', '.join(f.pattern_name for f in result.findings)})"
        )
        # Inject warning header so dashboard can highlight flagged requests
        flow.request.headers["X-CoworkGuard-Findings"] = str(len(result.findings))
        flow.request.headers["X-CoworkGuard-Action"] = "FLAGGED"
    else:
        flow.request.headers["X-CoworkGuard-Action"] = "CLEAN"


def response(flow: http.HTTPFlow):
    """Tag responses so the dashboard knows which were intercepted"""
    if ANTHROPIC_HOST not in flow.request.pretty_host:
        return
    action = flow.request.headers.get("X-CoworkGuard-Action", "UNKNOWN")
    flow.response.headers["X-CoworkGuard-Intercepted"] = "true"
    flow.response.headers["X-CoworkGuard-Action"] = action

#Copyright (c) 2026 [Katherine Weston]. All rights reserved.
#Licensed under MIT with Commons Clause — see LICENSE for details.
#Commercial use prohibited without a separate commercial license.