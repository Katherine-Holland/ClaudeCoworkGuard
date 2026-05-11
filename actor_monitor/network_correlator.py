"""
CoworkGuard AI Actor Monitor — Network Correlator
© 2026 Katherine Weston. All rights reserved.

Track 2C: correlates AX access events with outbound network connections.

The "killer feature":
  Claude Desktop accessed 1Password, then connected to
  api.anthropic.com 4 seconds later.

How it works:
  1. agent_guard.py writes AX_ACCESS_DETECTED events to the correlation buffer
  2. Every 2 seconds, poll_network_connections() runs lsof to get TCP connections
  3. correlate() matches connections to buffered AX events by PID/process-tree
  4. On match: fire NETWORK_AFTER_SENSITIVE_ACCESS — CRITICAL

Matching rules:
  - Same PID as the actor that triggered AX event, OR
  - Child process of that actor (process-tree matching)
  - Within CORRELATION_TTL seconds of the AX event
  - Destination classified as: known AI API, unknown external, or localhost

Severity:
  - Sensitive AX + known AI API host  = CRITICAL
  - Sensitive AX + unknown external   = HIGH
  - Sensitive AX + localhost only     = MEDIUM

Uses lsof — no special permissions required.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("coworkguard.network_correlator")

LOG_DIR = Path.home() / ".coworkguard" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────
# Known AI API hosts
# ─────────────────────────────────────────────

KNOWN_AI_HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.perplexity.ai",
    "api.groq.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.cohere.ai",
    "huggingface.co",
    "api.together.xyz",
    "api.x.ai",
    "api.cursor.sh",
    "copilot-proxy.githubusercontent.com",
}

CORRELATION_TTL  = 10    # seconds — AX event expires after this
POLL_INTERVAL    = 2     # seconds between lsof polls
ALERT_COOLDOWN   = 300   # seconds before same correlation re-alerts


# ─────────────────────────────────────────────
# Classify destination
# ─────────────────────────────────────────────

def _classify_destination(host: str, port: str) -> Tuple[str, str]:
    """
    Returns (classification, severity):
      known_ai_api  → CRITICAL
      unknown_external → HIGH
      localhost     → MEDIUM
    """
    host_lower = host.lower()

    # Localhost / private ranges
    if (host_lower in ("localhost", "127.0.0.1", "::1") or
            host_lower.startswith("192.168.") or
            host_lower.startswith("10.") or
            host_lower.startswith("172.")):
        return "localhost", "MEDIUM"

    # Known AI API
    for ai_host in KNOWN_AI_HOSTS:
        if host_lower == ai_host or host_lower.endswith("." + ai_host):
            return "known_ai_api", "CRITICAL"

    return "unknown_external", "HIGH"


# ─────────────────────────────────────────────
# lsof network connection parser
# ─────────────────────────────────────────────

def _parse_lsof_output(output: str) -> List[Dict]:
    """
    Parse output of: lsof -iTCP -sTCP:ESTABLISHED -n -P
    Returns list of connection dicts.
    """
    connections = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        # Skip header
        if parts[0] == "COMMAND":
            continue
        try:
            command = parts[0]
            pid     = int(parts[1])
            # Name field contains local->remote or local<->remote
            name_field = parts[-1]
            if "->" not in name_field:
                continue
            local, remote = name_field.split("->", 1)
            # Parse remote host:port
            if ":" in remote:
                # Handle IPv6 [::1]:port
                if remote.startswith("["):
                    match = re.match(r'\[([^\]]+)\]:(\d+)', remote)
                    if match:
                        remote_host = match.group(1)
                        remote_port = match.group(2)
                    else:
                        continue
                else:
                    remote_host, remote_port = remote.rsplit(":", 1)
            else:
                continue

            connections.append({
                "command":     command,
                "pid":         pid,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "timestamp":   time.monotonic(),
            })
        except (ValueError, IndexError):
            continue
    return connections


def poll_network_connections() -> List[Dict]:
    """Run lsof and return current TCP connections."""
    try:
        result = subprocess.run(
            ["lsof", "-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"],
            capture_output=True, text=True, timeout=5
        )
        return _parse_lsof_output(result.stdout)
    except Exception as e:
        log.debug("lsof failed: %s", e)
        return []


# ─────────────────────────────────────────────
# Process tree helper
# ─────────────────────────────────────────────

def _get_child_pids(parent_pid: int) -> Set[int]:
    """Get all child PIDs of a process using ps."""
    try:
        result = subprocess.run(
            ["pgrep", "-P", str(parent_pid)],
            capture_output=True, text=True, timeout=2
        )
        return {int(p) for p in result.stdout.split() if p.strip().isdigit()}
    except Exception:
        return set()


# ─────────────────────────────────────────────
# Correlation buffer
# ─────────────────────────────────────────────

class CorrelationBuffer:
    """
    Stores recent AX access events pending network correlation.
    Thread-safe — shared between agent_guard poll loop and network monitor.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._events: List[Dict] = []
        self._alerted: Dict[str, float] = {}  # key -> monotonic timestamp

    def add(self, actor_id: str, actor_pid: int, actor_name: str,
             target_app: str, target_bundle_id: str) -> None:
        """Add an AX access event to the buffer."""
        now = time.monotonic()
        with self._lock:
            self._events.append({
                "actor_id":         actor_id,
                "actor_pid":        actor_pid,
                "actor_name":       actor_name,
                "target_app":       target_app,
                "target_bundle_id": target_bundle_id,
                "timestamp":        now,
                "expires_at":       now + CORRELATION_TTL,
            })

    def get_active(self) -> List[Dict]:
        """Return non-expired AX events."""
        now = time.monotonic()
        with self._lock:
            self._events = [e for e in self._events if e["expires_at"] > now]
            return list(self._events)

    def already_alerted(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            ts = self._alerted.get(key, 0)
            return (now - ts) < ALERT_COOLDOWN

    def mark_alerted(self, key: str) -> None:
        with self._lock:
            self._alerted[key] = time.monotonic()
            # Reap old entries
            now = time.monotonic()
            self._alerted = {
                k: v for k, v in self._alerted.items()
                if (now - v) < ALERT_COOLDOWN * 2
            }


# ─────────────────────────────────────────────
# Correlation engine
# ─────────────────────────────────────────────

def correlate(ax_events: List[Dict], connections: List[Dict],
               buffer: CorrelationBuffer) -> List[Dict]:
    """
    Match AX events to network connections.
    Returns list of correlation findings.
    """
    findings = []
    now = time.monotonic()

    for event in ax_events:
        actor_pid  = event["actor_pid"]
        actor_id   = event["actor_id"]
        actor_name = event["actor_name"]
        target_app = event["target_app"]
        ax_time    = event["timestamp"]

        # Get child PIDs for process-tree matching
        child_pids = _get_child_pids(actor_pid)
        relevant_pids = {actor_pid} | child_pids

        for conn in connections:
            # Match by PID (direct or child process)
            if conn["pid"] not in relevant_pids:
                continue

            # Only consider connections made after the AX event
            conn_time = conn["timestamp"]
            if conn_time < ax_time:
                continue

            seconds_after = round(conn_time - ax_time, 1)
            if seconds_after > CORRELATION_TTL:
                continue

            host = conn["remote_host"]
            port = conn["remote_port"]
            classification, severity = _classify_destination(host, port)

            # Skip pure localhost — not interesting
            if classification == "localhost":
                continue

            # Dedupe alert key
            alert_key = f"{actor_id}:{target_app}:{host}"
            if buffer.already_alerted(alert_key):
                continue

            buffer.mark_alerted(alert_key)

            # Human-readable destination
            if classification == "known_ai_api":
                dest_display = host
            else:
                dest_display = f"{host}:{port}"

            finding = {
                "actor_id":         actor_id,
                "actor_name":       actor_name,
                "actor_pid":        actor_pid,
                "conn_pid":         conn["pid"],
                "target_app":       target_app,
                "destination":      host,
                "destination_port": port,
                "classification":   classification,
                "severity":         severity,
                "seconds_after":    seconds_after,
                "dest_display":     dest_display,
            }
            findings.append(finding)
            log.warning(
                "NETWORK_AFTER_SENSITIVE_ACCESS [%s] accessed %s, "
                "then connected to %s %.1fs later — %s",
                actor_name, target_app, dest_display, seconds_after, severity
            )

    return findings


# ─────────────────────────────────────────────
# Alert + log
# ─────────────────────────────────────────────

def _notify(title: str, message: str) -> None:
    safe_title = title.replace('"', "'")
    safe_msg   = message.replace('"', "'")
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "{safe_msg}" with title "⚠️ CoworkGuard" '
            f'subtitle "{safe_title}"'
        ], timeout=3, capture_output=True)
    except Exception:
        pass


def _post_to_dashboard(payload: bytes) -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://localhost:7070/api/log-event",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass


def fire_correlation_alert(finding: Dict) -> None:
    """Write audit log entry and notify user."""
    actor_name   = finding["actor_name"]
    target_app   = finding["target_app"]
    dest_display = finding["dest_display"]
    seconds      = finding["seconds_after"]
    severity     = finding["severity"]
    classification = finding["classification"]

    # Notification text — factual, not accusatory
    if classification == "known_ai_api":
        notif_msg = (
            f"{actor_name} accessed {target_app}, then connected to "
            f"{dest_display} {seconds}s later."
        )
    else:
        notif_msg = (
            f"{actor_name} accessed {target_app}, then made an outbound "
            f"connection {seconds}s later."
        )

    _notify(f"{actor_name} — network activity after sensitive access", notif_msg)

    # Audit log
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    entry = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "type":           "NETWORK_AFTER_SENSITIVE_ACCESS",
        "source":         "network_correlator",
        "action":         "FLAGGED",
        "blocked":        False,
        "severity":       severity,
        "actor_id":       finding["actor_id"],
        "actor_name":     actor_name,
        "target_app":     target_app,
        "destination":    finding["destination"],
        "seconds_after":  seconds,
        "classification": classification,
        "finding_count":  1,
        "findings": [{
            "type":     "NETWORK_AFTER_SENSITIVE_ACCESS",
            "severity": severity,
            "preview":  notif_msg,
            "blocked":  False,
        }],
    }
    with open(log_file, "a") as fh:
        fh.write(json.dumps(entry) + "\n")

    # Post to dashboard (non-blocking)
    payload = json.dumps({
        "type":       "NETWORK_AFTER_SENSITIVE_ACCESS",
        "severity":   severity,
        "action":     "FLAGGED",
        "actor_id":   finding["actor_id"],
        "actor_name": actor_name,
        "target_app": target_app,
        "destination": finding["destination"],
        "seconds_after": seconds,
        "timestamp":  entry["timestamp"],
        "message":    notif_msg,
    }).encode()
    threading.Thread(
        target=_post_to_dashboard, args=(payload,), daemon=True
    ).start()


# ─────────────────────────────────────────────
# Public API — used by agent_guard.py
# ─────────────────────────────────────────────

# Module-level shared buffer
_buffer = CorrelationBuffer()


def record_ax_event(actor_id: str, actor_pid: int, actor_name: str,
                     target_app: str, target_bundle_id: str) -> None:
    """Called by agent_guard when an AX co-occurrence is detected."""
    _buffer.add(actor_id, actor_pid, actor_name, target_app, target_bundle_id)


def run_correlation_check() -> None:
    """
    Called every 2 seconds from the network monitor thread.
    Polls connections and fires correlation alerts.
    """
    ax_events = _buffer.get_active()
    if not ax_events:
        return  # nothing pending — skip lsof call

    connections = poll_network_connections()
    if not connections:
        return

    findings = correlate(ax_events, connections, _buffer)
    for finding in findings:
        fire_correlation_alert(finding)


def start_network_monitor() -> threading.Thread:
    """
    Start the background network polling thread.
    Returns the thread — caller can join if needed.
    """
    def _loop():
        log.info("Network correlator started — polling every %ds", POLL_INTERVAL)
        while True:
            try:
                run_correlation_check()
            except Exception as e:
                log.debug("Correlation error: %s", e)
            time.sleep(POLL_INTERVAL)

    t = threading.Thread(target=_loop, daemon=True, name="network-correlator")
    t.start()
    return t


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CoworkGuard NetCorr] %(message)s"
    )

    print("Network correlator self-test")
    print("Polling connections for 10 seconds...\n")

    conns = poll_network_connections()
    print(f"Active TCP connections: {len(conns)}")
    for c in conns[:10]:
        dest_type, sev = _classify_destination(c['remote_host'], c['remote_port'])
        print(f"  PID {c['pid']:6} {c['command']:20} -> {c['remote_host']:30} "
              f"[{dest_type}] [{sev}]")

    print("\nTesting correlation buffer...")
    buf = CorrelationBuffer()
    buf.add("claude_desktop", 9999, "Claude Desktop", "1Password",
            "com.1password.1password")
    active = buf.get_active()
    print(f"  Buffered AX events: {len(active)}")

    print("\nTesting process tree...")
    import os
    children = _get_child_pids(os.getpid())
    print(f"  Child PIDs of this process: {children}")

    print("\nDone.")
