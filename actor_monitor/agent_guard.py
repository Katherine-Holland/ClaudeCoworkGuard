"""
CoworkGuard AI Actor Monitor — Agent Guard
© 2026 Katherine Weston. All rights reserved.

Monitors running AI actor processes and detects risky permission combinations
and sensitive app co-occurrence without requiring Accessibility permission.

What it detects:
  - Which AI actor processes are currently running
  - Which sensitive apps are running simultaneously
  - Which AI actors have Accessibility / Full Disk Access / Screen Recording
    (read from macOS TCC.db — requires Full Disk Access only)
  - AI actor + sensitive app running at the same time → HIGH alert
  - AI actor with Accessibility + Full Disk Access → HIGH alert

What it does NOT do (requires AX permission or kernel extension):
  - Intercept actual AX reads
  - Monitor specific UI element access
  - Block network connections

Runs as a background process spawned by main.rs.
Polls every 30 seconds. Writes to daily audit JSONL log.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .actor_registry import ActorRegistry, Actor, SensitiveBundle
from . import network_correlator

log = logging.getLogger("coworkguard.agent_guard")

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

LOG_DIR      = Path.home() / ".coworkguard" / "logs"
SETTINGS_FILE = Path.home() / ".coworkguard" / "settings.json"
LOG_DIR.mkdir(parents=True, exist_ok=True)

POLL_INTERVAL    = 30    # seconds between scans
ALERT_TTL        = 86400 # seconds — re-alert after 24h (handles permission re-grants)
CORRELATION_TTL  = 10    # seconds — AX access + network within this = CRITICAL
                         # TODO: network correlation — Track 2C

# macOS TCC database — stores app permission grants
TCC_DB_PATHS = [
    Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
    Path("/Library/Application Support/com.apple.TCC/TCC.db"),
]

# TCC service identifiers
TCC_ACCESSIBILITY    = "kTCCServiceAccessibility"
TCC_FULL_DISK        = "kTCCServiceSystemPolicyAllFiles"
TCC_SCREEN_RECORDING = "kTCCServiceScreenCapture"
TCC_CAMERA           = "kTCCServiceCamera"
TCC_MICROPHONE       = "kTCCServiceMicrophone"


# ─────────────────────────────────────────────
# TCC permission reader
# ─────────────────────────────────────────────

def _read_tcc_permissions() -> Dict[str, Set[str]]:
    """
    Read macOS TCC.db to find which apps have which permissions.
    Requires Full Disk Access — skipped in free version to avoid
    macOS permission prompts. Returns empty dict gracefully.
    TODO Shield: enable TCC scanning with explicit FDA grant flow.
    """
    # Free version: skip TCC.db entirely — no permission prompt
    # Shield will add explicit FDA onboarding and full permission scanning
    return {}


def _get_permission_labels(bundle_id: str, tcc: Dict[str, Set[str]]) -> List[str]:
    """Return human-readable permission labels for a bundle_id."""
    services = tcc.get(bundle_id, set())
    labels = []
    if TCC_ACCESSIBILITY    in services: labels.append("accessibility")
    if TCC_FULL_DISK        in services: labels.append("full_disk")
    if TCC_SCREEN_RECORDING in services: labels.append("screen_recording")
    if TCC_CAMERA           in services: labels.append("camera")
    if TCC_MICROPHONE       in services: labels.append("microphone")
    return labels


# ─────────────────────────────────────────────
# Process scanning
# ─────────────────────────────────────────────

def _get_running_bundle_id(pid: int) -> Optional[str]:
    """Get bundle ID for a running process using macOS lsappinfo."""
    try:
        result = subprocess.run(
            ["lsappinfo", "info", "-only", "bundleid", str(pid)],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if "bundleid" in line.lower() and "=" in line:
                return line.split("=")[-1].strip().strip('"')
    except Exception:
        pass
    return None


def _build_bundle_cache() -> Dict[int, str]:
    """
    Build a pid→bundle_id map once per scan cycle.
    Avoids spawning one lsappinfo subprocess per process across multiple callers.
    """
    if not HAS_PSUTIL:
        return {}
    cache: Dict[int, str] = {}
    for proc in psutil.process_iter(['pid']):
        try:
            bid = _get_running_bundle_id(proc.info['pid'])
            if bid:
                cache[proc.info['pid']] = bid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return cache


def _get_parent_actor_id(proc, registry: ActorRegistry) -> Optional[str]:
    """Get the actor_id of a process's parent if it's a known AI actor."""
    try:
        parent = proc.parent()
        if parent:
            parent_actor = registry.match_process(name=parent.name())
            return parent_actor.actor_id if parent_actor else None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return None


def scan_running_actors(registry: ActorRegistry,
                         tcc: Dict[str, Set[str]],
                         bundle_cache: Dict[int, str]) -> List[Dict]:
    """
    Scan all running processes and return those matching known AI actors.
    bundle_cache should be built once per poll cycle via _build_bundle_cache().
    """
    if not HAS_PSUTIL:
        return []

    running = []
    seen_actor_ids: Set[str] = set()

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        try:
            name = proc.info['name'] or ''
            pid  = proc.info['pid']

            # Use pre-built cache — avoids one lsappinfo subprocess per process
            bundle_id = bundle_cache.get(pid)

            # Get parent for MCP tool matching
            parent_actor_id = _get_parent_actor_id(proc, registry)

            actor = registry.match_process(
                name=name,
                bundle_id=bundle_id,
                parent_actor_id=parent_actor_id,
            )
            if not actor:
                continue

            # Fix 1: Validate bundle_id against actor's known bundle list.
            # Electron apps (Cursor, Claude Desktop, ChatGPT) spawn XPC helper
            # processes whose bundle_ids contaminate the cache. If the resolved
            # bundle_id isn't in the actor's known list, discard it and fall back
            # to the canonical bundle_id. This catches XPC helpers and any other
            # helper process contamination across all 29 actors.
            if bundle_id and actor.bundle_ids and bundle_id not in actor.bundle_ids:
                bundle_id = None  # discard — helper bundle, not the main app

            # Get permissions from TCC
            perms = []
            if bundle_id:
                perms = _get_permission_labels(bundle_id, tcc)

            # Determine risk level
            risk = _assess_risk(actor, perms)

            # Build proper actor_id: bundle_id:pid:process_start_time
            # Fix 2: correct operator precedence — bundle_id fallback must wrap
            # the ternary so None bundle_id always falls back to bundle_ids[0].
            _bid = bundle_id or (actor.bundle_ids[0] if actor.bundle_ids else actor.actor_id)
            _start = int(proc.info.get('create_time') or 0)
            _full_actor_id = f"{_bid}:{pid}:{_start}"

            entry = {
                "actor_id":     _full_actor_id,
                "display_name": actor.display_name,
                "process_name": actor.display_name,  # stamper weak-match uses process_name
                "pid":          pid,
                "bundle_id":    _bid,
                "process_start_time": _start,
                "permissions":  perms,
                "capabilities": actor.capabilities,
                "risk":         risk,
                "running_since": datetime.fromtimestamp(
                    proc.info['create_time'], tz=timezone.utc
                ).isoformat() if proc.info.get('create_time') else "",
            }

            # For actors requiring parent match, include but mark accordingly
            if actor.requires_parent_match:
                entry["parent_actor_id"] = parent_actor_id
                if not parent_actor_id:
                    continue  # skip — not running as MCP tool

            # Dedupe on full process identity — allows multiple instances of the
            # same app (e.g. two Cursor windows) to appear as separate registry entries.
            if _full_actor_id in seen_actor_ids:
                continue
            seen_actor_ids.add(_full_actor_id)
            running.append(entry)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return running



def _assess_risk(actor: Actor, permissions: List[str]) -> str:
    """
    Assess risk level for a running actor based on permissions.
    CRITICAL: accessibility + full_disk
    HIGH: accessibility alone, or full_disk + network in high-risk actor
    MEDIUM: network capable actor running
    LOW: everything else
    """
    has_ax  = "accessibility"    in permissions
    has_fda = "full_disk"        in permissions
    has_sr  = "screen_recording" in permissions

    if has_ax and has_fda:
        return "critical"
    if has_ax or (has_fda and "network_access" in actor.capabilities):
        return "high"
    if has_sr:
        return "high"
    if "network_access" in actor.capabilities:
        return "medium"
    return "low"


# ─────────────────────────────────────────────
# Alert generation
# ─────────────────────────────────────────────

def _notify(title: str, message: str) -> None:
    # Sanitise — double quotes in title/message break the osascript string
    safe_title   = title.replace('"', "'")
    safe_message = message.replace('"', "'")
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "{safe_message}" with title "⚠️ CoworkGuard" subtitle "{safe_title}"'
        ], timeout=3, capture_output=True)
    except Exception:
        pass


def _post_to_dashboard(payload: bytes) -> None:
    """Send event to dashboard server. Runs on a daemon thread — never blocks the poll loop."""
    try:
        req = urllib.request.Request(
            "http://localhost:7070/api/log-event",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass


def _write_log(event_type: str, severity: str, actor_id: str,
               actor_name: str, detail: str, extra: dict = None) -> None:
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    entry = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "type":          event_type,
        "source":        "agent_guard",
        "action":        "FLAGGED",
        "blocked":       False,
        "severity":      severity,
        "actor_id":      actor_id,
        "actor_name":    actor_name,
        "finding_count": 1,
        "findings": [{
            "type":     event_type,
            "severity": severity,
            "preview":  detail,
            "blocked":  False,
        }],
    }
    if extra:
        entry.update(extra)
    with open(log_file, "a") as fh:
        fh.write(json.dumps(entry) + "\n")

    # Report to dashboard on a daemon thread — avoids blocking the poll loop
    # if the dashboard server is unavailable
    payload = json.dumps({
        "type":       event_type,
        "severity":   severity,
        "action":     "FLAGGED",
        "actor_id":   actor_id,
        "actor_name": actor_name,
        "timestamp":  entry["timestamp"],
        "message":    detail,
    }).encode()
    threading.Thread(target=_post_to_dashboard, args=(payload,), daemon=True).start()


def _reap_alerted(alerted: Dict[str, float]) -> None:
    """Remove alert keys older than ALERT_TTL so re-grants trigger fresh alerts."""
    now = time.monotonic()
    expired = [k for k, t in alerted.items() if now - t > ALERT_TTL]
    for k in expired:
        del alerted[k]


def check_permission_risks(actors: List[Dict], registry: ActorRegistry,
                            alerted: Dict[str, float]) -> None:
    """Alert when an actor has a risky permission combination."""
    for actor_info in actors:
        perms = actor_info.get("permissions", [])
        actor_id = actor_info["actor_id"]
        actor_name = actor_info["display_name"]

        has_ax  = "accessibility" in perms
        has_fda = "full_disk"     in perms

        # Dedupe alerts — suppress within ALERT_TTL window
        alert_key = f"perm:{actor_id}:{':'.join(sorted(perms))}"
        if alert_key in alerted:
            continue

        if has_ax and has_fda:
            alerted[alert_key] = time.monotonic()
            detail = f"{actor_name} has Accessibility and Full Disk Access"
            log.warning("PERM_RISK [%s] %s", actor_id, detail)
            _write_log("PERM_RISK_CRITICAL", "CRITICAL", actor_id, actor_name, detail)
            _notify(
                f"{actor_name} — permission risk",
                "This app has both Accessibility and Full Disk Access. "
                "Review in CoworkGuard Agent Guard tab."
            )
        elif has_ax:
            alerted[alert_key] = time.monotonic()
            detail = f"{actor_name} has Accessibility access"
            log.info("AX_ACCESS [%s] %s", actor_id, detail)
            _write_log("AX_ACCESS_DETECTED", "HIGH", actor_id, actor_name, detail)


def check_sensitive_cooccurrence(actors: List[Dict],
                                   registry: ActorRegistry,
                                   alerted: Dict[str, float],
                                   bundle_cache: Dict[int, str]) -> None:
    """
    Alert when an AI actor and a sensitive app are running simultaneously.
    MVP: detect co-occurrence, not actual AX reads.
    bundle_cache should be built once per poll cycle via _build_bundle_cache().
    """
    if not HAS_PSUTIL:
        return

    # Build bundle_id -> process name from the shared cache
    running_bundles: Dict[str, str] = {}  # bundle_id -> process name
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            bid = bundle_cache.get(proc.info['pid'])
            if bid:
                running_bundles[bid.lower()] = proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Check each running actor against sensitive bundles
    for actor_info in actors:
        actor_id   = actor_info["actor_id"]
        actor_name = actor_info["display_name"]
        perms      = actor_info.get("permissions", [])
        has_ax     = "accessibility" in perms

        for bid, sb in {
            k: v for k, v in
            {b: registry.is_sensitive_bundle(b) for b in running_bundles}.items()
            if v
        }.items():
            alert_key = f"cooccur:{actor_id}:{bid}"
            if alert_key in alerted:
                continue

            # Only alert if actor has AX permission — otherwise just running
            # alongside a sensitive app is not a strong signal
            if not has_ax:
                continue

            alerted[alert_key] = time.monotonic()
            detail = (f"{actor_name} has Accessibility access while "
                      f"{sb.display_name} is running")
            severity = sb.risk
            actor_pid = actor_info.get("pid", 0)

            log.info("AX_COOCCUR [%s] %s", actor_id, detail)
            _write_log(
                "AX_ACCESS_DETECTED", severity,
                actor_id, actor_name, detail,
                extra={"target_app": sb.display_name, "target_bundle": bid}
            )
            _notify(
                f"{actor_name} — sensitive app active",
                f"{actor_name} has Accessibility access while "
                f"{sb.display_name} is open."
            )
            # Feed into network correlator — Track 2C
            network_correlator.record_ax_event(
                actor_id=actor_id,
                actor_pid=actor_pid,
                actor_name=actor_name,
                target_app=sb.display_name,
                target_bundle_id=bid,
            )


# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────

def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}



def _push_actor_registry(actors: list) -> None:
    """
    Push current running actor list to server.py actor registry endpoint.
    Called every scan cycle so server.py can stamp actor_id onto proxy events.
    Enriches actors with session_ids before pushing.
    Fails silently — registry push is best-effort, never blocks the scan loop.
    """
    try:
        from core.identity.session_tracker import build_actor_registry_payload
        enriched = build_actor_registry_payload(actors)
    except ImportError:
        enriched = actors  # core identity not available — push as-is

    try:
        import json as _json
        payload = _json.dumps({"actors": enriched}).encode()
        req = urllib.request.Request(
            "http://localhost:7070/api/actor-registry",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass  # server not running or busy — skip silently


def main() -> None:
    if sys.platform != "darwin":
        log.error("agent_guard requires macOS")
        sys.exit(0)

    if not HAS_PSUTIL:
        log.error("psutil not installed — agent_guard unavailable")
        while True:
            time.sleep(60)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CoworkGuard AgentGuard] %(message)s"
    )

    registry = ActorRegistry()
    log.info(
        "Agent Guard started — %d actors, %d sensitive bundles, polling every %ds",
        registry.actor_count(), registry.sensitive_bundle_count(), POLL_INTERVAL
    )

    alerted: Dict[str, float] = {}  # alert_key -> monotonic timestamp; reaped after ALERT_TTL

    # Start network correlation thread — Track 2C
    network_correlator.start_network_monitor()

    while True:
        try:
            settings = _load_settings()
            if settings.get("quiet_mode", False):
                time.sleep(POLL_INTERVAL)
                continue

            # Reap stale alert keys so re-grants trigger fresh alerts after ALERT_TTL
            _reap_alerted(alerted)

            # Read TCC permissions
            tcc = _read_tcc_permissions()

            # Build bundle ID cache once — shared by all scanners this cycle
            bundle_cache = _build_bundle_cache()

            # Scan running AI actors
            actors = scan_running_actors(registry, tcc, bundle_cache)

            if actors:
                log.info(
                    "Running AI actors: %s",
                    ", ".join(a["display_name"] for a in actors)
                )

            # Check permission risks
            check_permission_risks(actors, registry, alerted)

            # Check sensitive app co-occurrence
            check_sensitive_cooccurrence(actors, registry, alerted, bundle_cache)

            # Push actor registry to server — enables actor stamping on proxy events
            _push_actor_registry(actors)

        except Exception as e:
            log.error("Agent Guard error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
