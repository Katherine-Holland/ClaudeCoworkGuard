"""
CoworkGuard Pro — Process Scanner
© 2026 Katherine Weston. All rights reserved.

Polls open file handles of known AI processes using lsof.
This is where actor attribution and sensitive file access finally merge.

Why lsof polling rather than FSEvents alone:
  - FSEvents reliably catches writes but NOT reads
  - AI tools reading credentials never write anything — reads are the risk
  - lsof shows what a process currently has open, not just what changed

Poll interval: 10 seconds — balances detection speed vs CPU cost.
Only scans processes that are in the actor registry (known AI tools).
Fires DEV_ENV_ACCESS events via server.py /api/dev-env-event.

Example sequence this enables:
  Cursor
  ↓ Opened .env file
  ↓ Read GITHUB_TOKEN (~/.config/gh/hosts.yml)
  ↓ 2 seconds later
  Connected externally
  ↓ Confirmed same process (actor_id verified)
"""

from __future__ import annotations

import logging
import subprocess
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set

from .path_classifier import classify, is_sensitive, Classification

log = logging.getLogger("coworkguard.process_scanner")

POLL_INTERVAL   = 10   # seconds between scans
DEDUP_WINDOW    = 60   # seconds — don't re-fire same path+pid within this window


# ─────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────

# Shape: { (pid, path): last_fired_monotonic }
_fired: Dict[tuple[int, str], float] = {}


def _should_fire(pid: int, path: str) -> bool:
    key = (pid, path)
    now = time.monotonic()
    last = _fired.get(key, 0)
    if now - last > DEDUP_WINDOW:
        _fired[key] = now
        return True
    return False


def _reap_dedup_cache() -> None:
    """Remove expired entries to prevent unbounded growth."""
    now = time.monotonic()
    expired = [k for k, v in _fired.items() if now - v > DEDUP_WINDOW * 2]
    for k in expired:
        del _fired[k]


# ─────────────────────────────────────────────
# lsof scanning
# ─────────────────────────────────────────────

def get_open_files(pid: int) -> list[str]:
    """
    Return list of file paths currently open by a process.
    Uses lsof -p {pid} -F n (name field only — fast output).
    Returns empty list on any error or timeout.
    """
    try:
        result = subprocess.run(
            ["lsof", "-p", str(pid), "-F", "n", "-b"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        paths = []
        for line in result.stdout.splitlines():
            # lsof -F n output: lines starting with 'n' are filenames
            if line.startswith("n") and len(line) > 1:
                path = line[1:]  # strip the 'n' prefix
                if path.startswith("/"):  # only absolute paths
                    paths.append(path)
        return paths
    except subprocess.TimeoutExpired:
        log.debug("lsof timeout for PID %s", pid)
        return []
    except Exception as e:
        log.debug("lsof error for PID %s: %s", pid, e)
        return []


def scan_process(pid: int, actor: dict) -> list[dict]:
    """
    Scan open files for a single process.
    Returns list of DEV_ENV_ACCESS event dicts for sensitive files found.
    """
    open_files = get_open_files(pid)
    events = []

    for path in open_files:
        if not is_sensitive(path):
            continue

        if not _should_fire(pid, path):
            continue  # already fired recently for this pid+path

        clf = classify(path)
        if not clf:
            continue

        event = _build_event(pid, path, actor, clf)
        events.append(event)
        log.info(
            "DEV_ENV_ACCESS [%s] %s — %s",
            actor.get("display_name", "?"),
            clf.label,
            path,
        )

    return events


def _build_event(pid: int, path: str, actor: dict, clf: Classification) -> dict:
    """Build a DEV_ENV_ACCESS event dict."""
    return {
        "type":        "DEV_ENV_ACCESS",
        "source":      "process_scanner",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "path":        path,
        "path_short":  _shorten_path(path),

        # Classification
        "event_subtype":  clf.event_type,
        "severity":       clf.severity,
        "label":          clf.label,
        "description":    clf.description,
        "category":       clf.category,
        "tags":           clf.tags,
        "clf_confidence": clf.confidence,

        # Actor identity — from registry
        "actor_id":      actor.get("actor_id", ""),
        "bundle_id":     actor.get("bundle_id", ""),
        "pid":           pid,
        "display_name":  actor.get("display_name", ""),
        "process_name":  actor.get("process_name", ""),
        "session_id":    actor.get("session_id", ""),
        "confidence":    "strong" if actor.get("actor_id") else "weak",

        # Dashboard fields
        "action":        "FLAGGED",
        "blocked":       False,
        "finding_count": 1,
        "findings": [{
            "type":     clf.event_type,
            "severity": clf.severity,
            "preview":  _shorten_path(path),
            "blocked":  False,
            "label":    clf.label,
        }],
    }


def _shorten_path(path: str) -> str:
    """Shorten path for display — replace home dir with ~."""
    try:
        home = str(Path.home())
        if path.startswith(home):
            return "~" + path[len(home):]
    except Exception:
        pass
    return path


# ─────────────────────────────────────────────
# Event firing
# ─────────────────────────────────────────────

def _fire_event(event: dict) -> None:
    """POST event to server.py /api/dev-env-event."""
    try:
        import json as _json
        import urllib.request
        payload = _json.dumps(event).encode()
        req = urllib.request.Request(
            "http://localhost:7070/api/dev-env-event",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        log.debug("Failed to fire dev-env event: %s", e)


# ─────────────────────────────────────────────
# Main scan loop
# ─────────────────────────────────────────────

_running = False
_scan_thread: Optional[threading.Thread] = None


def start_scanner(get_registry_fn) -> None:
    """
    Start the background process scanner thread.

    get_registry_fn: callable that returns current actor registry
                     Shape: { pid: { actor_id, bundle_id, display_name, ... } }
    """
    global _running, _scan_thread
    if _running:
        return

    _running = True
    _scan_thread = threading.Thread(
        target=_scan_loop,
        args=(get_registry_fn,),
        daemon=True,
        name="coworkguard-process-scanner",
    )
    _scan_thread.start()
    log.info("Process scanner started — polling every %ds", POLL_INTERVAL)


def stop_scanner() -> None:
    global _running
    _running = False
    log.info("Process scanner stopped")


def _scan_loop(get_registry_fn) -> None:
    while _running:
        try:
            _reap_dedup_cache()
            registry = get_registry_fn()

            if not registry:
                time.sleep(POLL_INTERVAL)
                continue

            for pid, actor in registry.items():
                if not isinstance(pid, int):
                    continue

                events = scan_process(pid, actor)
                for event in events:
                    _fire_event(event)

        except Exception as e:
            log.error("Process scanner error: %s", e)

        time.sleep(POLL_INTERVAL)


# ─────────────────────────────────────────────
# Standalone scan — for testing
# ─────────────────────────────────────────────

def scan_once(registry: dict) -> list[dict]:
    """
    Run one scan cycle synchronously. Returns all events found.
    Useful for testing and on-demand scans.
    """
    all_events = []
    for pid, actor in registry.items():
        if isinstance(pid, int):
            events = scan_process(pid, actor)
            all_events.extend(events)
            for event in events:
                _fire_event(event)
    return all_events
