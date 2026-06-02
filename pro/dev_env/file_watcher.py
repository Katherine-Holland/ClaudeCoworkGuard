"""
CoworkGuard Pro — File Watcher
© 2026 Katherine Weston. All rights reserved.

Watches known sensitive paths for file creation and modification events.
Complements process_scanner.py — together they cover both reads and writes.

FSEvents / watchdog scope:
  - Reliable for: file writes, creates, deletes, renames
  - NOT reliable for: reads (use process_scanner.py for that)
  - Latency: near-instantaneous on macOS with FSEvents backend

Architecture:
  - Watchdog observer watches WATCH_PATHS directories recursively
  - Each event filtered through path_classifier
  - Sensitive events fired to /api/dev-env-event
  - No actor attribution here — server.py stamps actor_id via stamp_event()

Dependencies:
  - watchdog >= 3.0 (pip install watchdog)
  - Falls back to polling if watchdog not available
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .path_classifier import classify, is_sensitive, WATCH_PATHS, ENV_FILE_PATTERNS

log = logging.getLogger("coworkguard.file_watcher")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    log.warning("watchdog not installed — file watcher unavailable. pip install watchdog")

DEDUP_WINDOW = 30  # seconds — don't re-fire same path within this window

_fired: dict[str, float] = {}  # path -> last_fired_monotonic


def _should_fire(path: str) -> bool:
    now = time.monotonic()
    last = _fired.get(path, 0)
    if now - last > DEDUP_WINDOW:
        _fired[path] = now
        return True
    return False


# ─────────────────────────────────────────────
# Watchdog event handler
# ─────────────────────────────────────────────

class SensitivePathHandler(FileSystemEventHandler):
    """Handles FSEvents for sensitive directories."""

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path, "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle(event.dest_path, "moved")

    def _handle(self, path: str, change_type: str) -> None:
        if not is_sensitive(path):
            # Also check env file patterns by name
            name = Path(path).name
            if not any(name == p or name.startswith(".env") for p in ENV_FILE_PATTERNS):
                return

        if not _should_fire(path):
            return

        clf = classify(path)
        if not clf:
            return

        log.info(
            "File watcher: %s %s — %s",
            clf.label, change_type, _shorten_path(path)
        )

        event = _build_event(path, change_type, clf)
        _fire_event(event)


def _build_event(path: str, change_type: str, clf) -> dict:
    return {
        "type":        "DEV_ENV_ACCESS",
        "source":      "file_watcher",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "path":        path,
        "path_short":  _shorten_path(path),
        "change_type": change_type,

        # Classification
        "event_subtype":  clf.event_type,
        "severity":       clf.severity,
        "label":          clf.label,
        "description":    clf.description,
        "category":       clf.category,
        "tags":           clf.tags,
        "clf_confidence": clf.confidence,

        # Actor identity stamped by server.py stamp_event()
        # No actor_id here — server joins it via port/registry lookup
        "confidence": "none",  # will be upgraded by stamp_event()

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
    try:
        home = str(Path.home())
        if path.startswith(home):
            return "~" + path[len(home):]
    except Exception:
        pass
    return path


def _fire_event(event: dict) -> None:
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
        log.debug("Failed to fire file watcher event: %s", e)


# ─────────────────────────────────────────────
# Observer management
# ─────────────────────────────────────────────

_observer: Optional[Observer] = None
_watcher_thread: Optional[threading.Thread] = None


def start_watcher() -> bool:
    """
    Start the file system watcher.
    Returns True if started successfully, False if watchdog not available.
    """
    global _observer

    if not HAS_WATCHDOG:
        log.warning("watchdog not available — install with: pip install watchdog")
        return False

    if _observer and _observer.is_alive():
        return True

    handler = SensitivePathHandler()
    _observer = Observer()

    watched = 0
    for raw_path in WATCH_PATHS:
        path = Path(raw_path).expanduser()
        if path.exists():
            try:
                _observer.schedule(handler, str(path), recursive=True)
                watched += 1
                log.debug("Watching: %s", path)
            except Exception as e:
                log.debug("Could not watch %s: %s", path, e)
        # Don't warn for missing paths — they may not exist on this machine

    if watched == 0:
        log.info("No sensitive paths found to watch yet — watcher standing by")

    _observer.start()
    log.info("File watcher started — watching %d sensitive directories", watched)
    return True


def stop_watcher() -> None:
    global _observer
    if _observer:
        try:
            _observer.stop()
            _observer.join(timeout=3)
        except Exception:
            pass
        _observer = None
    log.info("File watcher stopped")


def is_running() -> bool:
    return _observer is not None and _observer.is_alive()
