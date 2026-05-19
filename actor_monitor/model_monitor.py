"""
CoworkGuard AI Actor Monitor — Model Monitor
© 2026 Katherine Weston. All rights reserved.

Watches the filesystem for AI model files appearing on the user's machine.
Detects when browsers, desktop apps, or local AI tools download model weights
without the user explicitly requesting them.

Monitors:
  - Chrome/Edge/Brave Gemini Nano (OptGuideOnDeviceModel/*/weights.bin)
  - Ollama model blobs (~/.ollama/models/blobs/*)
  - LM Studio GGUF files (~/.lmstudio/models/**/*.gguf)
  - Claude Desktop model cache
  - Generic large binary files in known AI app directories

Events fired:
  - LOCAL_MODEL_DOWNLOADED  — new model file detected
  - LOCAL_MODEL_UPDATED     — existing model file changed
  - LOCAL_MODEL_REMOVED     — model file deleted

Runs as a background process. Polls every 60 seconds (configurable).
Uses file hash comparison to detect changes.

Usage:
    python3 -m actor_monitor.model_monitor
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .actor_registry import ActorRegistry, Actor

log = logging.getLogger("coworkguard.model_monitor")

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

LOG_DIR  = Path.home() / ".coworkguard" / "logs"
STATE_FILE = Path.home() / ".coworkguard" / "model_state.json"
SETTINGS_FILE = Path.home() / ".coworkguard" / "settings.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)

POLL_INTERVAL = 5           # seconds between full scans — fast detection
ALLOW_LIST_FILE = Path.home() / ".coworkguard" / "model_download_allowlist.json"

def _is_allowed(actor_id: str) -> bool:
    """Check if this actor is on the model download allow list."""
    try:
        if ALLOW_LIST_FILE.exists():
            allowed = json.loads(ALLOW_LIST_FILE.read_text())
            return actor_id in allowed
    except Exception:
        pass
    return False
MIN_MODEL_SIZE_MB = 50      # ignore files smaller than this — avoid noise
LARGE_MODEL_SIZE_MB = 500   # flag files larger than this as notable

# macOS notification via osascript
def _notify(title: str, message: str) -> None:
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "{message}" with title "⚠️ CoworkGuard" subtitle "{title}"'
        ], timeout=3, capture_output=True)
    except Exception:
        pass


# ─────────────────────────────────────────────
# Model file discovery
# ─────────────────────────────────────────────

def _expand(path_str: str) -> Path:
    return Path(path_str).expanduser()


def _file_hash(path: Path) -> str:
    """SHA-256 of first 1MB — fast fingerprint without reading whole file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(1024 * 1024))
        return h.hexdigest()[:16]
    except Exception:
        return ""


def _file_size_mb(path: Path) -> float:
    try:
        return path.stat().st_size / (1024 * 1024)
    except Exception:
        return 0.0


def _scan_model_paths(actors: List[Actor]) -> List[Dict]:
    """
    Scan all model_paths from all actors and return found model files.
    Returns list of dicts with path, actor_id, size_mb, hash.
    """
    found = []
    seen_paths = set()

    for actor in actors:
        for pattern in actor.model_paths:
            # Handle glob patterns
            base = _expand(pattern)
            parent = base.parent
            glob_pattern = base.name

            # Walk up to find the first non-glob parent
            parts = str(parent).split("/")
            fixed_parts = []
            for part in parts:
                if "*" in part or "?" in part:
                    break
                fixed_parts.append(part)
            fixed_base = Path("/".join(fixed_parts)) if fixed_parts else Path("/")

            if not fixed_base.exists():
                continue

            # Use rglob for recursive patterns, glob for flat
            try:
                if "**" in pattern:
                    suffix = pattern.split("**")[-1].lstrip("/")
                    matches = list(fixed_base.rglob(suffix))
                else:
                    matches = list(fixed_base.glob("**/" + glob_pattern))
            except Exception:
                matches = []

            for match in matches:
                if not match.is_file():
                    continue
                if str(match) in seen_paths:
                    continue
                seen_paths.add(str(match))

                size_mb = _file_size_mb(match)
                # Skip numbered chunk files (-partial-0, -partial-1 etc) — tiny, not the model
                import re as _re
                if _re.search(r'-partial-\d+$', path.name):
                    continue
                # Skip other temp extensions
                if path.suffix in ('.part', '.tmp'):
                    continue
                # Files ending in -partial (no number) are the actual model blob downloading  # too small to be a model

                found.append({
                    "path": str(match),
                    "actor_id": actor.actor_id,
                    "actor_name": actor.display_name,
                    "size_mb": round(size_mb, 1),
                    "hash": _file_hash(match),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                })

    return found


# ─────────────────────────────────────────────
# State management
# ─────────────────────────────────────────────

def _load_state() -> Dict[str, Dict]:
    """Load previously seen model files."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_state(state: Dict[str, Dict]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ─────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────

def _write_log(event_type: str, actor_id: str, actor_name: str,
               path: str, size_mb: float, severity: str) -> None:
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "source": "model_monitor",
        "action": "FLAGGED",
        "blocked": False,
        "severity": severity,
        "actor_id": actor_id,
        "actor_name": actor_name,
        "path": path,
        "size_mb": size_mb,
        "finding_count": 1,
        "findings": [{
            "type": event_type,
            "severity": severity,
            "preview": f"{actor_name}: {Path(path).name} ({size_mb:.0f}MB)",
            "blocked": False,
        }],
    }
    with open(log_file, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


# ─────────────────────────────────────────────
# Event handling
# ─────────────────────────────────────────────

def _handle_downloading_model(actor_id: str, actor_name: str, path: str,
                               size_mb: float, prev_size_mb: float) -> None:
    """Fire when a model file is actively growing — download in progress."""
    log.info("LOCAL_MODEL_DOWNLOADING [%s] %s (%.1f MB, was %.1f MB)",
             actor_name, path, size_mb, prev_size_mb)
    _write_log("LOCAL_MODEL_DOWNLOADING", actor_id, actor_name, path, size_mb, "HIGH")
    size_str = f"{size_mb:.0f}MB" if size_mb < 1000 else f"{size_mb/1024:.1f}GB"
    _notify(
        title=f"{actor_name} is downloading an AI model",
        message=f"{size_str} downloaded so far. Open CoworkGuard to stop or allow.",
    )


def _handle_new_model(actor: Actor, path: str, size_mb: float,
                      registry: ActorRegistry) -> None:
    severity = registry.severity_for("LOCAL_MODEL_DOWNLOADED")
    size_str = f"{size_mb:.0f}MB" if size_mb < 1000 else f"{size_mb/1024:.1f}GB"

    # Use actor's own explanation
    explanation = actor.explanation_for("LOCAL_MODEL_DOWNLOADED")

    log.info("LOCAL_MODEL_DOWNLOADED [%s] %s (%s)", actor.display_name, path, size_str)

    # Write to audit log
    _write_log("LOCAL_MODEL_DOWNLOADED", actor.actor_id, actor.display_name,
               path, size_mb, severity)

    # Notify user — factual, not accusatory
    title = f"{actor.display_name} — local AI model enabled"
    message = f"{Path(path).name} ({size_str}). {explanation[:80]}"
    _notify(title, message)

    # Report to local server dashboard
    try:
        import urllib.request
        import json as _json
        payload = _json.dumps({
            "type": "LOCAL_MODEL_DOWNLOADED",
            "severity": severity,
            "action": "FLAGGED",
            "url": path,
            "actor_id": actor.actor_id,
            "actor_name": actor.display_name,
            "size_mb": size_mb,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": explanation,
        }).encode()
        req = urllib.request.Request(
            "http://localhost:7070/api/log-event",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass  # server not running — audit log is the fallback


def _handle_updated_model(actor: Actor, path: str, size_mb: float,
                           registry: ActorRegistry) -> None:
    severity = registry.severity_for("LOCAL_MODEL_UPDATED")
    log.info("LOCAL_MODEL_UPDATED [%s] %s", actor.display_name, path)
    _write_log("LOCAL_MODEL_UPDATED", actor.actor_id, actor.display_name,
               path, size_mb, severity)


def _handle_removed_model(actor_id: str, actor_name: str, path: str) -> None:
    log.info("LOCAL_MODEL_REMOVED [%s] %s", actor_name, path)
    _write_log("LOCAL_MODEL_REMOVED", actor_id, actor_name, path, 0.0, "LOW")


# ─────────────────────────────────────────────
# Main scan loop
# ─────────────────────────────────────────────

def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def run_once(registry: ActorRegistry, state: Dict[str, Dict]) -> Dict[str, Dict]:
    """
    Run one scan cycle. Returns updated state.
    """
    actors = [a for a in registry.all_actors() if a.model_paths]
    current = _scan_model_paths(actors)
    current_by_path = {m["path"]: m for m in current}

    # Find new and updated models
    for path, info in current_by_path.items():
        actor = registry.get_actor(info["actor_id"])
        if not actor:
            continue

        if path not in state:
            # New model
            _handle_new_model(actor, path, info["size_mb"], registry)
        elif state[path]["hash"] != info["hash"]:
            # Updated model
            _handle_updated_model(actor, path, info["size_mb"], registry)

    # Find removed models — skip partial files (Ollama cleanup)
    for path, info in state.items():
        if path not in current_by_path:
            import re as _re2
            if _re2.search(r'-partial-\d+$', path) or path.endswith(('.part', '.tmp', '.download')):
                continue
            _handle_removed_model(info["actor_id"], info["actor_name"], path)

    return current_by_path


def main() -> None:
    if sys.platform != "darwin":
        log.error("model_monitor requires macOS")
        sys.exit(0)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CoworkGuard ModelMonitor] %(message)s"
    )

    registry = ActorRegistry()
    log.info("Model monitor started — %d actors with model paths, polling every %ds",
             sum(1 for a in registry.all_actors() if a.model_paths), POLL_INTERVAL)

    state = _load_state()

    while True:
        try:
            settings = _load_settings()
            if settings.get("quiet_mode", False):
                time.sleep(POLL_INTERVAL)
                continue

            state = run_once(registry, state)
            _save_state(state)

        except Exception as e:
            log.error("Model monitor error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
