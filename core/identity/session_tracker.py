"""
CoworkGuard Pro — Session Tracker
© 2026 Katherine Weston. All rights reserved.

Builds and maintains session_id for each active actor.

session_id = actor_id + active_context
    e.g. com.anthropic.claude:12345:1716150000:window-Messages

Active context sources (in priority order):
    1. Active window title (via macOS Accessibility API / AppleScript)
    2. Active browser tab origin
    3. Working directory (for terminal-based agents)
    4. Fallback: actor_id only

Session IDs expire after IDLE_TIMEOUT seconds of no activity.
"""

from __future__ import annotations

import logging
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Optional

log = logging.getLogger("coworkguard.session_tracker")

IDLE_TIMEOUT = 300  # seconds — session expires after 5 minutes idle


# ─────────────────────────────────────────────
# Session registry
# ─────────────────────────────────────────────

# Shape: { actor_id: { session_id, context, last_active, pid } }
_SESSIONS: Dict[str, Dict] = {}


def update_session(actor_id: str, pid: int, context: Optional[str] = None) -> str:
    """
    Update or create a session for an actor.
    Returns the current session_id.
    """
    now = time.monotonic()
    existing = _SESSIONS.get(actor_id)

    # Build context string
    if not context:
        context = _get_active_context(pid)

    session_id = f"{actor_id}:{context}" if context else actor_id

    _SESSIONS[actor_id] = {
        "session_id":   session_id,
        "actor_id":     actor_id,
        "pid":          pid,
        "context":      context or "",
        "last_active":  now,
        "started_at":   existing["started_at"] if existing else datetime.now(timezone.utc).isoformat(),
    }

    return session_id


def get_session(actor_id: str) -> Optional[Dict]:
    """Get current session for an actor. Returns None if expired."""
    session = _SESSIONS.get(actor_id)
    if not session:
        return None
    now = time.monotonic()
    if now - session["last_active"] > IDLE_TIMEOUT:
        del _SESSIONS[actor_id]
        return None
    return session


def get_session_id(actor_id: str) -> Optional[str]:
    """Convenience — returns just the session_id string."""
    session = get_session(actor_id)
    return session["session_id"] if session else None


def all_sessions() -> Dict[str, Dict]:
    """Return all active (non-expired) sessions."""
    now = time.monotonic()
    return {
        k: v for k, v in _SESSIONS.items()
        if now - v["last_active"] <= IDLE_TIMEOUT
    }


def expire_sessions() -> int:
    """Remove expired sessions. Returns count removed."""
    now = time.monotonic()
    expired = [k for k, v in _SESSIONS.items() if now - v["last_active"] > IDLE_TIMEOUT]
    for k in expired:
        del _SESSIONS[k]
    return len(expired)


# ─────────────────────────────────────────────
# Active context detection
# ─────────────────────────────────────────────

def _get_active_context(pid: int) -> Optional[str]:
    """
    Try to determine the active context for a process.
    Returns a short string suitable for inclusion in session_id.
    Returns None if context can't be determined.
    """
    # Try to get active window title for this PID via AppleScript
    try:
        script = f'''
        tell application "System Events"
            set proc to first process whose unix id is {pid}
            set win to first window of proc
            return name of win
        end tell
        '''
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            # Sanitise — remove chars not valid in session_id
            raw = result.stdout.strip()
            sanitised = "".join(c if c.isalnum() or c in "-_ " else "" for c in raw)
            sanitised = sanitised.strip().replace(" ", "-")[:40]
            if sanitised:
                return f"window-{sanitised}"
    except Exception:
        pass

    return None


def build_actor_registry_payload(running_actors: list[Dict]) -> list[Dict]:
    """
    Enrich actor list from agent_guard with session_ids before
    pushing to server.py /api/actor-registry.

    running_actors: list of dicts with at least pid, actor_id, bundle_id,
                    process_name, display_name, process_start_time
    """
    enriched = []
    for actor in running_actors:
        actor_id = actor.get("actor_id", "")
        pid = actor.get("pid")
        if not actor_id or not pid:
            enriched.append(actor)
            continue

        session_id = update_session(actor_id, int(pid))
        enriched.append({
            **actor,
            "session_id": session_id,
        })
    return enriched
