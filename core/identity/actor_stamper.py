"""
CoworkGuard Pro — Actor Stamper
© 2026 Katherine Weston. All rights reserved.

Joins proxy audit events to the actor identity registry.

Flow:
    proxy fires write_audit event (has source_port, no actor_id)
    → port_to_pid()  — lsof lookup, cached 5s (caution: lsof per-request is expensive)
    → pid_to_actor() — registry lookup
    → stamp_event()  — merges actor_id, session_id, confidence onto event

Confidence rules (strict — never say "confirmed" unless we have proof):
    strong  — same actor_id on both events (same bundle_id + pid + start_time)
    medium  — same session_id (same actor + active context)
    weak    — same app name within time window (existing free-tier behaviour)
    none    — no match possible

Only 'strong' confidence uses the word "confirmed" in UI copy.
'medium' → "likely", 'weak' → "possible".
"""

from __future__ import annotations

import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("coworkguard.actor_stamper")

# ─────────────────────────────────────────────
# Port → PID cache
# Caution: lsof per-request is expensive.
# Cache for 5 seconds — balances freshness vs performance.
# ─────────────────────────────────────────────

_PORT_CACHE: Dict[int, tuple[int, float]] = {}  # port → (pid, timestamp)
PORT_CACHE_TTL = 5.0  # seconds


def port_to_pid(port: int) -> Optional[int]:
    """
    Resolve a source port to a PID via lsof.
    Cached for PORT_CACHE_TTL seconds to avoid hammering lsof on every request.
    Returns None if no match found or lsof times out.
    """
    now = time.monotonic()

    # Return cached value if still fresh
    if port in _PORT_CACHE:
        pid, ts = _PORT_CACHE[port]
        if now - ts < PORT_CACHE_TTL:
            return pid
        else:
            del _PORT_CACHE[port]

    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t", "-sTCP:ESTABLISHED"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        pids = [p.strip() for p in result.stdout.strip().split() if p.strip().isdigit()]
        if not pids:
            # Try without state filter — catches connecting/listen states too
            result2 = subprocess.run(
                ["lsof", "-i", f":{port}", "-t"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            pids = [p.strip() for p in result2.stdout.strip().split() if p.strip().isdigit()]

        pid = int(pids[0]) if pids else None
        _PORT_CACHE[port] = (pid, now)
        return pid

    except subprocess.TimeoutExpired:
        log.warning("lsof timeout resolving port %s", port)
        return None
    except Exception as e:
        log.debug("port_to_pid(%s) error: %s", port, e)
        return None


def clear_port_cache() -> None:
    """Clear the port→PID cache. Called on actor registry refresh."""
    _PORT_CACHE.clear()


# ─────────────────────────────────────────────
# Actor registry (in-memory, updated by agent_guard)
# ─────────────────────────────────────────────

# Shape: { pid: { actor_id, bundle_id, process_name, display_name,
#                 process_start_time, session_id, active_window } }
_ACTOR_REGISTRY: Dict[int, Dict] = {}
_REGISTRY_UPDATED_AT: float = 0.0


def update_registry(actors: list[Dict]) -> None:
    """
    Replace the in-memory actor registry.
    Called by /api/actor-registry POST from agent_guard.
    """
    global _ACTOR_REGISTRY, _REGISTRY_UPDATED_AT
    _ACTOR_REGISTRY = {int(a["pid"]): a for a in actors if "pid" in a}
    _REGISTRY_UPDATED_AT = time.monotonic()
    clear_port_cache()  # stale port→PID mappings no longer valid
    log.debug("Actor registry updated: %d actors", len(_ACTOR_REGISTRY))


def get_registry() -> Dict[int, Dict]:
    return _ACTOR_REGISTRY


def pid_to_actor(pid: int) -> Optional[Dict]:
    """Look up actor metadata by PID. Returns None if not in registry."""
    return _ACTOR_REGISTRY.get(pid)


# ─────────────────────────────────────────────
# Event stamping
# ─────────────────────────────────────────────

def stamp_event(event: Dict, source_port: Optional[int] = None) -> Dict:
    """
    Stamp an audit event with actor identity fields.

    Tries:
      1. source_port → PID → actor_id (strong confidence)
      2. existing actor_name match in registry (weak confidence)

    Mutates and returns the event dict.
    Confidence is conservative — only 'strong' when we have proof.
    """
    # Already stamped upstream — don't overwrite
    if event.get("confidence") == "strong":
        return event

    pid = None

    # Path 1: source port lookup
    if source_port:
        pid = port_to_pid(source_port)

    # Path 2: pid already in event (actor_monitor events have it)
    if not pid and event.get("pid"):
        pid = int(event["pid"])

    if pid:
        actor = pid_to_actor(pid)
        if actor:
            event["actor_id"]       = actor.get("actor_id", "")
            event["bundle_id"]      = actor.get("bundle_id", "")
            event["pid"]            = pid
            event["process_name"]   = actor.get("process_name", "")
            event["display_name"]   = actor.get("display_name", actor.get("process_name", ""))
            event["session_id"]     = actor.get("session_id", "")
            event["confidence"]     = "strong"
            event["actor_stamped_at"] = datetime.now(timezone.utc).isoformat()
            log.debug(
                "Strong stamp: %s → actor_id=%s",
                event.get("type", "?"), event["actor_id"]
            )
            return event

    # Path 3: name-based weak match
    actor_name = event.get("actor_name") or event.get("ai_provider") or ""
    if actor_name:
        for _, actor in _ACTOR_REGISTRY.items():
            if (actor.get("display_name", "").lower() == actor_name.lower() or
                    actor.get("process_name", "").lower() == actor_name.lower()):
                event["actor_id"]   = actor.get("actor_id", "")
                event["bundle_id"]  = actor.get("bundle_id", "")
                event["session_id"] = actor.get("session_id", "")
                event["confidence"] = "weak"
                log.debug("Weak stamp (name match): %s", actor_name)
                return event

    # No match — mark explicitly so dashboard knows
    if "confidence" not in event:
        event["confidence"] = "none"

    return event


# ─────────────────────────────────────────────
# Confidence → UI copy
# Strict: only 'strong' uses "confirmed"
# ─────────────────────────────────────────────

CONFIDENCE_COPY = {
    "strong": {
        "badge":  "Confirmed sequence",
        "why":    (
            "CoworkGuard confirmed these events came from the same process. "
            "{display_name} (PID {pid}) {action_desc} {time_desc}."
        ),
    },
    "medium": {
        "badge":  "Likely sequence",
        "why":    (
            "CoworkGuard detected sensitive activity and an outbound connection "
            "from what appears to be the same session. The link is likely but not confirmed."
        ),
    },
    "weak": {
        "badge":  "Possible sequence",
        "why":    (
            "CoworkGuard saw private-app access and AI network activity close together, "
            "but could not confirm they came from the same actor. "
            "This may be unrelated activity."
        ),
    },
    "none": {
        "badge":  "Unlinked events",
        "why":    "CoworkGuard could not link these events to a specific actor.",
    },
}


def confidence_copy(confidence: str, **kwargs) -> Dict[str, str]:
    """
    Return badge text and 'why' explanation for a given confidence level.
    Formats the 'why' template with any provided kwargs.
    """
    entry = CONFIDENCE_COPY.get(confidence, CONFIDENCE_COPY["none"])
    try:
        why = entry["why"].format(**kwargs)
    except KeyError:
        why = entry["why"]
    return {"badge": entry["badge"], "why": why}
