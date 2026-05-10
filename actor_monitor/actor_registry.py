"""
CoworkGuard AI Actor Monitor — Actor Registry
© 2026 Katherine Weston. All rights reserved.

Loads actors.json and matches running processes to known AI actor profiles.
Used by agent_guard.py to identify what AI is running on the machine.

Usage:
    from actor_monitor.actor_registry import ActorRegistry

    registry = ActorRegistry()
    actor = registry.match_process(pid=1234, name="Claude", bundle_id="com.anthropic.claudefordesktop")
    if actor:
        print(actor.display_name, actor.capabilities)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("coworkguard.actor_registry")

ACTORS_FILE = Path(__file__).parent / "actors.json"


# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class DetectionMethod:
    method: str
    status: str          # shipped / partial / planned
    note: str = ""


@dataclass
class FalsePositiveControls:
    allow_silence: bool = True
    allow_always_allow: bool = True
    cooldown_seconds: int = 300


@dataclass
class ConsentRequired:
    visibility: bool = False
    enforcement: bool = True


@dataclass
class Actor:
    actor_id: str
    display_name: str
    bundle_ids: List[str]
    process_names: List[str]
    requires_parent_match: bool
    parent_process: List[str]           # actor_ids of known parents
    watch_paths: List[str]
    model_paths: List[str]
    capabilities: List[str]
    risk_events: List[str]
    default_policy: Dict[str, str]      # event -> action (notify/ask/block/critical)
    consent_required: ConsentRequired
    false_positive_controls: FalsePositiveControls
    explanations: Dict[str, str]        # event -> plain English explanation
    detection_notes: Dict[str, str]     # event -> implementation notes
    enabled: bool = True
    notes: str = ""

    def policy_for(self, event: str) -> str:
        """
        Return the policy action for a given event. Defaults to 'notify'.
        Keys in default_policy are SCREAMING_SNAKE_CASE matching risk_events exactly.
        Falls back to lowercase lookup for backwards compatibility.
        """
        if event in self.default_policy:
            return self.default_policy[event]
        # fallback: try lowercase capability-style key
        lower = event.lower()
        if lower in self.default_policy:
            return self.default_policy[lower]
        return "notify"

    def explanation_for(self, event: str, actor: str = "", target: str = "", seconds: int = 0) -> str:
        """Return plain English explanation for an event, with template substitution."""
        template = self.explanations.get(event, f"{self.display_name}: {event}")
        return (template
                .replace("{actor}", actor or self.display_name)
                .replace("{target}", target)
                .replace("{seconds}", str(seconds)))


@dataclass
class SensitiveBundle:
    bundle_id: str
    display_name: str
    risk: str           # CRITICAL / HIGH / MEDIUM / LOW


# ─────────────────────────────────────────────
# Actor Registry
# ─────────────────────────────────────────────

class ActorRegistry:
    """
    Loads actors.json and provides process matching.

    Matching priority:
      1. Exact bundle_id match
      2. Exact process_name match (case-insensitive)
      3. Partial process_name match (for helpers e.g. "Claude Helper")
      4. Parent process match for python_mcp / node_mcp
    """

    def __init__(self, actors_file: Path = ACTORS_FILE):
        self._actors: Dict[str, Actor] = {}
        self._sensitive_bundles: Dict[str, SensitiveBundle] = {}
        self._detection_methods: Dict[str, DetectionMethod] = {}
        self._event_severity: Dict[str, str] = {}
        self._notification_templates: Dict[str, str] = {}
        self._policy_modes: Dict[str, dict] = {}
        self._policy_precedence: str = ""
        self._load(actors_file)

    def _load(self, path: Path) -> None:
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            log.error("actors.json not found at %s", path)
            return
        except json.JSONDecodeError as e:
            log.error("actors.json parse error: %s", e)
            return

        self._event_severity = data.get("event_severity", {})
        self._notification_templates = data.get("notification_templates", {})
        self._policy_modes = data.get("policy_modes", {})
        self._policy_precedence = data.get("_policy_precedence", "")

        # Load detection methods
        for cap, details in data.get("detection_methods", {}).items():
            if isinstance(details, dict):
                self._detection_methods[cap] = DetectionMethod(
                    method=details.get("method", cap),
                    status=details.get("status", "unknown"),
                    note=details.get("note", ""),
                )

        # Load actors
        for entry in data.get("actors", []):
            if not entry.get("enabled", True):
                continue
            fp = entry.get("false_positive_controls", {})
            cr = entry.get("consent_required", {})
            actor = Actor(
                actor_id=entry["actor_id"],
                display_name=entry["display_name"],
                bundle_ids=[b.lower() for b in entry.get("bundle_ids", [])],
                process_names=[p.lower() for p in entry.get("process_names", [])],
                requires_parent_match=entry.get("requires_parent_match", False),
                parent_process=entry.get("parent_process", []),
                watch_paths=entry.get("watch_paths", []),
                model_paths=entry.get("model_paths", []),
                capabilities=entry.get("capabilities", []),
                risk_events=entry.get("risk_events", []),
                default_policy=entry.get("default_policy", {}),
                consent_required=ConsentRequired(
                    visibility=cr.get("visibility", False),
                    enforcement=cr.get("enforcement", True),
                ),
                false_positive_controls=FalsePositiveControls(
                    allow_silence=fp.get("allow_silence", True),
                    allow_always_allow=fp.get("allow_always_allow", True),
                    cooldown_seconds=fp.get("cooldown_seconds", 300),
                ),
                explanations=entry.get("explanations", {}),
                detection_notes=entry.get("detection_notes", {}),
                enabled=entry.get("enabled", True),
                notes=entry.get("notes", ""),
            )
            self._actors[actor.actor_id] = actor

        # Load sensitive bundles
        for entry in data.get("sensitive_bundles", []):
            sb = SensitiveBundle(
                bundle_id=entry["bundle_id"].lower(),
                display_name=entry["display_name"],
                risk=entry["risk"],
            )
            self._sensitive_bundles[sb.bundle_id] = sb

        log.info(
            "ActorRegistry loaded: %d actors, %d sensitive bundles",
            len(self._actors), len(self._sensitive_bundles)
        )

    def reload(self) -> None:
        """Reload actors.json at runtime — picks up user edits without restart."""
        self._actors.clear()
        self._sensitive_bundles.clear()
        self._detection_methods.clear()
        self._event_severity.clear()
        self._notification_templates.clear()
        self._load(ACTORS_FILE)
        log.info("ActorRegistry reloaded")

    # ── Process matching ──

    def match_process(
        self,
        name: str,
        bundle_id: Optional[str] = None,
        parent_actor_id: Optional[str] = None,
    ) -> Optional[Actor]:
        """
        Match a running process to a known AI actor.

        Args:
            name: Process name (e.g. "Claude", "python3")
            bundle_id: macOS bundle ID if available
            parent_actor_id: actor_id of the parent process if known

        Returns:
            Matched Actor or None
        """
        name_lower = name.lower()
        bid_lower = (bundle_id or "").lower()

        # 1. Exact bundle_id match (most reliable)
        if bid_lower:
            for actor in self._actors.values():
                if bid_lower in actor.bundle_ids:
                    return actor

        # 2. Exact process_name match
        for actor in self._actors.values():
            if actor.requires_parent_match:
                continue   # handled separately below
            if name_lower in actor.process_names:
                return actor

        # 3. Partial process_name match (for helpers)
        for actor in self._actors.values():
            if actor.requires_parent_match:
                continue
            for pname in actor.process_names:
                if pname in name_lower:  # helper suffix only e.g. "claude helper" matches "claude"
                    return actor

        # 4. Parent-matched actors (python_mcp, node_mcp)
        if parent_actor_id:
            for actor in self._actors.values():
                if not actor.requires_parent_match:
                    continue
                if name_lower in actor.process_names:
                    if parent_actor_id in actor.parent_process:
                        return actor

        return None

    def match_bundle(self, bundle_id: str) -> Optional[Actor]:
        """Match by bundle_id only — for app launch detection."""
        bid = bundle_id.lower()
        for actor in self._actors.values():
            if bid in actor.bundle_ids:
                return actor
        return None

    # ── Sensitive bundle lookup ──

    def is_sensitive_bundle(self, bundle_id: str) -> Optional[SensitiveBundle]:
        """Return SensitiveBundle if bundle_id is in the sensitive list."""
        return self._sensitive_bundles.get(bundle_id.lower())

    def sensitive_bundle_by_name(self, name: str) -> Optional[SensitiveBundle]:
        """Return SensitiveBundle by display name (case-insensitive)."""
        name_lower = name.lower()
        for sb in self._sensitive_bundles.values():
            if sb.display_name.lower() == name_lower:
                return sb
        return None

    # ── Policy helpers ──

    def severity_for(self, event: str) -> str:
        """Return severity for a given event type. Defaults to MEDIUM."""
        return self._event_severity.get(event, "MEDIUM")

    def notification_text(self, event: str, actor_name: str = "",
                           target: str = "", seconds: int = 0, detail: str = "") -> str:
        """Return formatted notification text for an event."""
        template = self._notification_templates.get(event, f"{actor_name}: {event}")
        return (template
                .replace("{actor}", actor_name)
                .replace("{target}", target)
                .replace("{seconds}", str(seconds))
                .replace("{detail}", detail))

    def detection_status(self, capability: str) -> str:
        """Return detection status for a capability: shipped/partial/planned."""
        dm = self._detection_methods.get(capability)
        return dm.status if dm else "unknown"

    # ── Introspection ──

    def all_actors(self) -> List[Actor]:
        return list(self._actors.values())

    def get_actor(self, actor_id: str) -> Optional[Actor]:
        return self._actors.get(actor_id)

    def actor_count(self) -> int:
        return len(self._actors)

    def sensitive_bundle_count(self) -> int:
        return len(self._sensitive_bundles)


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    registry = ActorRegistry()

    print(f"\nLoaded {registry.actor_count()} actors, "
          f"{registry.sensitive_bundle_count()} sensitive bundles\n")

    tests = [
        ("Claude", "com.anthropic.claudefordesktop", None),
        ("Cursor Helper", None, None),
        ("Google Chrome", "com.google.Chrome", None),
        ("python3", None, "claude_desktop"),
        ("python3", None, None),             # no parent — should NOT match python_mcp
        ("node", None, "cursor"),
        ("Raycast", "com.raycast.macos", None),
        ("Ollama", "ai.ollama.ollama", None),
        ("unknownapp", None, None),           # no match
    ]

    for name, bundle_id, parent in tests:
        actor = registry.match_process(name, bundle_id, parent)
        if actor:
            severity = registry.severity_for("NETWORK_AFTER_SENSITIVE_ACCESS")
            print(f"  {name:25} -> {actor.display_name:20} "
                  f"| capabilities: {', '.join(actor.capabilities[:2])}")
        else:
            print(f"  {name:25} -> no match")

    print("\nSensitive bundle check:")
    for bid in ["com.1password.1password", "com.apple.mail", "com.google.Chrome", "com.unknown.app"]:
        sb = registry.is_sensitive_bundle(bid)
        print(f"  {bid:40} -> {sb.display_name + ' (' + sb.risk + ')' if sb else 'not sensitive'}")

    print("\nDetection status (by capability name):")
    for cap in ["local_model_downloads", "accessibility_access", "network_access", "mcp_config_changed"]:
        dm = registry._detection_methods.get(cap)
        if dm:
            note = f" [{dm.note[:40]}...]" if dm.note else ""
            print(f"  {cap:30} -> {dm.status:10}{note}")
        else:
            print(f"  {cap:30} -> not found")
