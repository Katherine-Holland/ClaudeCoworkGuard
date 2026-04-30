"""
CoworkGuard MCP Trust Gateway — Tool Metadata Scanner
© 2026 Katherine Weston. All rights reserved.

Detects tool poisoning via metadata changes. Pins tool descriptions,
schemas and permissions on first sight. Alerts if they change.

Attack vectors detected:
  - Tool description changed after approval ("rug pull")
  - Schema parameters added or removed
  - Tool name changed
  - New tool seen for first time (quarantine pending review)
  - Permission scope escalation

Reference:
  Microsoft MCP security guidance — tool poisoning via malicious
  tool metadata and rug-pull changes after initial approval.

Usage:
    from mcp_trust.metadata_scanner import ToolMetadataScanner

    scanner = ToolMetadataScanner()
    result = scanner.scan(tool_name, description, schema)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .result import (
    ScanResult, Finding,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    ACTION_BLOCK, ACTION_CONFIRM, ACTION_QUARANTINE, ACTION_ALLOW,
    REASON_TOOL_METADATA_CHANGED, REASON_NEW_TOOL_SEEN,
    REASON_TOOL_SCHEMA_CHANGED, REASON_PERMISSION_ESCALATION,
)


# ─────────────────────────────────────────────
# Registry storage
# ─────────────────────────────────────────────

REGISTRY_PATH = Path.home() / ".coworkguard" / "tool_registry.json"


def _load_registry() -> Dict[str, Any]:
    if REGISTRY_PATH.exists():
        try:
            with open(REGISTRY_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_registry(registry: Dict[str, Any]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def _hash_metadata(description: str, schema: Optional[dict]) -> str:
    """Hash tool description + schema for change detection."""
    content = json.dumps({
        "description": description or "",
        "schema": schema or {},
    }, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def _schema_params(schema: Optional[dict]) -> set:
    """Extract parameter names from a tool schema."""
    if not schema:
        return set()
    props = schema.get("properties") or schema.get("parameters", {}).get("properties", {})
    return set(props.keys()) if isinstance(props, dict) else set()


def _has_dangerous_permissions(schema: Optional[dict]) -> list:
    """Check for dangerous permission patterns in schema."""
    if not schema:
        return []
    schema_str = json.dumps(schema).lower()
    dangerous = []
    checks = [
        ("full_filesystem", ["filesystem", "full_access", "all_files", "/*", "~/*"]),
        ("shell_access", ["shell", "exec", "subprocess", "command", "bash", "sh"]),
        ("network_unrestricted", ["any_url", "all_domains", "unrestricted_network"]),
        ("credential_access", ["keychain", "password", "credentials", ".ssh", ".aws"]),
    ]
    for name, keywords in checks:
        if any(kw in schema_str for kw in keywords):
            dangerous.append(name)
    return dangerous


# ─────────────────────────────────────────────
# ToolMetadataScanner
# ─────────────────────────────────────────────

class ToolMetadataScanner:
    """
    Pins tool metadata on first registration and alerts on changes.

    First time a tool is seen:
      - Store hash of description + schema
      - Return QUARANTINE — new tool requires review

    Subsequent calls:
      - Compare hash against stored value
      - If changed → BLOCK (potential rug pull)
      - If schema params changed → CONFIRM
      - If dangerous permissions detected → CONFIRM
    """

    def __init__(self, registry_path: Optional[Path] = None):
        self._registry_path = registry_path or REGISTRY_PATH
        self._registry = _load_registry()

    def _save(self) -> None:
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(self._registry_path, "w") as f:
            json.dump(self._registry, f, indent=2)

    def scan(
        self,
        tool_name: str,
        description: str = "",
        schema: Optional[dict] = None,
        tool_server: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan tool metadata for changes or dangerous patterns.

        Args:
            tool_name: MCP tool name
            description: Tool description string
            schema: Tool input schema (JSON schema dict)
            tool_server: MCP server URL

        Returns:
            ScanResult — QUARANTINE for new tools, BLOCK for changed metadata
        """
        findings = []
        reasons = []
        current_hash = _hash_metadata(description, schema)
        current_params = _schema_params(schema)
        registry_key = f"{tool_server or 'local'}::{tool_name}"

        stored = self._registry.get(registry_key)

        if stored is None:
            # ── New tool — never seen before ──
            self._registry[registry_key] = {
                "tool_name": tool_name,
                "tool_server": tool_server,
                "description_preview": (description or "")[:100],
                "metadata_hash": current_hash,
                "schema_params": list(current_params),
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "approved": False,
            }
            self._save()

            findings.append(Finding(
                pattern_name="NEW_TOOL_SEEN",
                severity=SEVERITY_HIGH,
                match_preview=f"{tool_name[:40]} — new, not yet approved",
                reason=REASON_NEW_TOOL_SEEN,
            ))
            reasons.append(REASON_NEW_TOOL_SEEN)

            return ScanResult(
                payload_hash=current_hash[:16],
                payload_size_bytes=len(json.dumps(schema or {}).encode()),
                findings=findings,
                blocked=False,
                action=ACTION_QUARANTINE,
                risk_score=0.5,
                reasons=reasons,
                recommended_action=ACTION_QUARANTINE,
                scanner_name="ToolMetadataScanner",
                tool_name=tool_name,
                tool_server=tool_server,
            )

        # ── Known tool — check for changes ──
        stored_hash = stored.get("metadata_hash", "")
        stored_params = set(stored.get("schema_params", []))

        # Update last seen
        self._registry[registry_key]["last_seen"] = datetime.now(timezone.utc).isoformat()
        self._save()

        blocked = False
        recommended = ACTION_ALLOW

        # Check metadata hash changed
        if current_hash != stored_hash:
            findings.append(Finding(
                pattern_name="TOOL_METADATA_CHANGED",
                severity=SEVERITY_CRITICAL,
                match_preview=f"{tool_name[:40]} — description or schema changed",
                reason=REASON_TOOL_METADATA_CHANGED,
                blocked=True,
            ))
            reasons.append(REASON_TOOL_METADATA_CHANGED)
            blocked = True
            recommended = ACTION_BLOCK

        # Check schema params changed
        if current_params != stored_params:
            added = current_params - stored_params
            removed = stored_params - current_params
            preview = []
            if added:
                preview.append(f"added: {', '.join(sorted(added)[:3])}")
            if removed:
                preview.append(f"removed: {', '.join(sorted(removed)[:3])}")
            findings.append(Finding(
                pattern_name="TOOL_SCHEMA_CHANGED",
                severity=SEVERITY_HIGH,
                match_preview=f"{tool_name[:30]} — {'; '.join(preview)}",
                reason=REASON_TOOL_SCHEMA_CHANGED,
            ))
            reasons.append(REASON_TOOL_SCHEMA_CHANGED)
            if not blocked:
                recommended = ACTION_CONFIRM

        # Check dangerous permissions
        dangerous = _has_dangerous_permissions(schema)
        if dangerous:
            findings.append(Finding(
                pattern_name="DANGEROUS_PERMISSIONS",
                severity=SEVERITY_HIGH,
                match_preview=f"permissions: {', '.join(dangerous[:3])}",
                reason=REASON_PERMISSION_ESCALATION,
            ))
            reasons.append(REASON_PERMISSION_ESCALATION)
            if not blocked and recommended == ACTION_ALLOW:
                recommended = ACTION_CONFIRM

        action = ACTION_BLOCK if blocked else (ACTION_CONFIRM if findings else ACTION_ALLOW)
        risk_score = 1.0 if blocked else (0.6 if findings else 0.0)

        return ScanResult(
            payload_hash=current_hash[:16],
            payload_size_bytes=len(json.dumps(schema or {}).encode()),
            findings=findings,
            blocked=blocked,
            action=action,
            risk_score=risk_score,
            reasons=reasons,
            recommended_action=recommended,
            scanner_name="ToolMetadataScanner",
            tool_name=tool_name,
            tool_server=tool_server,
        )

    def approve_tool(self, tool_name: str, tool_server: Optional[str] = None) -> bool:
        """Mark a tool as approved after user review."""
        registry_key = f"{tool_server or 'local'}::{tool_name}"
        if registry_key in self._registry:
            self._registry[registry_key]["approved"] = True
            self._registry[registry_key]["approved_at"] = datetime.now(timezone.utc).isoformat()
            self._save()
            return True
        return False

    def update_baseline(self, tool_name: str, description: str = "",
                        schema: Optional[dict] = None,
                        tool_server: Optional[str] = None) -> None:
        """Update stored baseline after user approves a metadata change."""
        registry_key = f"{tool_server or 'local'}::{tool_name}"
        if registry_key in self._registry:
            self._registry[registry_key]["metadata_hash"] = _hash_metadata(description, schema)
            self._registry[registry_key]["schema_params"] = list(_schema_params(schema))
            self._registry[registry_key]["description_preview"] = (description or "")[:100]
            self._registry[registry_key]["approved"] = True
            self._save()

    def get_registry(self) -> dict:
        """Return full tool registry for dashboard display."""
        return dict(self._registry)


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile
    import os

    # Use temp registry so we don't pollute real one
    tmp = tempfile.mktemp(suffix=".json")

    scanner = ToolMetadataScanner(registry_path=Path(tmp))

    schema_v1 = {
        "properties": {
            "path": {"type": "string", "description": "File path"}
        }
    }

    schema_v2 = {
        "properties": {
            "path": {"type": "string"},
            "recursive": {"type": "boolean"},  # new param added
        }
    }

    schema_dangerous = {
        "properties": {
            "path": {"type": "string", "description": "any path including ~/.ssh"}
        }
    }

    tests = [
        ("First sight — new tool", "read_file", "Reads a file", schema_v1),
        ("Same tool — no changes", "read_file", "Reads a file", schema_v1),
        ("Schema changed — param added", "read_file", "Reads a file", schema_v2),
        ("Description changed — rug pull", "read_file", "Reads ANY file including credentials", schema_v2),
        ("New tool with dangerous permissions", "shell_exec", "Runs shell commands ~/.ssh access", schema_dangerous),
    ]

    for label, name, desc, schema in tests:
        result = scanner.scan(name, desc, schema, tool_server="test-server")
        print(f"\n{label}")
        print(f"  Action:     {result.action}")
        print(f"  Risk score: {result.risk_score}")
        print(f"  Findings:   {result.finding_count}")
        for f in result.findings:
            print(f"  [{f.severity:8}] {f.pattern_name} — {f.match_preview}")

    os.unlink(tmp)
