"""
CoworkGuard — Shared Scan Result Types
© 2026 Katherine Weston. All rights reserved.

Shared dataclasses used across all scanner modules:
  - scanner.py (SecretScanner)
  - mcp_trust/injection_scanner.py (PromptInjectionScanner)
  - mcp_trust/metadata_scanner.py (ToolMetadataScanner)
  - mcp_trust/unicode_scanner.py (UnicodeHiddenTextScanner)
  - mcp_trust/policy_engine.py (PolicyEngine)

Backwards compatible with the existing scanner.py ScanResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


# ─────────────────────────────────────────────
# Severity levels
# ─────────────────────────────────────────────

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

# ─────────────────────────────────────────────
# Policy actions
# ─────────────────────────────────────────────

ACTION_ALLOW       = "ALLOW"        # clean — pass through unchanged
ACTION_REDACT      = "REDACT"       # sensitive data stripped, clean version forwarded
ACTION_CONFIRM     = "CONFIRM"      # held — user must approve before forwarding
ACTION_QUARANTINE  = "QUARANTINE"   # held — requires admin review (Shield)
ACTION_BLOCK       = "BLOCK"        # dropped — safe error returned to LLM
ACTION_FLAGGED     = "FLAGGED"      # legacy — flagged but allowed through
ACTION_CLEAN       = "CLEAN"        # legacy — no findings

# ─────────────────────────────────────────────
# Reason codes
# ─────────────────────────────────────────────

REASON_INSTRUCTION_OVERRIDE    = "instruction_override"
REASON_TOOL_CHAINING           = "tool_chaining_request"
REASON_EXFILTRATION_ATTEMPT    = "exfiltration_attempt"
REASON_CREDENTIAL_LEAK         = "credential_leak"
REASON_PII_DETECTED            = "pii_detected"
REASON_HIDDEN_UNICODE          = "hidden_unicode"
REASON_TOOL_METADATA_CHANGED   = "tool_metadata_changed"
REASON_NEW_TOOL_SEEN           = "new_tool_seen"
REASON_TOOL_SCHEMA_CHANGED     = "tool_schema_changed"
REASON_PERMISSION_ESCALATION   = "permission_escalation"


# ─────────────────────────────────────────────
# Finding — a single detected issue
# Backwards compatible with scanner.py Finding
# ─────────────────────────────────────────────

@dataclass
class Finding:
    pattern_name: str           # human-readable pattern name e.g. "SSN", "INSTRUCTION_OVERRIDE"
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    match_preview: str          # redacted preview — never raw content
    line: Optional[int] = None  # line number if applicable
    blocked: bool = False       # whether this finding caused a block
    reason: Optional[str] = None  # reason code e.g. REASON_INSTRUCTION_OVERRIDE


# ─────────────────────────────────────────────
# ScanResult — result of scanning a single payload
# Extended from scanner.py ScanResult
# ─────────────────────────────────────────────

@dataclass
class ScanResult:
    # Core fields — backwards compatible with scanner.py
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload_hash: str = ""          # SHA-256 prefix of content — never raw
    payload_size_bytes: int = 0
    findings: List[Finding] = field(default_factory=list)
    blocked: bool = False
    action: str = ACTION_CLEAN

    # Extended fields for MCP trust gateway
    risk_score: float = 0.0         # 0.0 - 1.0 composite risk score
    reasons: List[str] = field(default_factory=list)  # reason codes
    recommended_action: str = ACTION_ALLOW
    redacted_output: Optional[str] = None  # output with sensitive content stripped
    scanner_name: Optional[str] = None     # which scanner produced this result
    tool_name: Optional[str] = None        # MCP tool name if applicable
    tool_server: Optional[str] = None      # MCP server URL if applicable

    # ── Convenience properties (backwards compatible) ──

    @property
    def has_critical(self) -> bool:
        return any(f.severity == SEVERITY_CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == SEVERITY_HIGH for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        """Serialise to dict for audit log / API response."""
        return {
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
            "payload_size_bytes": self.payload_size_bytes,
            "blocked": self.blocked,
            "action": self.action,
            "risk_score": round(self.risk_score, 3),
            "reasons": self.reasons,
            "recommended_action": self.recommended_action,
            "scanner_name": self.scanner_name,
            "tool_name": self.tool_name,
            "tool_server": self.tool_server,
            "finding_count": self.finding_count,
            "findings": [
                {
                    "pattern_name": f.pattern_name,
                    "severity": f.severity,
                    "preview": f.match_preview,
                    "blocked": f.blocked,
                    "reason": f.reason,
                    "line": f.line,
                }
                for f in self.findings
            ],
        }


# ─────────────────────────────────────────────
# MergedScanResult — combines results from
# multiple scanners into a single decision
# ─────────────────────────────────────────────

@dataclass
class MergedScanResult:
    """
    Combines results from multiple scanners (Secret, Injection,
    Metadata, Unicode) into a single policy decision.
    """
    results: List[ScanResult] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for r in self.results:
            findings.extend(r.findings)
        return findings

    @property
    def highest_severity(self) -> str:
        for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW):
            if any(f.severity == sev for f in self.all_findings):
                return sev
        return SEVERITY_LOW

    @property
    def max_risk_score(self) -> float:
        if not self.results:
            return 0.0
        return max(r.risk_score for r in self.results)

    @property
    def all_reasons(self) -> List[str]:
        reasons = []
        for r in self.results:
            reasons.extend(r.reasons)
        return list(set(reasons))

    @property
    def is_blocked(self) -> bool:
        return any(r.blocked for r in self.results)

    @property
    def recommended_action(self) -> str:
        """
        Returns the most restrictive recommended action
        across all scanner results.
        Priority: BLOCK > QUARANTINE > CONFIRM > REDACT > ALLOW
        """
        priority = [
            ACTION_BLOCK,
            ACTION_QUARANTINE,
            ACTION_CONFIRM,
            ACTION_REDACT,
            ACTION_ALLOW,
        ]
        actions = {r.recommended_action for r in self.results}
        for action in priority:
            if action in actions:
                return action
        return ACTION_ALLOW

    def to_dict(self) -> dict:
        return {
            "highest_severity": self.highest_severity,
            "max_risk_score": round(self.max_risk_score, 3),
            "recommended_action": self.recommended_action,
            "all_reasons": self.all_reasons,
            "is_blocked": self.is_blocked,
            "finding_count": len(self.all_findings),
            "scanner_results": [r.to_dict() for r in self.results],
        }
