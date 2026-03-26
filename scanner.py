"""
CoworkGuard - Core Scanner Engine
Detects PII, secrets, auth tokens, and internal URLs in outbound payloads.
Proprietary logic — © CoworkGuard
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

# ─────────────────────────────────────────────
# Detection Patterns
# ─────────────────────────────────────────────

PATTERNS = {
    # PII
    "SSN":              r"\b\d{3}-\d{2}-\d{4}\b",
    "EMAIL":            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE_US":         r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "DOB":              r"\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/\d{4}\b",
    "CREDIT_CARD":      r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "IP_ADDRESS":       r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "PASSPORT":         r"\b[A-Z]{1,2}[0-9]{6,9}\b",

    # Auth / Secrets
    "AWS_KEY":          r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GH_TOKEN":         r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}",
    "GOOGLE_API":       r"AIza[0-9A-Za-z\-_]{35}",
    "STRIPE_KEY":       r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}",
    "SLACK_TOKEN":      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "JWT":              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "PRIVATE_KEY":      r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "BEARER_TOKEN":     r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
    "BASIC_AUTH":       r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{10,}",
    "ANTHROPIC_KEY":    r"sk-ant-[a-zA-Z0-9\-_]{40,}",
    "OPENAI_KEY":       r"sk-[a-zA-Z0-9]{48}",

    # Internal / Corporate
    "INTERNAL_URL":     r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s]*",
    "VPN_HOSTNAME":     r"https?://[a-zA-Z0-9\-]+\.(?:internal|corp|intranet|local|lan)[^\s]*",
    "ENV_FILE":         r"(?i)(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|PRIVATE_KEY)\s*=\s*\S+",
    "CONNECTION_STR":   r"(?i)(mongodb|postgresql|mysql|redis|amqp)://[^\s\"']+",
}

# Severity levels per category
SEVERITY = {
    "SSN": "CRITICAL", "CREDIT_CARD": "CRITICAL", "PRIVATE_KEY": "CRITICAL",
    "AWS_KEY": "CRITICAL", "AWS_SECRET": "CRITICAL", "ANTHROPIC_KEY": "CRITICAL",
    "JWT": "HIGH", "BEARER_TOKEN": "HIGH", "GH_TOKEN": "HIGH",
    "STRIPE_KEY": "HIGH", "SLACK_TOKEN": "HIGH", "OPENAI_KEY": "HIGH",
    "CONNECTION_STR": "HIGH", "ENV_FILE": "HIGH",
    "EMAIL": "MEDIUM", "PHONE_US": "MEDIUM", "IP_ADDRESS": "MEDIUM",
    "INTERNAL_URL": "MEDIUM", "VPN_HOSTNAME": "MEDIUM",
    "DOB": "MEDIUM", "PASSPORT": "MEDIUM",
    "BASIC_AUTH": "HIGH", "GOOGLE_API": "HIGH",
}

# Domains considered sensitive — navigating here while Cowork is active triggers a warning
SENSITIVE_DOMAINS = [
    "console.aws.amazon.com", "app.datadoghq.com", "grafana.",
    "jenkins.", "gitlab.", "github.com", "bitbucket.",
    "jira.", "confluence.", "notion.so", "linear.app",
    "stripe.com/dashboard", "twilio.com/console",
    "mail.google.com", "outlook.live.com", "outlook.office",
    "payroll.", "hr.", "workday.com", "bamboohr.",
    "salesforce.com", "hubspot.com",
]


# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class Finding:
    pattern_name: str
    severity: str
    match_preview: str      # Redacted preview — never logs raw match
    char_position: int
    blocked: bool = False

@dataclass
class ScanResult:
    timestamp: str
    payload_hash: str       # Hash of payload, never raw content
    payload_size_bytes: int
    findings: List[Finding] = field(default_factory=list)
    blocked: bool = False
    action: str = "ALLOWED"

    @property
    def has_critical(self):
        return any(f.severity == "CRITICAL" for f in self.findings)

    @property
    def has_high(self):
        return any(f.severity == "HIGH" for f in self.findings)


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class CoworkScanner:
    """
    Scans text payloads for PII, secrets, and sensitive data.
    Never stores raw payload content — only hashes and redacted previews.
    """

    def __init__(self, block_on_critical=True, block_on_high=False):
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        self._compiled = {
            name: re.compile(pattern, re.IGNORECASE if name not in ("AWS_KEY", "GH_TOKEN", "JWT") else 0)
            for name, pattern in PATTERNS.items()
        }

    def _redact(self, match_str: str) -> str:
        """Returns a redacted preview — shows type/length but never raw value."""
        n = len(match_str)
        if n <= 6:
            return "*" * n
        return match_str[:2] + "*" * (n - 4) + match_str[-2:]

    def scan(self, text: str) -> ScanResult:
        findings = []

        for name, pattern in self._compiled.items():
            for match in pattern.finditer(text):
                findings.append(Finding(
                    pattern_name=name,
                    severity=SEVERITY.get(name, "LOW"),
                    match_preview=self._redact(match.group()),
                    char_position=match.start(),
                ))

        payload_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        result = ScanResult(
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload_hash=payload_hash,
            payload_size_bytes=len(text.encode("utf-8")),
            findings=findings,
        )

        should_block = (
            (self.block_on_critical and result.has_critical) or
            (self.block_on_high and result.has_high)
        )

        if should_block:
            result.blocked = True
            result.action = "BLOCKED"
            for f in findings:
                if f.severity in ("CRITICAL", "HIGH"):
                    f.blocked = True
        elif findings:
            result.action = "FLAGGED"

        return result

    def scan_json_payload(self, raw_body: bytes) -> ScanResult:
        """
        Extracts text content from an Anthropic API request body and scans it.
        Handles nested message arrays.
        """
        try:
            body = json.loads(raw_body)
        except Exception:
            return self.scan(raw_body.decode("utf-8", errors="replace"))

        # Extract all text content from messages
        text_parts = []
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_parts.append(block.get("text", ""))

        # Also check system prompt
        system = body.get("system", "")
        if isinstance(system, str):
            text_parts.append(system)
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict):
                    text_parts.append(block.get("text", ""))

        combined = "\n".join(text_parts)
        return self.scan(combined)

    def check_domain(self, url: str) -> Optional[str]:
        """Returns the matched sensitive domain name if URL is sensitive, else None."""
        for domain in SENSITIVE_DOMAINS:
            if domain in url:
                return domain
        return None


# ─────────────────────────────────────────────
# Quick self-test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    scanner = CoworkScanner(block_on_critical=True, block_on_high=True)

    test_payload = """
    Hi Claude, here's the context from my screen.
    User SSN: 123-45-6789
    Their email is john.smith@company-internal.corp
    AWS Key: AKIAIOSFODNN7EXAMPLE
    JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    Internal DB: postgresql://admin:supersecret@192.168.1.50:5432/proddb
    """

    result = scanner.scan(test_payload)
    print(f"\n{'='*50}")
    print(f"CoworkGuard Scan Result")
    print(f"{'='*50}")
    print(f"Action:   {result.action}")
    print(f"Blocked:  {result.blocked}")
    print(f"Findings: {len(result.findings)}")
    print(f"Hash:     {result.payload_hash}")
    print(f"\nFindings:")
    for f in result.findings:
        print(f"  [{f.severity:8}] {f.pattern_name:20} → {f.match_preview}")
        
#Copyright (c) 2026 [Katherine Weston]. All rights reserved.
#Licensed under MIT with Commons Clause — see LICENSE for details.
#Commercial use prohibited without a separate commercial license.