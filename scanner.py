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
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────
# Sensitive domains — loaded from shared domains.json
# Same list is used by the Chrome extension (background.js)
# Edit domains.json to add custom domains — both layers update automatically
# ─────────────────────────────────────────────
def _load_domains():
    domains_file = Path(__file__).parent / "domains.json"
    if domains_file.exists():
        try:
            with open(domains_file) as f:
                return json.load(f).get("sensitive_domains", [])
        except Exception:
            pass
    # Fallback if file missing
    return [
        "console.aws.amazon.com", "app.datadoghq.com", "grafana.",
        "jenkins.", "gitlab.", "github.com", "bitbucket.",
        "jira.", "confluence.", "notion.so", "linear.app",
        "stripe.com/dashboard", "twilio.com/console",
        "mail.google.com", "outlook.live.com", "outlook.office",
        "payroll.", "hr.", "workday.com", "bamboohr.",
        "salesforce.com", "hubspot.com",
    ]

SENSITIVE_DOMAINS = _load_domains()

# ─────────────────────────────────────────────
# Detection Patterns
# ─────────────────────────────────────────────

PATTERNS = {
    # ── PII ──────────────────────────────────────────────────────────────
    "SSN":              r"\b\d{3}-\d{2}-\d{4}\b",
    "EMAIL":            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE_US":         r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "DOB":              r"\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/\d{4}\b",
    "CREDIT_CARD":      r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "IP_ADDRESS":       r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    # Passport — requires document/travel context nearby to reduce false positives
    # on product codes, order IDs etc. that match the raw character class
    "PASSPORT":         r"(?i)(?:passport|travel\s*doc(?:ument)?|pass(?:port)?\s*(?:no|num|number|#)?)\s*(?:is|:|\s)\s*[A-Z]{1,2}[0-9]{6,9}\b",

    # ── Cloud provider credentials ────────────────────────────────────────
    "AWS_KEY":          r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    # GCP — note: this pattern can fire on documentation/examples containing
    # "service_account" — consider the false positive risk in your environment.
    # The pattern is intentionally broad because a real GCP key in a payload
    # is always CRITICAL. Custom patterns can be used to refine if needed.
    "GCP_SERVICE_ACCT": r'"type":\s*"service_account"',
    "AZURE_CONN_STR":   r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",

    # ── Keys / Certs ──────────────────────────────────────────────────────
    "PRIVATE_KEY":      r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "CERTIFICATE":      r"-----BEGIN CERTIFICATE-----",

    # ── Auth tokens ───────────────────────────────────────────────────────
    "JWT":              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "BEARER_TOKEN":     r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
    "BASIC_AUTH":       r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{10,}",
    "OAUTH_TOKEN":      r"(?i)(access_token|refresh_token|oauth_token)\s*[=:]\s*['\"]?[a-zA-Z0-9\-._~+/]{20,}['\"]?",

    # ── AI / LLM provider keys ────────────────────────────────────────────
    # Anthropic
    "ANTHROPIC_KEY":    r"sk-ant-[a-zA-Z0-9\-_]{40,}",
    # OpenAI — legacy (sk-), project (sk-proj-), user (sk-None-), service account (sk-svcacct-)
    "OPENAI_KEY":       r"sk-(?:proj|None|svcacct)-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{48}",
    # Google AI / Gemini
    "GOOGLE_API":       r"AIza[0-9A-Za-z\-_]{35}",
    # Hugging Face — user tokens (hf_) and fine-grained org tokens (api_org_)
    "HUGGINGFACE_KEY":  r"hf_[a-zA-Z0-9]{34,}|api_org_[a-zA-Z0-9]{34,}",
    # Cohere — avoid lookahead ReDoS, match on context keyword instead
    "COHERE_KEY":       r"(?i)cohere[_\-\s]*(?:api[_\-\s]*)?key[_\-\s]*[=:]\s*[a-zA-Z0-9]{32,}|co-[a-zA-Z0-9\-]{30,}",
    # Mistral
    "MISTRAL_KEY":      r"(?i)mistral.{0,10}['\"][a-zA-Z0-9]{32,}['\"]",
    # Groq
    "GROQ_KEY":         r"gsk_[a-zA-Z0-9]{52}",
    # xAI / Grok
    "XAI_KEY":          r"xai-[a-zA-Z0-9]{40,}",
    # Replicate
    "REPLICATE_KEY":    r"r8_[a-zA-Z0-9]{40}",
    # Perplexity
    "PERPLEXITY_KEY":   r"pplx-[a-zA-Z0-9]{48}",

    # ── SaaS / Developer platform keys ───────────────────────────────────
    "STRIPE_KEY":       r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}",
    "STRIPE_WEBHOOK":   r"whsec_[a-zA-Z0-9]{32,}",
    "SLACK_TOKEN":      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "SLACK_WEBHOOK":    r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "GH_TOKEN":         r"ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|ghs_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82,}",
    "GITLAB_TOKEN":     r"glpat-[a-zA-Z0-9\-_]{20}",
    "TWILIO_KEY":       r"SK[a-zA-Z0-9]{32}",
    "TWILIO_TOKEN":     r"(?i)twilio.{0,20}['\"][a-zA-Z0-9]{32}['\"]",
    "SENDGRID_KEY":     r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
    "MAILGUN_KEY":      r"key-[a-zA-Z0-9]{32}",
    "NPM_TOKEN":        r"npm_[a-zA-Z0-9]{36}",
    "VERCEL_TOKEN":     r"(?i)vercel.{0,10}['\"][a-zA-Z0-9]{24}['\"]",
    "NETLIFY_TOKEN":    r"(?i)netlify.{0,10}['\"][a-zA-Z0-9\-_]{40,}['\"]",
    "FIREBASE_KEY":     r"AAAA[a-zA-Z0-9_\-]{7}:[a-zA-Z0-9_\-]{140}",
    "SUPABASE_KEY":     r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "DATADOG_KEY":      r"(?i)dd.{0,10}(api|app).{0,5}key.{0,5}['\"][a-zA-Z0-9]{40}['\"]",

    # ── Internal / Corporate ──────────────────────────────────────────────
    "INTERNAL_URL":     r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s]*",
    "VPN_HOSTNAME":     r"https?://[a-zA-Z0-9\-]+\.(?:internal|corp|intranet|local|lan)[^\s]*",
    "ENV_FILE":         r"(?i)(DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*\S+",
    "CONNECTION_STR":   r"(?i)(mongodb(\+srv)?|postgresql|mysql|redis|amqp|mssql|sqlite)://[^\s\"']+",
    # MCP config credential exposure (supply chain attack vector)
    "MCP_CREDENTIAL":   r'"env"\s*:\s*\{[^}]*"[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*"\s*:\s*"[^"]{8,}"',
}

# ── Severity levels ───────────────────────────────────────────────────────────
SEVERITY = {
    # CRITICAL — block by default
    "SSN": "CRITICAL", "CREDIT_CARD": "CRITICAL", "PRIVATE_KEY": "CRITICAL",
    "AWS_KEY": "CRITICAL", "AWS_SECRET": "CRITICAL", "ANTHROPIC_KEY": "CRITICAL",
    "GCP_SERVICE_ACCT": "CRITICAL", "AZURE_CONN_STR": "CRITICAL",
    "CERTIFICATE": "CRITICAL", "MCP_CREDENTIAL": "CRITICAL",

    # HIGH — flagged, optionally blocked
    "OPENAI_KEY": "HIGH", "HUGGINGFACE_KEY": "HIGH", "GROQ_KEY": "HIGH",
    "XAI_KEY": "HIGH", "REPLICATE_KEY": "HIGH", "PERPLEXITY_KEY": "HIGH",
    "MISTRAL_KEY": "HIGH", "COHERE_KEY": "HIGH",
    "JWT": "HIGH", "BEARER_TOKEN": "HIGH", "OAUTH_TOKEN": "HIGH",
    "GH_TOKEN": "HIGH", "GITLAB_TOKEN": "HIGH",
    "STRIPE_KEY": "HIGH", "STRIPE_WEBHOOK": "HIGH",
    "SLACK_TOKEN": "HIGH", "SLACK_WEBHOOK": "HIGH",
    "SENDGRID_KEY": "HIGH", "TWILIO_KEY": "HIGH", "TWILIO_TOKEN": "HIGH",
    "NPM_TOKEN": "HIGH", "FIREBASE_KEY": "HIGH", "SUPABASE_KEY": "HIGH",
    "DATADOG_KEY": "HIGH", "MAILGUN_KEY": "HIGH",
    "CONNECTION_STR": "HIGH", "ENV_FILE": "HIGH",
    "BASIC_AUTH": "HIGH", "GOOGLE_API": "HIGH",
    "VERCEL_TOKEN": "HIGH", "NETLIFY_TOKEN": "HIGH",

    # MEDIUM — flagged only
    "EMAIL": "MEDIUM", "PHONE_US": "MEDIUM", "IP_ADDRESS": "MEDIUM",
    "INTERNAL_URL": "MEDIUM", "VPN_HOSTNAME": "MEDIUM",
    "DOB": "MEDIUM", "PASSPORT": "MEDIUM",
}

# Domains considered sensitive — navigating here while Cowork is active triggers a warning

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

    # Maximum findings per pattern type — prevents log flooding on
    # payloads with many repeated matches (e.g. 1000 email addresses)
    MAX_FINDINGS_PER_PATTERN = 5

    def __init__(self, block_on_critical=True, block_on_high=False,
                 email_allowlist=None, suppressed_patterns=None):
        self.block_on_critical = block_on_critical
        self.block_on_high = block_on_high
        # User-configurable email domain allowlist — e.g. ["mycompany.com"]
        # Emails matching these domains are not flagged
        self.email_allowlist = [d.lower() for d in (email_allowlist or [])]
        # Patterns to suppress entirely — e.g. ["GCP_SERVICE_ACCT"] if known safe
        self.suppressed_patterns = set(suppressed_patterns or [])
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

    def _is_allowlisted_email(self, match_str: str) -> bool:
        """Returns True if email matches user's allowlist domains."""
        if not self.email_allowlist:
            return False
        lower = match_str.lower()
        return any(lower.endswith("@" + domain) or lower.endswith("." + domain)
                   for domain in self.email_allowlist)

    def scan(self, text: str) -> ScanResult:
        findings = []
        # Track count per pattern for deduplication cap
        pattern_counts: dict = {}

        for name, pattern in self._compiled.items():
            # Skip suppressed patterns
            if name in self.suppressed_patterns:
                continue

            for match in pattern.finditer(text):
                match_str = match.group()

                # Apply email allowlist
                if name == "EMAIL" and self._is_allowlisted_email(match_str):
                    continue

                # Cap findings per pattern type
                count = pattern_counts.get(name, 0)
                if count >= self.MAX_FINDINGS_PER_PATTERN:
                    continue
                pattern_counts[name] = count + 1

                findings.append(Finding(
                    pattern_name=name,
                    severity=SEVERITY.get(name, "LOW"),
                    match_preview=self._redact(match_str),
                    char_position=match.start(),
                ))

        payload_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        result = ScanResult(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            payload_hash=payload_hash,
            payload_size_bytes=len(text.encode("utf-8")),
            findings=findings,
            action="CLEAN",
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

    def _extract_text_anthropic(self, body: dict) -> list:
        """Extract text from Anthropic API request format."""
        parts = []
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        system = body.get("system", "")
        if isinstance(system, str):
            parts.append(system)
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict):
                    parts.append(block.get("text", ""))
        return parts

    def _extract_text_openai(self, body: dict) -> list:
        """Extract text from OpenAI API request format (ChatCompletion)."""
        parts = []
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # OpenAI vision format: [{type: "text", text: "..."}, ...]
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        # Also check prompt field (completions API)
        if "prompt" in body:
            prompt = body["prompt"]
            if isinstance(prompt, str):
                parts.append(prompt)
            elif isinstance(prompt, list):
                parts.extend([p for p in prompt if isinstance(p, str)])
        return parts

    def _extract_text_gemini(self, body: dict) -> list:
        """Extract text from Google Gemini API request format."""
        parts = []
        for content in body.get("contents", []):
            for part in content.get("parts", []):
                if isinstance(part, dict) and "text" in part:
                    parts.append(part["text"])
        # System instruction
        system = body.get("systemInstruction", {})
        for part in system.get("parts", []):
            if isinstance(part, dict) and "text" in part:
                parts.append(part["text"])
        return parts

    def _extract_text_generic(self, body: dict) -> list:
        """
        Generic text extractor for other providers (Mistral, Cohere, Groq, etc.)
        Handles common message formats and falls back to full JSON string.
        """
        parts = []
        # Try OpenAI-compatible format first (most providers use this)
        if "messages" in body:
            parts.extend(self._extract_text_openai(body))
        # Cohere format
        if "message" in body and isinstance(body["message"], str):
            parts.append(body["message"])
        if "chat_history" in body:
            for msg in body["chat_history"]:
                if isinstance(msg, dict) and "message" in msg:
                    parts.append(msg["message"])
        # If nothing extracted, fall back to full JSON text
        if not parts:
            parts.append(json.dumps(body))
        return parts

    def scan_json_payload(self, raw_body: bytes, url: str = "") -> ScanResult:
        """
        Extracts text content from an AI API request body and scans it.
        Routes to provider-specific extractors based on URL.
        """
        try:
            body = json.loads(raw_body)
        except Exception:
            return self.scan(raw_body.decode("utf-8", errors="replace"))

        # Route to provider-specific extractor
        # Default (empty URL) uses Anthropic format for backwards compatibility
        url_lower = url.lower()
        if not url_lower or "anthropic.com" in url_lower:
            parts = self._extract_text_anthropic(body)
        elif "openai.com" in url_lower or "cursor.sh" in url_lower or "groq.com" in url_lower:
            parts = self._extract_text_openai(body)
        elif "googleapis.com" in url_lower:
            parts = self._extract_text_gemini(body)
        else:
            # Mistral, Cohere, Perplexity, xAI, Copilot — generic handler
            parts = self._extract_text_generic(body)

        combined = "\n".join(parts)
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
    JWT: eyJURVNUX09OTFlfTk9UX1JFQUw.eyJURVNUX09OTFlfTk9UX1JFQUwifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
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
