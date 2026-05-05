"""
Tests for proxy-level MCP secret scanning (MCP_SECRET_BLOCKED path).

These tests verify that the CoworkScanner (secret/PII scanner) correctly
catches sensitive data in MCP tool responses — separate from the
PolicyEngine (injection/metadata/unicode) path.

Tests:
  - Tool response containing SSN → blocked
  - Tool response containing AWS key → blocked
  - Tool response containing private key → blocked
  - Clean tool response → passes through
  - Tool response with injection AND SSN → secret scanner fires first
  - Nested tool_result content → blocked
  - Empty tool response → passes through
"""

import json
import pytest

from scanner import CoworkScanner


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def scan_tool_output(text: str, block_on_critical: bool = True, block_on_high: bool = False):
    """
    Simulate what proxy.py does in the MCP response hook:
    scanner.scan(tool_output) where tool_output is the extracted text.
    """
    scanner = CoworkScanner(
        block_on_critical=block_on_critical,
        block_on_high=block_on_high,
    )
    return scanner.scan(text)


def scan_tool_result_payload(payload: dict, block_on_critical: bool = True):
    """
    Simulate scan_json_payload on a top-level tool_result body.
    """
    scanner = CoworkScanner(block_on_critical=block_on_critical)
    raw = json.dumps(payload).encode()
    return scanner.scan_json_payload(raw)


# ─────────────────────────────────────────────
# MCP_SECRET_BLOCKED — detection
# ─────────────────────────────────────────────

class TestMCPSecretBlocked:

    def test_ssn_in_tool_output_is_blocked(self):
        result = scan_tool_output(
            "User record found. SSN: 123-45-6789, Name: John Smith"
        )
        assert result.blocked is True
        assert result.action == "BLOCKED"
        assert any(f.pattern_name == "SSN" for f in result.findings)

    def test_aws_key_in_tool_output_is_blocked(self):
        result = scan_tool_output(
            "Credentials: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        assert result.blocked is True
        assert any(f.severity == "CRITICAL" for f in result.findings)

    def test_private_key_in_tool_output_is_blocked(self):
        result = scan_tool_output(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        )
        assert result.blocked is True
        assert any(f.pattern_name == "PRIVATE_KEY" for f in result.findings)

    def test_anthropic_api_key_in_tool_output_is_blocked(self):
        result = scan_tool_output(
            "Here is your API key: sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop"
        )
        assert result.blocked is True

    def test_openai_api_key_in_tool_output_is_flagged(self):
        result = scan_tool_output(
            "OpenAI key: sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        )
        assert result.blocked is False
        assert result.action == "FLAGGED"
        assert any(f.pattern_name == "OPENAI_KEY" for f in result.findings)

    def test_openai_api_key_blocked_when_block_on_high(self):
        result = scan_tool_output(
            "OpenAI key: sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            block_on_high=True,
        )
        assert result.blocked is True

    def test_credit_card_in_tool_output_is_blocked(self):
        result = scan_tool_output(
            "Payment details: 4532015112830366 exp 12/26"
        )
        assert result.blocked is True


# ─────────────────────────────────────────────
# MCP_SECRET_BLOCKED — clean responses pass through
# ─────────────────────────────────────────────

class TestMCPCleanPassThrough:

    def test_clean_file_listing_passes(self):
        result = scan_tool_output(
            "Files found: main.py, README.md, requirements.txt, tests/"
        )
        assert result.blocked is False

    def test_clean_database_result_passes(self):
        result = scan_tool_output(
            "Query returned 3 rows: [{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}]"
        )
        assert result.blocked is False

    def test_clean_api_response_passes(self):
        result = scan_tool_output(
            '{"status": "ok", "message": "Operation completed successfully", "count": 42}'
        )
        assert result.blocked is False

    def test_empty_tool_output_passes(self):
        result = scan_tool_output("")
        assert result.blocked is False

    def test_clean_code_snippet_passes(self):
        result = scan_tool_output(
            "def hello_world():\n    print('Hello, world!')\n\nhello_world()"
        )
        assert result.blocked is False


# ─────────────────────────────────────────────
# tool_result top-level payload extraction
# ─────────────────────────────────────────────

class TestToolResultExtraction:

    def test_ssn_in_top_level_tool_result_blocked(self):
        payload = {
            "type": "tool_result",
            "content": "Patient record: SSN 123-45-6789"
        }
        result = scan_tool_result_payload(payload)
        assert result.blocked is True
        assert any(f.pattern_name == "SSN" for f in result.findings)

    def test_aws_key_in_top_level_tool_result_blocked(self):
        payload = {
            "type": "tool_result",
            "content": "Found credentials: AKIAIOSFODNN7EXAMPLE"
        }
        result = scan_tool_result_payload(payload)
        assert result.blocked is True

    def test_clean_top_level_tool_result_passes(self):
        payload = {
            "type": "tool_result",
            "content": "Here are the files: main.py, README.md"
        }
        result = scan_tool_result_payload(payload)
        assert result.blocked is False

    def test_nested_tool_result_list_content_blocked(self):
        payload = {
            "type": "tool_result",
            "content": [
                {"type": "text", "text": "User found. SSN: 123-45-6789"}
            ]
        }
        result = scan_tool_result_payload(payload)
        assert result.blocked is True

    def test_empty_tool_result_passes(self):
        payload = {
            "type": "tool_result",
            "content": ""
        }
        result = scan_tool_result_payload(payload)
        assert result.blocked is False


# ─────────────────────────────────────────────
# Severity and blocking thresholds
# ─────────────────────────────────────────────

class TestMCPSeverityThresholds:

    def test_critical_blocked_by_default(self):
        result = scan_tool_output(
            "SSN: 123-45-6789",
            block_on_critical=True,
            block_on_high=False,
        )
        assert result.blocked is True

    def test_high_not_blocked_when_block_on_high_false(self):
        # JWT is HIGH severity — should not block unless block_on_high=True
        result = scan_tool_output(
            "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            block_on_critical=True,
            block_on_high=False,
        )
        assert result.blocked is False
        assert len(result.findings) > 0

    def test_high_blocked_when_block_on_high_true(self):
        result = scan_tool_output(
            "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            block_on_critical=True,
            block_on_high=True,
        )
        assert result.blocked is True

    def test_findings_are_redacted(self):
        """Raw sensitive values must never appear in finding previews."""
        result = scan_tool_output("SSN: 123-45-6789")
        for f in result.findings:
            assert "123-45-6789" not in f.match_preview
