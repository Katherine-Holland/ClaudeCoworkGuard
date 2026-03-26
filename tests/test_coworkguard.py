#!/usr/bin/env python3
"""
CoworkGuard - Test Suite
Run from the coworkguard/ directory:

    python3 tests/test_coworkguard.py

Or run individual test classes:

    python3 -m pytest tests/test_coworkguard.py -v
"""

import sys
import json
import unittest
from pathlib import Path

# Add parent dir to path so we can import scanner
sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner import CoworkScanner, ScanResult, Finding


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def make_scanner(critical=True, high=False, medium=False):
    return CoworkScanner(
        block_on_critical=critical,
        block_on_high=high,
    )


# ─────────────────────────────────────────────
# PII Tests
# ─────────────────────────────────────────────

class TestPIIDetection(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_ssn_detected(self):
        result = self.scanner.scan("User SSN is 123-45-6789 please process")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("SSN", types)

    def test_ssn_is_critical(self):
        result = self.scanner.scan("SSN: 987-65-4321")
        ssn = next(f for f in result.findings if f.pattern_name == "SSN")
        self.assertEqual(ssn.severity, "CRITICAL")

    def test_ssn_blocks_request(self):
        result = self.scanner.scan("SSN: 123-45-6789")
        self.assertTrue(result.blocked)
        self.assertEqual(result.action, "BLOCKED")

    def test_email_detected(self):
        result = self.scanner.scan("Contact john.smith@company.co.uk for details")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("EMAIL", types)

    def test_email_is_medium(self):
        result = self.scanner.scan("Email: user@example.com")
        email = next(f for f in result.findings if f.pattern_name == "EMAIL")
        self.assertEqual(email.severity, "MEDIUM")

    def test_email_does_not_block_by_default(self):
        result = self.scanner.scan("Email: user@example.com")
        self.assertFalse(result.blocked)
        self.assertEqual(result.action, "FLAGGED")

    def test_credit_card_detected(self):
        result = self.scanner.scan("Card: 4532015112830366 expires 12/26")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("CREDIT_CARD", types)

    def test_credit_card_is_critical(self):
        result = self.scanner.scan("4532015112830366")
        cc = next(f for f in result.findings if f.pattern_name == "CREDIT_CARD")
        self.assertEqual(cc.severity, "CRITICAL")

    def test_us_phone_detected(self):
        result = self.scanner.scan("Call me at 555-867-5309")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("PHONE_US", types)

    def test_ip_address_detected(self):
        result = self.scanner.scan("Server is at 192.168.1.100")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("IP_ADDRESS", types)


# ─────────────────────────────────────────────
# Secret / Auth Tests
# ─────────────────────────────────────────────

class TestSecretDetection(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_aws_key_detected(self):
        result = self.scanner.scan("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("AWS_KEY", types)

    def test_aws_key_is_critical(self):
        result = self.scanner.scan("AKIAIOSFODNN7EXAMPLE")
        aws = next(f for f in result.findings if f.pattern_name == "AWS_KEY")
        self.assertEqual(aws.severity, "CRITICAL")

    def test_aws_key_blocks(self):
        result = self.scanner.scan("key: AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(result.blocked)

    def test_github_token_detected(self):
        result = self.scanner.scan("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("GH_TOKEN", types)

    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = self.scanner.scan(f"Authorization header: {jwt}")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("JWT", types)

    def test_jwt_is_high(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = self.scanner.scan(jwt)
        j = next(f for f in result.findings if f.pattern_name == "JWT")
        self.assertEqual(j.severity, "HIGH")

    def test_private_key_detected(self):
        result = self.scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("PRIVATE_KEY", types)

    def test_private_key_is_critical(self):
        result = self.scanner.scan("-----BEGIN PRIVATE KEY-----")
        pk = next(f for f in result.findings if f.pattern_name == "PRIVATE_KEY")
        self.assertEqual(pk.severity, "CRITICAL")

    def test_openai_legacy_key_detected(self):
        result = self.scanner.scan("key: sk-" + "a" * 48)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("OPENAI_KEY", types)

    def test_openai_project_key_detected(self):
        result = self.scanner.scan("key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890AB")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("OPENAI_KEY", types)

    def test_openai_svcacct_key_detected(self):
        result = self.scanner.scan("key: sk-svcacct-abcdefghijklmnopqrstuvwxyz123456")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("OPENAI_KEY", types)

    def test_stripe_key_detected(self):
        result = self.scanner.scan("stripe_key=sk_live_abcdefghijklmnopqrstuvwx")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("STRIPE_KEY", types)

    def test_bearer_token_detected(self):
        result = self.scanner.scan("Authorization: Bearer eyABC123DEF456GHI789JKL012MNO")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("BEARER_TOKEN", types)

    def test_anthropic_key_detected(self):
        result = self.scanner.scan("key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("ANTHROPIC_KEY", types)

    def test_huggingface_key_detected(self):
        result = self.scanner.scan("hf_token: hf_abcdefghijklmnopqrstuvwxyz12345678")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("HUGGINGFACE_KEY", types)

    def test_groq_key_detected(self):
        result = self.scanner.scan("gsk_" + "a" * 52)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("GROQ_KEY", types)

    def test_xai_key_detected(self):
        result = self.scanner.scan("xai-abcdefghijklmnopqrstuvwxyz1234567890abcd")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("XAI_KEY", types)

    def test_replicate_key_detected(self):
        result = self.scanner.scan("r8_" + "a" * 40)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("REPLICATE_KEY", types)

    def test_sendgrid_key_detected(self):
        result = self.scanner.scan("SG." + "a"*22 + "." + "b"*43)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("SENDGRID_KEY", types)

    def test_npm_token_detected(self):
        result = self.scanner.scan("npm_abcdefghijklmnopqrstuvwxyz1234567890")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("NPM_TOKEN", types)

    def test_gitlab_token_detected(self):
        result = self.scanner.scan("glpat-abcdefghijklmnopqrst")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("GITLAB_TOKEN", types)

    def test_slack_webhook_detected(self):
        result = self.scanner.scan("https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/abcdefghijklmnopqrstuvwx")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("SLACK_WEBHOOK", types)

    def test_stripe_webhook_detected(self):
        result = self.scanner.scan("whsec_abcdefghijklmnopqrstuvwxyz1234567890ab")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("STRIPE_WEBHOOK", types)

    def test_gcp_service_account_detected(self):
        result = self.scanner.scan('{"type": "service_account", "project_id": "myproject"}')
        types = [f.pattern_name for f in result.findings]
        self.assertIn("GCP_SERVICE_ACCT", types)

    def test_gcp_service_account_is_critical(self):
        result = self.scanner.scan('{"type": "service_account"}')
        gcp = next(f for f in result.findings if f.pattern_name == "GCP_SERVICE_ACCT")
        self.assertEqual(gcp.severity, "CRITICAL")


# ─────────────────────────────────────────────
# Internal / Corporate Tests
# ─────────────────────────────────────────────

class TestInternalDataDetection(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_internal_url_detected(self):
        result = self.scanner.scan("Dashboard at http://192.168.1.50:3000/admin")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("INTERNAL_URL", types)

    def test_private_10x_url_detected(self):
        result = self.scanner.scan("API endpoint: http://10.0.1.5/api/v1/users")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("INTERNAL_URL", types)

    def test_vpn_hostname_detected(self):
        result = self.scanner.scan("Connect to https://jenkins.internal/build/42")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("VPN_HOSTNAME", types)

    def test_db_connection_string_detected(self):
        result = self.scanner.scan("DATABASE_URL=postgresql://admin:secret@db.prod:5432/myapp")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("CONNECTION_STR", types)

    def test_db_connection_string_is_high(self):
        result = self.scanner.scan("postgresql://user:pass@host:5432/db")
        db = next(f for f in result.findings if f.pattern_name == "CONNECTION_STR")
        self.assertEqual(db.severity, "HIGH")

    def test_env_value_detected(self):
        result = self.scanner.scan("DB_PASSWORD=supersecretpassword123")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("ENV_FILE", types)

    def test_mongodb_detected(self):
        result = self.scanner.scan("mongodb://user:pass@cluster.example.com:27017/prod")
        types = [f.pattern_name for f in result.findings]
        self.assertIn("CONNECTION_STR", types)


# ─────────────────────────────────────────────
# Blocking Behaviour Tests
# ─────────────────────────────────────────────

class TestBlockingBehaviour(unittest.TestCase):

    def test_clean_payload_is_allowed(self):
        scanner = make_scanner()
        result = scanner.scan("Please summarise this meeting transcript for me.")
        self.assertFalse(result.blocked)
        self.assertEqual(result.action, "CLEAN")
        self.assertEqual(len(result.findings), 0)

    def test_critical_blocked_by_default(self):
        scanner = make_scanner(critical=True, high=False)
        result = scanner.scan("SSN: 123-45-6789")
        self.assertTrue(result.blocked)

    def test_high_not_blocked_by_default(self):
        scanner = make_scanner(critical=True, high=False)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl012mno345pqr678"
        result = scanner.scan(jwt)
        self.assertFalse(result.blocked)
        self.assertEqual(result.action, "FLAGGED")

    def test_high_blocked_when_enabled(self):
        scanner = CoworkScanner(block_on_critical=True, block_on_high=True)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl012mno345pqr678stu"
        result = scanner.scan(jwt)
        self.assertTrue(result.blocked)

    def test_multiple_findings_highest_wins(self):
        scanner = make_scanner(critical=True, high=False)
        # Mix of MEDIUM (email) and CRITICAL (SSN) — should block
        result = scanner.scan("Email: user@test.com SSN: 123-45-6789")
        self.assertTrue(result.blocked)

    def test_action_values(self):
        scanner = make_scanner()
        clean   = scanner.scan("Just a normal message")
        flagged = scanner.scan("Email: user@test.com")
        blocked = scanner.scan("SSN: 123-45-6789")
        self.assertEqual(clean.action,   "CLEAN")
        self.assertEqual(flagged.action, "FLAGGED")
        self.assertEqual(blocked.action, "BLOCKED")


# ─────────────────────────────────────────────
# Redaction Tests
# ─────────────────────────────────────────────

class TestRedaction(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_preview_never_exposes_full_value(self):
        result = self.scanner.scan("SSN: 123-45-6789")
        ssn = next(f for f in result.findings if f.pattern_name == "SSN")
        self.assertNotEqual(ssn.match_preview, "123-45-6789")

    def test_preview_contains_asterisks(self):
        result = self.scanner.scan("SSN: 123-45-6789")
        ssn = next(f for f in result.findings if f.pattern_name == "SSN")
        self.assertIn("*", ssn.match_preview)

    def test_payload_hash_is_not_raw_content(self):
        text = "SSN: 123-45-6789"
        result = self.scanner.scan(text)
        self.assertNotIn("123-45-6789", result.payload_hash)
        self.assertNotEqual(result.payload_hash, text)

    def test_payload_size_is_accurate(self):
        text = "Hello world"
        result = self.scanner.scan(text)
        self.assertEqual(result.payload_size_bytes, len(text.encode("utf-8")))


# ─────────────────────────────────────────────
# JSON Payload Tests (Anthropic API format)
# ─────────────────────────────────────────────

class TestJSONPayloadScanning(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_scans_message_content(self):
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "messages": [
                {"role": "user", "content": "My SSN is 123-45-6789"}
            ]
        }).encode()
        result = self.scanner.scan_json_payload(payload)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("SSN", types)

    def test_scans_nested_content_blocks(self):
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "AWS key: AKIAIOSFODNN7EXAMPLE"}
                ]}
            ]
        }).encode()
        result = self.scanner.scan_json_payload(payload)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("AWS_KEY", types)

    def test_scans_system_prompt(self):
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "system": "DB password: DB_PASSWORD=hunter2",
            "messages": [{"role": "user", "content": "Hello"}]
        }).encode()
        result = self.scanner.scan_json_payload(payload)
        types = [f.pattern_name for f in result.findings]
        self.assertIn("ENV_FILE", types)

    def test_clean_message_passes(self):
        payload = json.dumps({
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": "What is the capital of France?"}]
        }).encode()
        result = self.scanner.scan_json_payload(payload)
        self.assertEqual(result.action, "CLEAN")

    def test_invalid_json_handled_gracefully(self):
        result = self.scanner.scan_json_payload(b"not json at all {{{{")
        self.assertIsInstance(result, ScanResult)


# ─────────────────────────────────────────────
# Domain Check Tests
# ─────────────────────────────────────────────

class TestDomainChecks(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_aws_console_is_sensitive(self):
        match = self.scanner.check_domain("https://console.aws.amazon.com/ec2/v2/home")
        self.assertIsNotNone(match)

    def test_gmail_is_sensitive(self):
        match = self.scanner.check_domain("https://mail.google.com/mail/u/0/")
        self.assertIsNotNone(match)

    def test_salesforce_is_sensitive(self):
        match = self.scanner.check_domain("https://myorg.salesforce.com/lightning/")
        self.assertIsNotNone(match)

    def test_google_search_is_not_sensitive(self):
        match = self.scanner.check_domain("https://www.google.com/search?q=weather")
        self.assertIsNone(match)

    def test_random_site_not_sensitive(self):
        match = self.scanner.check_domain("https://www.bbc.co.uk/news")
        self.assertIsNone(match)

    def test_github_is_sensitive(self):
        match = self.scanner.check_domain("https://github.com/myorg/private-repo")
        self.assertIsNotNone(match)


# ─────────────────────────────────────────────
# Edge Cases
# ─────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):

    def setUp(self):
        self.scanner = make_scanner()

    def test_empty_string(self):
        result = self.scanner.scan("")
        self.assertEqual(result.action, "CLEAN")

    def test_very_long_clean_text(self):
        result = self.scanner.scan("Hello world. " * 5000)
        self.assertEqual(result.action, "CLEAN")

    def test_multiple_secrets_same_payload(self):
        text = "SSN: 123-45-6789 and AWS: AKIAIOSFODNN7EXAMPLE"
        result = self.scanner.scan(text)
        self.assertTrue(result.blocked)
        self.assertGreaterEqual(len(result.findings), 2)

    def test_unicode_text_handled(self):
        result = self.scanner.scan("こんにちは世界 — bonjour le monde — مرحبا بالعالم")
        self.assertIsInstance(result, ScanResult)

    def test_result_has_timestamp(self):
        result = self.scanner.scan("test")
        self.assertTrue(result.timestamp.endswith("Z"))

    def test_result_has_hash(self):
        result = self.scanner.scan("test content")
        self.assertEqual(len(result.payload_hash), 16)

    def test_has_critical_property(self):
        result = self.scanner.scan("SSN: 123-45-6789")
        self.assertTrue(result.has_critical)

    def test_has_high_property(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl012mno345pqr678stu"
        result = self.scanner.scan(jwt)
        self.assertTrue(result.has_high)


# ─────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestPIIDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestInternalDataDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestBlockingBehaviour))
    suite.addTests(loader.loadTestsFromTestCase(TestRedaction))
    suite.addTests(loader.loadTestsFromTestCase(TestJSONPayloadScanning))
    suite.addTests(loader.loadTestsFromTestCase(TestDomainChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"CoworkGuard Test Suite")
    print(f"{'='*60}")
    print(f"Tests run:  {result.testsRun}")
    print(f"Failures:   {len(result.failures)}")
    print(f"Errors:     {len(result.errors)}")
    print(f"{'PASSED ✅' if result.wasSuccessful() else 'FAILED ❌'}")

    sys.exit(0 if result.wasSuccessful() else 1)
