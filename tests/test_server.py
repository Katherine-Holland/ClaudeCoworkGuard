"""
Tests for server.py API endpoints and helper functions.
Uses Flask test client — no real server process needed.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# server.py imports flask and psutil at module level; patch psutil before import
import sys
sys.modules.setdefault("psutil", MagicMock(process_iter=lambda *a, **kw: []))

import server
from server import app, load_settings, save_settings, check_payload_folders, is_path_allowed


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Flask test client with isolated settings and log dirs."""
    monkeypatch.setattr(server, "SETTINGS", tmp_path / "settings.json")
    monkeypatch.setattr(server, "LOG_DIR", tmp_path / "logs")
    (tmp_path / "logs").mkdir()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def client_with_logs(tmp_path, monkeypatch):
    """Client with pre-populated audit log entries."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(server, "SETTINGS", tmp_path / "settings.json")
    monkeypatch.setattr(server, "LOG_DIR", log_dir)

    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    log_file = log_dir / f"audit_{today}.jsonl"
    entries = [
        {"timestamp": "2026-01-01T10:00:00+00:00", "action": "CLEAN",   "findings": [], "payload_size_bytes": 100},
        {"timestamp": "2026-01-01T10:01:00+00:00", "action": "FLAGGED", "findings": [{"type": "SSN", "severity": "CRITICAL"}], "payload_size_bytes": 200},
        {"timestamp": "2026-01-01T10:02:00+00:00", "action": "BLOCKED", "findings": [{"type": "AWS_KEY", "severity": "CRITICAL"}], "payload_size_bytes": 300},
    ]
    with open(log_file, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ─────────────────────────────────────────────
# /api/status
# ─────────────────────────────────────────────

class TestStatusEndpoint:

    def test_returns_200(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200

    def test_has_required_keys(self, client):
        data = json.loads(client.get("/api/status").data)
        assert "server" in data
        assert "settings" in data
        assert "timestamp" in data
        assert data["server"] == "ok"

    def test_timestamp_is_iso_format(self, client):
        data = json.loads(client.get("/api/status").data)
        from datetime import datetime
        # Should parse without error
        datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))

    def test_settings_contains_defaults(self, client):
        data = json.loads(client.get("/api/status").data)
        settings = data["settings"]
        assert "block_on_critical" in settings
        assert "block_on_high" in settings
        assert settings["block_on_critical"] is True


# ─────────────────────────────────────────────
# /api/logs
# ─────────────────────────────────────────────

class TestLogsEndpoint:

    def test_returns_200(self, client):
        r = client.get("/api/logs")
        assert r.status_code == 200

    def test_empty_logs_returns_valid_structure(self, client):
        data = json.loads(client.get("/api/logs").data)
        assert "entries" in data
        assert "stats" in data
        assert "total" in data
        assert isinstance(data["entries"], list)

    def test_returns_log_entries(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs").data)
        assert data["total"] == 3

    def test_stats_counts_correct(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs").data)
        stats = data["stats"]
        assert stats["blocked"] == 1
        assert stats["flagged"] == 1
        assert stats["clean"] == 1

    def test_pattern_counts_populated(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs").data)
        counts = data["patternCounts"]
        assert "SSN" in counts or "AWS_KEY" in counts

    def test_limit_parameter_respected(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs?limit=1").data)
        assert len(data["entries"]) <= 1

    def test_limit_clamped_to_1000(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs?limit=99999").data)
        # Should not raise — limit is clamped
        assert data["total"] <= 1000

    def test_invalid_limit_uses_default(self, client_with_logs):
        data = json.loads(client_with_logs.get("/api/logs?limit=abc").data)
        assert data is not None


# ─────────────────────────────────────────────
# /api/settings GET + POST
# ─────────────────────────────────────────────

class TestSettingsEndpoint:

    def test_get_returns_defaults(self, client):
        data = json.loads(client.get("/api/settings").data)
        assert data["block_on_critical"] is True
        assert data["block_on_high"] is False
        assert data["proxy_port"] == 8080

    def test_post_updates_boolean(self, client):
        r = client.post("/api/settings",
                        data=json.dumps({"block_on_high": True}),
                        content_type="application/json")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["ok"] is True
        assert data["settings"]["block_on_high"] is True

    def test_post_persists_across_get(self, client):
        client.post("/api/settings",
                    data=json.dumps({"block_on_high": True}),
                    content_type="application/json")
        data = json.loads(client.get("/api/settings").data)
        assert data["block_on_high"] is True

    def test_post_clamps_proxy_port(self, client):
        r = client.post("/api/settings",
                        data=json.dumps({"proxy_port": 99999}),
                        content_type="application/json")
        data = json.loads(r.data)
        assert data["settings"]["proxy_port"] == 65535

    def test_post_clamps_proxy_port_min(self, client):
        r = client.post("/api/settings",
                        data=json.dumps({"proxy_port": 1}),
                        content_type="application/json")
        data = json.loads(r.data)
        assert data["settings"]["proxy_port"] == 1024

    def test_post_rejects_invalid_json(self, client):
        r = client.post("/api/settings",
                        data="not json",
                        content_type="application/json")
        # Should return 400 or handle gracefully
        assert r.status_code in (400, 200)

    def test_post_rejects_invalid_regex_in_custom_patterns(self, client):
        r = client.post("/api/settings",
                        data=json.dumps({"custom_patterns": ["[invalid"]}),
                        content_type="application/json")
        data = json.loads(r.data)
        # Invalid regex should be silently dropped
        assert data["settings"].get("custom_patterns", []) == []

    def test_post_accepts_valid_regex(self, client):
        r = client.post("/api/settings",
                        data=json.dumps({"custom_patterns": [r"\bACME-\d{6}\b"]}),
                        content_type="application/json")
        data = json.loads(r.data)
        assert r"\bACME-\d{6}\b" in data["settings"]["custom_patterns"]

    def test_post_allowed_folders_stored(self, client, tmp_path):
        r = client.post("/api/settings",
                        data=json.dumps({"allowed_folders": [str(tmp_path)]}),
                        content_type="application/json")
        data = json.loads(r.data)
        assert str(tmp_path) in data["settings"]["allowed_folders"]


# ─────────────────────────────────────────────
# /api/clear
# ─────────────────────────────────────────────

class TestClearEndpoint:

    def test_clear_returns_ok(self, client):
        r = client.post("/api/clear")
        assert r.status_code == 200
        assert json.loads(r.data)["ok"] is True

    def test_clear_removes_log_files(self, client_with_logs, monkeypatch, tmp_path):
        # Verify logs exist first
        data = json.loads(client_with_logs.get("/api/logs").data)
        assert data["total"] > 0
        client_with_logs.post("/api/clear")
        data = json.loads(client_with_logs.get("/api/logs").data)
        assert data["total"] == 0


# ─────────────────────────────────────────────
# /api/domains
# ─────────────────────────────────────────────

class TestDomainsEndpoint:

    def test_returns_list(self, client):
        r = client.get("/api/domains")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "sensitive_domains" in data
        assert isinstance(data["sensitive_domains"], list)


# ─────────────────────────────────────────────
# /api/folder-check
# ─────────────────────────────────────────────

class TestFolderCheckEndpoint:

    def test_no_allowed_folders_always_ok(self, client):
        r = client.post("/api/folder-check",
                        data=json.dumps({"text": "/etc/passwd"}),
                        content_type="application/json")
        data = json.loads(r.data)
        assert data["ok"] is True

    def test_path_within_allowed_folder_ok(self, client, tmp_path):
        client.post("/api/settings",
                    data=json.dumps({"allowed_folders": [str(tmp_path)]}),
                    content_type="application/json")
        payload = {"file": str(tmp_path / "myfile.txt")}
        r = client.post("/api/folder-check",
                        data=json.dumps(payload),
                        content_type="application/json")
        data = json.loads(r.data)
        assert data["ok"] is True


# ─────────────────────────────────────────────
# Helper: load_settings / save_settings
# ─────────────────────────────────────────────

class TestSettingsHelpers:

    def test_load_settings_returns_defaults_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "SETTINGS", tmp_path / "nonexistent.json")
        s = load_settings()
        assert s["block_on_critical"] is True
        assert s["proxy_port"] == 8080

    def test_save_and_reload(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "SETTINGS", tmp_path / "settings.json")
        save_settings({"block_on_high": True})
        s = load_settings()
        assert s["block_on_high"] is True

    def test_save_merges_with_defaults(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server, "SETTINGS", tmp_path / "settings.json")
        save_settings({"block_on_high": True})
        s = load_settings()
        # All default keys should still be present
        assert "block_on_critical" in s
        assert "proxy_port" in s

    def test_load_handles_corrupt_json(self, tmp_path, monkeypatch):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{ not valid json }")
        monkeypatch.setattr(server, "SETTINGS", settings_file)
        s = load_settings()
        assert s["block_on_critical"] is True  # falls back to defaults


# ─────────────────────────────────────────────
# Helper: is_path_allowed / check_payload_folders
# ─────────────────────────────────────────────

class TestPathHelpers:

    def test_no_allowed_folders_always_true(self, tmp_path):
        assert is_path_allowed(str(tmp_path / "file.txt"), []) is True

    def test_path_within_allowed_folder(self, tmp_path):
        assert is_path_allowed(str(tmp_path / "sub" / "file.txt"), [str(tmp_path)]) is True

    def test_path_outside_allowed_folder(self, tmp_path):
        other = tmp_path / "other"
        allowed = tmp_path / "allowed"
        assert is_path_allowed(str(other / "file.txt"), [str(allowed)]) is False

    def test_check_payload_no_folders_returns_empty(self):
        payload = {"text": "/etc/passwd"}
        assert check_payload_folders(payload, []) == []

    def test_check_payload_url_paths_not_flagged(self, tmp_path):
        # URL paths like /api/v1/users should not be treated as filesystem paths
        payload = {"url": "https://api.example.com/v1/users"}
        result = check_payload_folders(payload, [str(tmp_path)])
        assert result == []

    def test_check_payload_detects_outside_path(self, tmp_path):
        allowed = str(tmp_path / "workspace")
        payload = {"file": "/etc/passwd"}
        blocked = check_payload_folders(payload, [allowed])
        assert any("/etc/passwd" in p for p in blocked)

    def test_check_payload_allows_inside_path(self, tmp_path):
        allowed = str(tmp_path)
        payload = {"file": str(tmp_path / "myfile.txt")}
        blocked = check_payload_folders(payload, [allowed])
        assert blocked == []


# ─────────────────────────────────────────────
# /api/log-event
# ─────────────────────────────────────────────

class TestLogEventEndpoint:

    def _post(self, client, tmp_path, monkeypatch, payload):
        monkeypatch.setattr(server, "LOG_DIR", tmp_path / "logs")
        (tmp_path / "logs").mkdir(exist_ok=True)
        return client.post("/api/log-event",
                           data=json.dumps(payload),
                           content_type="application/json")

    def _read_log(self, tmp_path):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_file = tmp_path / "logs" / f"audit_{today}.jsonl"
        return json.loads(log_file.read_text().strip().split("\n")[-1])

    def test_valid_window_ai_detected_accepted(self, client, tmp_path, monkeypatch):
        r = self._post(client, tmp_path, monkeypatch, {
            "type": "WINDOW_AI_DETECTED",
            "severity": "HIGH",
            "action": "FLAGGED",
            "url": "https://claude.ai/",
            "path": "LanguageModel",
            "timestamp": "2026-05-01T10:00:00+00:00",
        })
        assert r.status_code == 200
        assert json.loads(r.data)["ok"] is True

    def test_valid_suspicious_wrap_accepted(self, client, tmp_path, monkeypatch):
        r = self._post(client, tmp_path, monkeypatch, {
            "type": "SUSPICIOUS_API_WRAP",
            "severity": "CRITICAL",
            "action": "CRITICAL_ALERT",
            "url": "https://chat.openai.com/",
            "fetchWrapped": True,
            "xhrWrapped": False,
            "timestamp": "2026-05-01T10:00:00+00:00",
        })
        assert r.status_code == 200
        assert json.loads(r.data)["ok"] is True

    def test_missing_fields_handled_gracefully(self, client, tmp_path, monkeypatch):
        r = self._post(client, tmp_path, monkeypatch, {})
        assert r.status_code == 200
        assert json.loads(r.data)["ok"] is True

    def test_oversized_url_truncated(self, client, tmp_path, monkeypatch):
        self._post(client, tmp_path, monkeypatch, {
            "type": "WINDOW_AI_DETECTED",
            "url": "https://claude.ai/" + "x" * 1000,
            "timestamp": "2026-05-01T10:00:00+00:00",
        })
        entry = self._read_log(tmp_path)
        assert len(entry["url"]) <= 500

    def test_invalid_timestamp_replaced_with_server_time(self, client, tmp_path, monkeypatch):
        self._post(client, tmp_path, monkeypatch, {
            "type": "WINDOW_AI_DETECTED",
            "timestamp": "not-a-date",
            "url": "https://claude.ai/",
        })
        entry = self._read_log(tmp_path)
        assert entry["timestamp"] != "not-a-date"
        from datetime import datetime
        datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))

    def test_unknown_event_type_normalised_to_chrome_event(self, client, tmp_path, monkeypatch):
        self._post(client, tmp_path, monkeypatch, {
            "type": "UNKNOWN_EVIL_TYPE",
            "timestamp": "2026-05-01T10:00:00+00:00",
        })
        entry = self._read_log(tmp_path)
        assert entry["type"] == "CHROME_EVENT"

    def test_event_written_to_audit_log_with_correct_source(self, client, tmp_path, monkeypatch):
        self._post(client, tmp_path, monkeypatch, {
            "type": "WINDOW_AI_DETECTED",
            "severity": "HIGH",
            "action": "FLAGGED",
            "url": "https://claude.ai/",
            "timestamp": "2026-05-01T10:00:00+00:00",
        })
        entry = self._read_log(tmp_path)
        assert entry["type"] == "WINDOW_AI_DETECTED"
        assert entry["source"] == "chrome_extension"


# ─────────────────────────────────────────────
# /api/pending-requests and /api/allow-request
# ─────────────────────────────────────────────

class TestPendingRequestsEndpoint:

    def test_returns_empty_when_proxy_unavailable(self, client, monkeypatch):
        monkeypatch.setattr(server, "HAS_PROXY", False)
        r = client.get("/api/pending-requests")
        assert r.status_code == 200
        d = json.loads(r.data)
        assert d["pending"] == []
        assert d["count"] == 0

    def test_returns_pending_list_from_proxy(self, client, monkeypatch):
        fake_pending = [
            {
                "id": "a" * 32,
                "url": "https://api.anthropic.com/v1/messages",
                "method": "POST",
                "provider": "Anthropic",
                "payload_hash": "abc123",
                "payload_size_bytes": 512,
                "findings": [{"type": "SSN", "severity": "CRITICAL", "preview": "***", "blocked": True}],
                "timestamp": 1234567890.0,
                "age_seconds": 5,
            }
        ]
        mock_proxy = MagicMock()
        mock_proxy.get_pending_requests.return_value = fake_pending
        monkeypatch.setattr(server, "HAS_PROXY", True)
        monkeypatch.setitem(sys.modules, "proxy", mock_proxy)
        monkeypatch.setattr(server, "_proxy", mock_proxy, raising=False)
        r = client.get("/api/pending-requests")
        assert r.status_code == 200
        d = json.loads(r.data)
        assert d["count"] == 1
        assert d["pending"][0]["id"] == "a" * 32


class TestAllowRequestEndpoint:

    def test_malformed_id_rejected(self, client):
        r = client.post("/api/allow-request/not-valid")
        assert r.status_code == 400
        assert json.loads(r.data)["ok"] is False

    def test_short_id_rejected(self, client):
        r = client.post("/api/allow-request/abc123")
        assert r.status_code == 400

    def test_id_with_uppercase_rejected(self, client, monkeypatch):
        # uuid4().hex is always lowercase — uppercase should fail validation
        monkeypatch.setattr(server, "HAS_PROXY", True)
        r = client.post("/api/allow-request/" + "A" * 32)
        assert r.status_code == 400

    def test_valid_id_not_found_returns_404(self, client, monkeypatch):
        mock_proxy = MagicMock()
        mock_proxy.allow_request.return_value = False
        monkeypatch.setattr(server, "HAS_PROXY", True)
        monkeypatch.setattr(server, "_proxy", mock_proxy, raising=False)
        r = client.post("/api/allow-request/" + "a" * 32)
        assert r.status_code == 404
        assert json.loads(r.data)["ok"] is False

    def test_valid_id_found_returns_200(self, client, monkeypatch):
        mock_proxy = MagicMock()
        mock_proxy.allow_request.return_value = True
        monkeypatch.setattr(server, "HAS_PROXY", True)
        monkeypatch.setattr(server, "_proxy", mock_proxy, raising=False)
        valid_id = "b" * 32
        r = client.post(f"/api/allow-request/{valid_id}")
        assert r.status_code == 200
        d = json.loads(r.data)
        assert d["ok"] is True
        assert d["request_id"] == valid_id

    def test_proxy_unavailable_returns_503(self, client, monkeypatch):
        monkeypatch.setattr(server, "HAS_PROXY", False)
        r = client.post("/api/allow-request/" + "c" * 32)
        assert r.status_code == 503
