"""
Copyright (c) 2026 Katherine Weston. All rights reserved.
Licensed under MIT with Commons Clause — see LICENSE for details.
Commercial use prohibited without a separate commercial license.

CoworkGuard - Local API Server
Serves live audit log data to the dashboard over localhost.
Also handles settings persistence and process detection.

Usage:
    pip install flask flask-cors psutil
    python3 server.py

Runs on http://localhost:7070
"""

import json
import re
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import proxy as _proxy
    HAS_PROXY = True
except ImportError:
    HAS_PROXY = False

app = Flask(__name__)
# Restrict CORS to localhost only — prevents malicious pages from
# calling the API while the dashboard is open in another tab
CORS(app, origins=[
    "http://localhost:7070",
    "http://127.0.0.1:7070",
    "http://localhost:3000",   # dev convenience
])

LOG_DIR = Path.home() / ".coworkguard" / "logs"
SETTINGS = Path.home() / ".coworkguard" / "settings.json"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────
# Default settings
# ─────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "block_on_critical": True,
    "block_on_high": False,
    "block_on_medium": False,
    "proxy_port": 8080,
    "max_log_entries": 1000,
    "alert_on_domain": True,
    "custom_patterns": [],
    "custom_blocked_domains": [],
    "allowed_folders": [],          # folders AI tools are allowed to read from
    "quiet_mode": False,
    "confirm_before_send": False,     # hold blocked requests for user confirmation
}


def load_settings():
    if SETTINGS.exists():
        try:
            with open(SETTINGS) as f:
                s = json.load(f)
            # Merge with defaults so new keys always exist
            return {**DEFAULT_SETTINGS, **s}
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(data):
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    merged = {**DEFAULT_SETTINGS, **data}
    with open(SETTINGS, "w") as f:
        json.dump(merged, f, indent=2)
    return merged


# ─────────────────────────────────────────────
# Folder allowlist — exit point check
# ─────────────────────────────────────────────

def is_path_allowed(path_str: str, allowed_folders: list) -> bool:
    """
    Check if a file path falls within the user's allowed folders.
    Returns True if allowed_folders is empty (no restriction set).
    Returns True if the path is within any allowed folder.
    Returns False if allowed_folders is set and path is outside all of them.
    """
    if not allowed_folders:
        return True  # no restriction configured — allow all
    try:
        p = Path(path_str).expanduser().resolve()
        for folder in allowed_folders:
            allowed = Path(folder).expanduser().resolve()
            try:
                p.relative_to(allowed)
                return True
            except ValueError:
                continue
        return False
    except Exception:
        return True  # if we can't parse the path, don't block


def check_payload_folders(payload: dict, allowed_folders: list) -> list:
    """
    Scan a payload dict for file paths and check them against the allowlist.
    Returns a list of blocked paths (empty if all clear).
    """
    if not allowed_folders:
        return []
    import re
    blocked = []
    payload_str = json.dumps(payload)
    # Strip URLs before extracting paths so that URL path components
    # (e.g. https://api.example.com/v1/users) are not treated as filesystem paths.
    stripped = re.sub(r'https?://[^\s\'"]+', '', payload_str)
    # Match absolute paths (/foo/bar) and home-relative paths (~/foo).
    paths = re.findall(r'(?<![:\w])\/[\w/.~-]{3,}|~\/[\w/.~-]+', stripped)
    for path in paths:
        if not is_path_allowed(path, allowed_folders):
            blocked.append(path)
    return blocked

# ─────────────────────────────────────────────
# Process detection
# ─────────────────────────────────────────────


def detect_cowork():
    """Detect if Claude desktop / Cowork is running."""
    if not HAS_PSUTIL:
        return {"active": False, "reason": "psutil not installed"}
    targets = ["Claude", "claude", "Claude Desktop", "Cowork"]
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmd = " ".join(proc.info["cmdline"] or [])
            if any(t.lower() in name.lower() or t.lower() in cmd.lower() for t in targets):
                return {"active": True, "pid": proc.pid, "name": name}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {"active": False}


def detect_proxy():
    """Check if mitmproxy is listening on the configured port."""
    settings = load_settings()
    port = settings.get("proxy_port", 8080)
    # Use socket check instead of psutil — avoids macOS permission issues
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return {"running": True, "port": port}
    except (ConnectionRefusedError, OSError):
        return {"running": False, "port": port}

# ─────────────────────────────────────────────
# Log reading
# ─────────────────────────────────────────────


def read_logs(limit=200):
    """Read all JSONL audit log files, newest entries first."""
    entries = []
    log_files = sorted(LOG_DIR.glob("audit_*.jsonl"), reverse=True)
    for lf in log_files[:7]:  # Max last 7 days
        try:
            with open(lf) as f:
                lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            if len(entries) >= limit:
                break
        except Exception:
            pass
    return entries[:limit]


def compute_stats(entries):
    blocked = sum(1 for e in entries if e.get("action") == "BLOCKED")
    flagged = sum(1 for e in entries if e.get("action") == "FLAGGED")
    clean = sum(1 for e in entries if e.get("action") == "CLEAN")
    domains = sum(1 for e in entries if e.get("type") == "DOMAIN_WARNING")
    return {"blocked": blocked, "flagged": flagged, "clean": clean, "domainWarnings": domains}


def compute_pattern_counts(entries):
    counts = {}
    for e in entries:
        for f in e.get("findings", []):
            t = f.get("type", "UNKNOWN")
            counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def compute_chart_data(entries):
    """
    Build hourly payload size buckets for the trend chart.
    Returns last 24 hours, one data point per hour.
    """
    from collections import defaultdict
    buckets = defaultdict(lambda: {"bytes": 0, "blocked": 0, "flagged": 0, "clean": 0})
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            key = ts.strftime("%Y-%m-%dT%H:00")
            size = e.get("payload_size_bytes", 0)
            buckets[key]["bytes"] += size
            action = e.get("action", "CLEAN")
            if action in buckets[key]:
                buckets[key][action.lower()] += 1
        except Exception:
            pass
    # Return sorted, last 24 buckets
    sorted_keys = sorted(buckets.keys())[-24:]
    return [{"hour": k, **buckets[k]} for k in sorted_keys]

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────


@app.route("/setup")
def setup():
    # setup.html is optional — only present after first-run wizard is needed
    setup_page = Path(__file__).parent / "setup.html"
    if setup_page.exists():
        return setup_page.read_text()
    # If setup.html not present, redirect to main dashboard
    from flask import redirect
    return redirect("/")



@app.route("/api/setup/install-deps", methods=["POST"])
def install_deps():
    """Install Python dependencies from requirements.txt."""
    import subprocess
    import sys
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists():
        return jsonify({"ok": False, "error": "requirements.txt not found"})
    try:
        # Try standard install first
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req),
             "--quiet", "--disable-pip-version-check"],
            capture_output=True, timeout=120
        )
        if result.returncode == 0:
            return jsonify({"ok": True})
        # Try with --break-system-packages for Homebrew/system Python
        result2 = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req),
             "--quiet", "--disable-pip-version-check", "--break-system-packages"],
            capture_output=True, timeout=120
        )
        if result2.returncode == 0:
            return jsonify({"ok": True})
        stderr = result2.stderr.decode("utf-8", errors="replace")[:300]
        return jsonify({"ok": False, "error": stderr or "pip install failed"})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Installation timed out — try manually: pip install -r requirements.txt"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/setup/generate-cert", methods=["POST"])
def generate_cert():
    """Run mitmdump briefly to generate the mitmproxy CA certificate."""
    import subprocess
    import time
    try:
        p = subprocess.Popen(
            ["mitmdump", "--listen-port", "18765", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        if cert.exists():
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Certificate file not found after generation"})
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "mitmdump not found — run: pip install mitmproxy"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/setup/trust-cert", methods=["POST"])
def trust_cert():
    """Attempt to auto-trust the mitmproxy certificate via macOS security command."""
    import subprocess
    cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not cert.exists():
        return jsonify({"ok": False, "error": "Certificate not found — complete step 1 first"})
    try:
        result = subprocess.run([
            "sudo", "-n", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(cert)
        ], capture_output=True, timeout=10)
        if result.returncode == 0:
            return jsonify({"ok": True})
        # sudo -n fails silently if password needed — try without -n (will prompt in terminal)
        return jsonify({"ok": False, "error": "Password required — please use the manual steps"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/setup/open-keychain", methods=["POST"])
def open_keychain():
    """Open the mitmproxy certificate in Keychain Access."""
    import subprocess
    cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if cert.exists():
        subprocess.Popen(["open", str(cert)])
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Certificate not found — complete step 1 first"})


@app.route("/api/domains")
def get_domains():
    """Serve sensitive domains list from domains.json — used by Chrome extension."""
    domains_file = Path(__file__).parent / "domains.json"
    if domains_file.exists():
        try:
            with open(domains_file) as f:
                data = json.load(f)
            # Merge with any custom domains from settings
            settings = load_settings()
            custom = settings.get("custom_blocked_domains", [])
            all_domains = list(set(data.get("sensitive_domains", []) + custom))
            return jsonify({"sensitive_domains": all_domains})
        except Exception:
            pass
    return jsonify({"sensitive_domains": []})


@app.route("/api/status")
def status():
    return jsonify({
        "cowork":    detect_cowork(),
        "proxy":     detect_proxy(),
        "settings":  load_settings(),
        "server":    "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/logs")
def logs():
    # Bounds-check limit — prevents unbounded log reads
    try:
        limit = int(request.args.get("limit", 200))
        limit = max(1, min(limit, 1000))
    except (ValueError, TypeError):
        limit = 200
    entries = read_logs(limit)
    return jsonify({
        "entries":       entries,
        "stats":         compute_stats(entries),
        "patternCounts": compute_pattern_counts(entries),
        "chartData":     compute_chart_data(entries),
        "total":         len(entries),
    })


@app.route("/api/skill-scans")
def skill_scans():
    """Read skill scan JSONL logs and return as JSON."""
    try:
        limit = int(request.args.get("limit", 200))
        limit = max(1, min(limit, 1000))
    except (ValueError, TypeError):
        limit = 200

    log_dir = Path.home() / ".coworkguard" / "logs"
    entries = []

    # Read all skill_scan_*.jsonl files sorted newest first
    try:
        log_files = sorted(log_dir.glob("skill_scan_*.jsonl"), reverse=True)
        for log_file in log_files:
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
            if len(entries) >= limit:
                break
    except Exception:
        pass

    entries = entries[:limit]
    # Sort newest first
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    return jsonify({
        "scans": entries,
        "total": len(entries),
    })


@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(load_settings())


@app.route("/api/settings", methods=["POST"])
def post_settings():
    data = request.get_json(force=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid settings format"}), 400

    # Validate and sanitise each field — never trust user input
    validated = {}

    # Booleans
    for key in ("block_on_critical", "block_on_high", "block_on_medium", "alert_on_domain"):
        if key in data:
            validated[key] = bool(data[key])

    # Integers with bounds
    if "proxy_port" in data:
        port = int(data["proxy_port"])
        validated["proxy_port"] = max(1024, min(65535, port))
    if "max_log_entries" in data:
        entries = int(data["max_log_entries"])
        validated["max_log_entries"] = max(100, min(10000, entries))

    # Lists of strings — validate each item is a non-empty string
    if "custom_patterns" in data:
        patterns = data["custom_patterns"]
        if isinstance(patterns, list):
            safe = []
            for p in patterns:
                if isinstance(p, str) and p.strip() and not p.strip().startswith("#"):
                    # Test compile the regex — reject invalid patterns
                    try:
                        import re
                        re.compile(p.strip())
                        safe.append(p.strip()[:200])  # cap length
                    except re.error:
                        pass  # silently skip invalid regex
            validated["custom_patterns"] = safe

    if "custom_blocked_domains" in data:
        domains = data["custom_blocked_domains"]
        if isinstance(domains, list):
            safe = [
                str(d).strip()[:100]
                for d in domains
                if isinstance(d, str) and d.strip()
            ]
            validated["custom_blocked_domains"] = safe

    if "allowed_folders" in data:
        folders = data["allowed_folders"]
        if isinstance(folders, list):
            safe = []
            for f in folders:
                if isinstance(f, str) and f.strip():
                    # Expand and validate the path exists
                    try:
                        p = Path(f.strip()).expanduser()
                        safe.append(str(p)[:500])
                    except Exception:
                        pass
            validated["allowed_folders"] = safe

    if "quiet_mode" in data:
        validated["quiet_mode"] = bool(data["quiet_mode"])

    saved = save_settings(validated)
    sig = Path.home() / ".coworkguard" / ".settings_updated"
    sig.touch()
    return jsonify({"ok": True, "settings": saved})




@app.route("/api/setup/open-full-disk-access", methods=["POST"])
def open_full_disk_access():
    """Open System Settings to Full Disk Access so user can grant permission."""
    import subprocess
    try:
        subprocess.Popen([
            "open",
            "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
        ])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/ble-status")
def ble_status():
    """Lightweight status endpoint for physical alert devices (ESP32 etc)."""
    settings = load_settings()
    entries = read_logs(limit=50)
    recent = [e for e in entries if e.get("timestamp", "") > (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")[:16]  # last ~60s approx
    )]
    critical = any(e.get("action") == "BLOCKED" for e in recent)
    flagged  = any(e.get("action") == "FLAGGED" for e in recent)
    proxy    = detect_proxy().get("running", False)

    if critical:
        return jsonify({"status": "BLOCKED", "colour": "red",   "flash": True})
    elif flagged:
        return jsonify({"status": "FLAGGED", "colour": "amber", "flash": False})
    elif proxy:
        return jsonify({"status": "CLEAN",   "colour": "green", "flash": False})
    else:
        return jsonify({"status": "OFF",     "colour": "off",   "flash": False})


@app.route("/api/folder-check", methods=["POST"])
def folder_check():
    """Check if a payload contains paths outside the allowed folders."""
    settings = load_settings()
    allowed = settings.get("allowed_folders", [])
    payload = request.get_json(force=True) or {}
    blocked_paths = check_payload_folders(payload, allowed)
    return jsonify({
        "ok": len(blocked_paths) == 0,
        "blocked_paths": blocked_paths,
        "allowed_folders": allowed,
    })



# Simple in-memory rate limiter for /api/log-event
_log_event_counts = {}  # {minute_str: count}

ALLOWED_EVENT_TYPES = {"WINDOW_AI_DETECTED", "SUSPICIOUS_API_WRAP", "DOMAIN_WARNING"}
LOG_EVENT_MAX_PER_MINUTE = 100


@app.route("/api/log-event", methods=["POST"])
def log_event():
    """
    Receive events from the Chrome extension and write them to the
    daily audit JSONL log so they appear in the dashboard.

    Used for:
      - WINDOW_AI_DETECTED  — Chrome Prompt API / window.ai usage
      - SUSPICIOUS_API_WRAP — malicious extension fetch/XHR wrapping
      - DOMAIN_WARNING      — sensitive domain navigation (supplement)
    """
    try:
        # Rate limit — max 100 events per minute
        minute = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        _log_event_counts[minute] = _log_event_counts.get(minute, 0) + 1
        # Clean up old minute keys
        for k in list(_log_event_counts):
            if k != minute:
                del _log_event_counts[k]
        if _log_event_counts[minute] > LOG_EVENT_MAX_PER_MINUTE:
            return jsonify({"ok": False, "error": "rate limit exceeded"}), 429

        event = request.get_json(force=True) or {}

        # Validate event type against known allowlist
        raw_type   = str(event.get("type", ""))[:64]
        event_type = raw_type if raw_type in ALLOWED_EVENT_TYPES else "CHROME_EVENT"

        severity   = str(event.get("severity", "MEDIUM"))[:16]
        action     = str(event.get("action", "FLAGGED"))[:32]
        url        = str(event.get("url", ""))[:500]

        # Validate timestamp — must parse as ISO 8601, otherwise use server time
        raw_ts = str(event.get("timestamp", ""))[:32]
        try:
            datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            timestamp = raw_ts
        except ValueError:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Build safe log entry — only known fields, no raw content
        entry = {
            "timestamp":  timestamp,
            "type":       event_type,
            "source":     "chrome_extension",
            "action":     action,
            "blocked":    action == "BLOCKED",
            "severity":   severity,
            "url":        url,
            "finding_count": 1,
            "findings": [{
                "type":     event_type,
                "severity": severity,
                "preview":  event_type,
                "blocked":  action == "BLOCKED",
            }],
        }

        # Include safe optional fields
        if "path" in event:
            entry["path"] = str(event["path"])[:64]
        if "domain" in event:
            entry["domain"] = str(event["domain"])[:128]
        if "fetchWrapped" in event:
            entry["fetchWrapped"] = bool(event["fetchWrapped"])
        if "xhrWrapped" in event:
            entry["xhrWrapped"] = bool(event["xhrWrapped"])
        if "message" in event:
            entry["message"] = str(event["message"])[:256]

        # Write to daily audit log
        log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/pending-requests")
def pending_requests():
    """Return list of requests held pending user confirmation."""
    try:
        if not HAS_PROXY:
            return jsonify({"pending": [], "count": 0})
        pending = _proxy.get_pending_requests()
        return jsonify({"pending": pending, "count": len(pending)})
    except Exception as e:
        return jsonify({"pending": [], "count": 0, "error": str(e)})


@app.route("/api/allow-request/<request_id>", methods=["POST"])
def allow_request(request_id: str):
    """
    Allow a held request to proceed.
    Sets the threading.Event in the proxy hook so the blocked flow resumes.
    """
    if not request_id or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        return jsonify({"ok": False, "error": "invalid request_id"}), 400
    try:
        if not HAS_PROXY:
            return jsonify({"ok": False, "error": "proxy not running"}), 503
        ok = _proxy.allow_request(request_id)
        if ok:
            app.logger.info(f"User allowed request {request_id[:8]}")
            return jsonify({"ok": True, "request_id": request_id})
        return jsonify({"ok": False, "error": "request not found or expired"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/clear", methods=["POST"])
def clear_logs():
    for lf in LOG_DIR.glob("audit_*.jsonl"):
        lf.unlink(missing_ok=True)
    return jsonify({"ok": True})


@app.route("/")
def index():
    dashboard = Path(__file__).parent / "dashboard.html"
    if dashboard.exists():
        return dashboard.read_text()
    return "<p>Dashboard not found — place dashboard.html next to server.py</p>", 404


if __name__ == "__main__":
    print("\n🛡️  CoworkGuard Server running at http://localhost:7070\n")
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)  # Suppress misleading "Running on 0.0.0.0" banner
    # Intentionally bound to 127.0.0.1 only — dashboard should never be
    # reachable from other machines on the network. If running in a cloud
    # dev environment (e.g. Gitpod), the platform's port forwarding handles
    # external access without exposing the server directly.
    app.run(host="127.0.0.1", port=7070, debug=False)
