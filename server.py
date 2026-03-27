"""
Copyright (c) 2026 [Katherine Weston]. All rights reserved.
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
import os
import glob
import subprocess
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

app = Flask(__name__)
# Restrict CORS to localhost only — prevents malicious pages from
# calling the API while the dashboard is open in another tab
CORS(app, origins=[
    "http://localhost:7070",
    "http://127.0.0.1:7070",
    "http://localhost:3000",   # dev convenience
])

LOG_DIR  = Path.home() / ".coworkguard" / "logs"
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
            cmd  = " ".join(proc.info["cmdline"] or [])
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
    clean   = sum(1 for e in entries if e.get("action") == "CLEAN")
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
            ts   = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            key  = ts.strftime("%Y-%m-%dT%H:00")
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
    setup_page = Path(__file__).parent / "setup.html"
    if setup_page.exists():
        return setup_page.read_text()
    return "<p>Setup page not found</p>", 404

@app.route("/api/setup/generate-cert", methods=["POST"])
def generate_cert():
    """Run mitmdump briefly to generate the mitmproxy CA certificate."""
    import subprocess, time
    try:
        p = subprocess.Popen(
            ["mitmdump", "--listen-port", "18765", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        p.terminate()
        p.wait(timeout=3)
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

@app.route("/api/status")
def status():
    return jsonify({
        "cowork":    detect_cowork(),
        "proxy":     detect_proxy(),
        "settings":  load_settings(),
        "server":    "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })

@app.route("/api/logs")
def logs():
    limit   = int(request.args.get("limit", 200))
    entries = read_logs(limit)
    return jsonify({
        "entries":       entries,
        "stats":         compute_stats(entries),
        "patternCounts": compute_pattern_counts(entries),
        "chartData":     compute_chart_data(entries),
        "total":         len(entries),
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

    saved = save_settings(validated)
    sig = Path.home() / ".coworkguard" / ".settings_updated"
    sig.touch()
    return jsonify({"ok": True, "settings": saved})

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
    app.run(host="127.0.0.1", port=7070, debug=False)
