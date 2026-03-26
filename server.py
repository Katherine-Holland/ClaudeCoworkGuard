"""
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
CORS(app)  # Allow dashboard (file:// or localhost) to call this

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
    if not HAS_PSUTIL:
        return {"running": False, "reason": "psutil not installed"}
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr.port == port and conn.status == "LISTEN":
            return {"running": True, "port": port}
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
    saved = save_settings(data)
    # Write a signal file so proxy.py can hot-reload settings
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
    app.run(host="127.0.0.1", port=7070, debug=False)

#Copyright (c) 2026 [Katherine Weston]. All rights reserved.
#Licensed under MIT with Commons Clause — see LICENSE for details.
#Commercial use prohibited without a separate commercial license.