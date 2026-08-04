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
import subprocess
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

# Core identity layer — actor stamping and session tracking
try:
    from core.identity.actor_stamper import stamp_event, update_registry, get_registry, pid_to_actor
    from core.identity.session_tracker import build_actor_registry_payload
    _IDENTITY_AVAILABLE = True
except ImportError:
    _IDENTITY_AVAILABLE = False

# Pro licence layer
try:
    from pro.licence.checker import get_tier, get_licence_info, is_pro
    _LICENCE_AVAILABLE = True
except ImportError:
    _LICENCE_AVAILABLE = False
    def get_tier(): return "free"
    def get_licence_info(): return {"tier":"free","email":None,"expires_at":None,"valid":False}
    def is_pro(): return False

# Pro startup — process scanner and file watcher
try:
    from pro.pro_startup import start_pro_components, stop_pro_components
    _PRO_STARTUP_AVAILABLE = True
except ImportError:
    _PRO_STARTUP_AVAILABLE = False
    def start_pro_components(*a, **kw): return {}
    def stop_pro_components(): pass

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

try:
    from actor_monitor.actor_registry import ActorRegistry
    _registry = ActorRegistry()
    HAS_REGISTRY = True
except Exception:
    _registry = None
    HAS_REGISTRY = False

app = Flask(__name__)

# The server binds to 127.0.0.1 only, but that alone is not a security
# boundary: DNS rebinding lets any website resolve a hostname to
# 127.0.0.1 and then send a browser request carrying its own Origin
# header. A wildcard CORS policy does not stop the server from
# *processing* that request — it only affects whether the attacker's
# JS can *read* the response. The real fix is to reject the request
# server-side before it's handled.
#
# Tauri's WKWebView origin is inconsistent across platforms/versions
# (tauri://localhost, https://tauri.localhost, null, or no Origin
# header at all), so we allowlist those explicitly rather than using
# origins="*".
_ALLOWED_ORIGINS = {
    "tauri://localhost",
    "https://tauri.localhost",
    "null",
}

CORS(app, origins=list(_ALLOWED_ORIGINS))


@app.before_request
def _reject_untrusted_origin():
    """
    Defence-in-depth against DNS rebinding: reject any request that
    carries an Origin header not in our allowlist. Requests with NO
    Origin header (direct navigation, curl, some Tauri webview calls)
    are allowed through — the attack this blocks specifically relies
    on cross-origin fetch()/XHR calls, which always send one.
    """
    origin = request.headers.get("Origin")
    if origin is not None and origin not in _ALLOWED_ORIGINS:
        return jsonify({"error": "origin not allowed"}), 403

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
    """Read all JSONL audit log files, newest entries first. Excludes dismissed events."""
    dismissed_file = Path.home() / ".coworkguard" / "dismissed_events.json"
    dismissed = set()
    if dismissed_file.exists():
        try:
            dismissed = set(json.loads(dismissed_file.read_text()))
        except Exception:
            pass
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
    # Filter dismissed events
    entries = [e for e in entries if e.get("timestamp","") not in dismissed]
    return entries[:limit]


def update_audit_entry(timestamp: str, updates: dict):
    """Find the audit log entry with the given timestamp and merge updates into it.
    Rewrites only the affected line — leaves all other entries untouched."""
    if not timestamp:
        return
    log_files = sorted(LOG_DIR.glob("audit_*.jsonl"), reverse=True)
    for lf in log_files[:3]:  # only check last 3 days
        try:
            lines = lf.read_text().splitlines()
            changed = False
            new_lines = []
            for line in lines:
                if not line.strip():
                    new_lines.append(line)
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("timestamp") == timestamp:
                        entry.update(updates)
                        new_lines.append(json.dumps(entry))
                        changed = True
                    else:
                        new_lines.append(line)
                except json.JSONDecodeError:
                    new_lines.append(line)
            if changed:
                lf.write_text("\n".join(new_lines) + "\n")
                return
        except Exception:
            pass


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
            ai_web_apps = data.get("ai_web_apps", [])
            ai_api_domains = data.get("ai_api_domains", [])
            return jsonify({
                "sensitive_domains": all_domains,
                "ai_web_apps": ai_web_apps,
                "ai_api_domains": ai_api_domains
            })
        except Exception:
            pass
    return jsonify({"sensitive_domains": []})



@app.route("/api/port-check", methods=["GET"])
def port_check():
    """Check if the proxy port is free or in use by another process."""
    try:
        import subprocess as sp
        port = load_settings().get("proxy_port", 8080)
        result = sp.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=3)
        pids = [p.strip() for p in result.stdout.strip().split() if p.strip().isdigit()]
        if not pids:
            return jsonify({"ok": True, "port": port, "conflict": False})
        # Get process name for the conflicting PID
        proc_result = sp.run(["ps", "-p", pids[0], "-o", "comm="], capture_output=True, text=True, timeout=3)
        proc_name = proc_result.stdout.strip().split("/")[-1] if proc_result.stdout.strip() else "another app"
        return jsonify({"ok": True, "port": port, "conflict": True, "pids": pids, "process": proc_name})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/kill-port", methods=["POST"])
def kill_port():
    """Kill the process using the proxy port so CoworkGuard can start."""
    try:
        import subprocess as sp, signal as sig
        port = load_settings().get("proxy_port", 8080)
        result = sp.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=3)
        pids = [int(p.strip()) for p in result.stdout.strip().split() if p.strip().isdigit()]
        if not pids:
            return jsonify({"ok": True, "message": "Port is already free"})
        killed = []
        for pid in pids:
            try:
                import os
                os.kill(pid, sig.SIGTERM)
                killed.append(pid)
                app.logger.info(f"Killed PID {pid} to free port {port}")
            except ProcessLookupError:
                pass
            except PermissionError:
                return jsonify({"ok": False, "error": "Permission denied — try restarting CoworkGuard as admin"}), 403
        return jsonify({"ok": True, "killed": killed, "port": port})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



# ─────────────────────────────────────────────
# Core Identity — Actor Registry
# ─────────────────────────────────────────────

@app.route("/api/actor-registry", methods=["POST"])
def post_actor_registry():
    """
    Receive actor registry snapshot from actor_monitor / agent_guard.
    Called on every scan cycle. Updates in-memory registry for event stamping.
    """
    if not _IDENTITY_AVAILABLE:
        return jsonify({"ok": False, "error": "identity layer not available"}), 503
    try:
        data = request.get_json(force=True) or {}
        actors = data.get("actors", [])
        if not isinstance(actors, list):
            return jsonify({"ok": False, "error": "actors must be a list"}), 400
        update_registry(actors)
        return jsonify({"ok": True, "count": len(actors)})
    except Exception as e:
        app.logger.error("post_actor_registry error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/actor-registry", methods=["GET"])
def get_actor_registry():
    """Return current actor registry. Used by dashboard correlation engine."""
    if not _IDENTITY_AVAILABLE:
        return jsonify({"ok": True, "actors": [], "count": 0})
    try:
        registry = get_registry()
        actors = list(registry.values())
        return jsonify({"ok": True, "actors": actors, "count": len(actors)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/actor/<int:pid>", methods=["GET"])
def get_actor_by_pid(pid):
    """Return actor metadata for a specific PID. Used by dashboard event detail."""
    if not _IDENTITY_AVAILABLE:
        return jsonify({"ok": False, "error": "identity layer not available"}), 503
    try:
        actor = pid_to_actor(pid)
        if not actor:
            return jsonify({"ok": False, "error": f"No actor found for PID {pid}"}), 404
        return jsonify({"ok": True, "actor": actor})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



# ─────────────────────────────────────────────
# Pro — Developer Environment Protection
# ─────────────────────────────────────────────

@app.route("/api/dev-env-event", methods=["POST"])
def dev_env_event():
    """
    Receive DEV_ENV_ACCESS events from process_scanner.py and file_watcher.py.
    Stamps actor identity, writes to audit log, appears in dashboard.

    Events fired when AI processes access:
      - .env files, SSH keys, AWS credentials, GitHub tokens
      - Kubernetes config, Docker credentials, cloud configs
      - AI tool configs (Claude, Cursor, VS Code)
      - MCP configurations, local vector stores
    """
    try:
        data = request.get_json(force=True) or {}

        if data.get("type") != "DEV_ENV_ACCESS":
            return jsonify({"ok": False, "error": "expected type DEV_ENV_ACCESS"}), 400

        # Build audit entry — calm, observational language
        entry = {
            "timestamp":      data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "type":           "DEV_ENV_ACCESS",
            "source":         data.get("source", "dev_env"),
            "action":         "FLAGGED",
            "blocked":        False,
            "severity":       data.get("severity", "MEDIUM"),
            "finding_count":  1,

            # What was accessed
            "path":           data.get("path", ""),
            "url":            data.get("path_short", data.get("path", "")),
            "event_subtype":  data.get("event_subtype", ""),
            "label":          data.get("label", "Sensitive file accessed"),
            "description":    data.get("description", ""),
            "category":       data.get("category", ""),
            "tags":           data.get("tags", []),
            "change_type":    data.get("change_type", ""),

            # Actor identity — may already be stamped by process_scanner
            "actor_id":       data.get("actor_id", ""),
            "bundle_id":      data.get("bundle_id", ""),
            "pid":            data.get("pid"),
            "display_name":   data.get("display_name", ""),
            "actor_name":     data.get("display_name", data.get("actor_name", "")),
            "session_id":     data.get("session_id", ""),
            "confidence":     data.get("confidence", "none"),

            # Findings for dashboard detail view
            "findings": data.get("findings", [{
                "type":     data.get("event_subtype", "DEV_ENV_ACCESS"),
                "severity": data.get("severity", "MEDIUM"),
                "preview":  data.get("path_short", ""),
                "blocked":  False,
                "label":    data.get("label", ""),
            }]),
        }

        # Stamp actor identity if not already confirmed
        if entry.get("confidence") != "strong" and _IDENTITY_AVAILABLE:
            entry = stamp_event(entry)

        # Write to audit log
        log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

        app.logger.info(
            "DEV_ENV_ACCESS [%s] %s — %s",
            entry.get("actor_name", "?"),
            entry.get("label", "?"),
            entry.get("path", "?")[:60],
        )

        return jsonify({"ok": True})

    except Exception as e:
        app.logger.error("dev_env_event error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500


# ─────────────────────────────────────────────
# Pro — Licence
# ─────────────────────────────────────────────

@app.route("/api/licence", methods=["GET"])
def get_licence():
    """
    Returns current licence tier and info.
    Used by dashboard to gate Pro UI elements.
    Safe to expose — no signing secret returned.
    """
    try:
        info = get_licence_info()
        return jsonify({"ok": True, **info})
    except Exception as e:
        return jsonify({"ok": True, "tier": "free", "valid": False})


@app.route("/api/licence", methods=["POST"])
def activate_licence():
    """
    Activate a licence by writing it to ~/.coworkguard/licence.json.
    Called when a user pastes their licence key into the dashboard.
    """
    try:
        data = request.get_json(force=True) or {}
        licence_data = data.get("licence")
        if not licence_data or not isinstance(licence_data, dict):
            return jsonify({"ok": False, "error": "licence object required"}), 400

        from pro.licence.checker import _verify_signature, _is_expired, LICENCE_FILE  # local ok — not stamper
        required = {"tier", "key", "email", "issued_at", "expires_at", "signature"}
        if not required.issubset(licence_data.keys()):
            return jsonify({"ok": False, "error": "invalid licence format"}), 400
        if not _verify_signature(licence_data):
            return jsonify({"ok": False, "error": "invalid licence signature"}), 400
        if _is_expired(licence_data["expires_at"]):
            return jsonify({"ok": False, "error": "licence has expired"}), 400

        LICENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENCE_FILE.write_text(json.dumps(licence_data, indent=2))

        app.logger.info("Licence activated: %s tier for %s",
                        licence_data["tier"], licence_data["email"])
        return jsonify({"ok": True, "tier": licence_data["tier"],
                        "email": licence_data["email"]})
    except Exception as e:
        app.logger.error("activate_licence error: %s", e)
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/pro-status", methods=["GET"])
def pro_status():
    """Returns status of Pro background components."""
    try:
        from pro.dev_env.process_scanner import _running as scanner_running
    except Exception:
        scanner_running = False
    try:
        from pro.dev_env.file_watcher import is_running as watcher_running
        watcher_ok = watcher_running()
    except Exception:
        watcher_ok = False
    return jsonify({
        "ok": True,
        "tier": get_tier(),
        "process_scanner": scanner_running,
        "file_watcher": watcher_ok,
    })

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
    for key in ("block_on_critical", "block_on_high", "block_on_medium", "alert_on_domain", "confirm_before_send", "quiet_mode"):
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

ALLOWED_EVENT_TYPES = {"WINDOW_AI_DETECTED", "SUSPICIOUS_API_WRAP", "DOMAIN_WARNING", "AI_SESSION_STARTED", "AI_SESSION_ENDED", "LOCAL_MODEL_DOWNLOADED",
    "DEV_ENV_ACCESS", "LOCAL_MODEL_DOWNLOADING", "LOCAL_MODEL_UPDATED", "LOCAL_MODEL_REMOVED"}
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
        if "app_name" in event:
            entry["app_name"] = str(event["app_name"])[:64]
        if "app_id" in event:
            entry["app_id"] = str(event["app_id"])[:64]
        if "actor_name" in event:
            entry["actor_name"] = str(event["actor_name"])[:64]
        if "ai_provider" in event:
            entry["ai_provider"] = str(event["ai_provider"])[:64]
        if "tab_id" in event:
            entry["tab_id"] = str(event["tab_id"])[:64]
        if "pid" in event:
            try:
                entry["pid"] = int(event["pid"])
            except (ValueError, TypeError):
                pass

        # Stamp actor identity before writing — enriches correlation quality
        if _IDENTITY_AVAILABLE:
            source_port = entry.pop("source_port", None)
            entry = stamp_event(entry, source_port=source_port)

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





@app.route("/api/stop-download", methods=["POST"])
def stop_download():
    """Stop a model download without killing the parent app.

    Strategy (in order):
    1. If a file path is provided, use lsof to find the specific PID that
       has that file open and kill only that process. This stops the download
       worker without touching the parent service (e.g. ollama server keeps
       running, only the pull subprocess is killed).
    2. Fall back to killing by actor process name if no path is given or
       lsof finds nothing — last resort, kills the whole app.
    """
    data = request.get_json(force=True) or {}
    actor_id = str(data.get("actor_id", ""))[:50]
    path_str = str(data.get("path", ""))[:500]
    timestamp = str(data.get("timestamp", ""))[:50]  # original event timestamp

    if not actor_id and not path_str:
        return jsonify({"ok": False, "error": "no actor_id or path"}), 400

    try:
        killed = []

        # ── Strategy 1: kill only the PID with the file open ──────────────
        if path_str:
            try:
                lsof = subprocess.run(
                    ["lsof", "-t", path_str],
                    capture_output=True, text=True, timeout=5
                )
                pids = [int(p) for p in lsof.stdout.split() if p.strip().isdigit()]
                for pid in pids:
                    try:
                        proc = psutil.Process(pid)
                        proc.kill()
                        killed.append(pid)
                        app.logger.info(
                            "Killed PID %d (%s) — had download file open: %s",
                            pid, proc.name(), path_str
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # lsof not available or timed out — fall through

        # ── Strategy 2: fall back to killing by process name ──────────────
        if not killed and actor_id and HAS_PSUTIL:
            actor = _registry.get_actor(actor_id) if _registry else None
            proc_names = actor.process_names if actor else [actor_id]
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    name = proc.info["name"] or ""
                    if any(n.lower() in name.lower() for n in proc_names):
                        cmdline = " ".join(proc.info.get("cmdline") or [])
                        if "XPCServices" in cmdline or "PrivateFrameworks" in cmdline:
                            continue
                        proc.kill()
                        killed.append(proc.info["pid"])
                        app.logger.warning(
                            "Killed entire process %s (PID %d) — no specific download PID found",
                            name, proc.info["pid"]
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Always persist the block decision regardless of whether a process
        # was killed. If lsof found nothing (download already finished or
        # Ollama moved to a new temp file), the user still intends to block
        # future downloads — write the directory to blocked_downloads.json
        # so file_write_monitor suppresses all retries in that directory.
        if path_str:
            try:
                block_file = Path.home() / ".coworkguard" / "blocked_downloads.json"
                block_file.parent.mkdir(parents=True, exist_ok=True)
                existing = []
                if block_file.exists():
                    try:
                        existing = json.loads(block_file.read_text())
                    except Exception:
                        existing = []
                # Store the parent directory so all retries in the same
                # directory are suppressed, not just the exact filename.
                block_dir = str(Path(path_str).parent)
                if block_dir not in existing:
                    existing.append(block_dir)
                existing = existing[-200:]
                block_file.write_text(json.dumps(existing))
            except Exception:
                pass

        # Update the audit log entry regardless of kill success so the
        # activity panel always reflects the user's decision.
        if timestamp:
            update_audit_entry(timestamp, {
                "action": "BLOCKED",
                "blocked": True,
                "outcome": "user_stopped",
                "outcome_at": datetime.now(timezone.utc).isoformat(),
            })

        if killed:
            return jsonify({"ok": True, "killed_pids": killed})
        # Process not found but block decision was persisted — still ok
        return jsonify({"ok": True, "killed_pids": [], "note": "Process already finished — download blocked for future attempts"})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/allow-download", methods=["POST"])
def allow_download():
    """Allow a flagged model download to proceed without further alerts."""
    data = request.get_json(force=True) or {}
    path_str = str(data.get("path", ""))[:500]
    timestamp = str(data.get("timestamp", ""))[:50]
    if not path_str:
        return jsonify({"ok": False, "error": "no path"}), 400
    try:
        allow_file = Path.home() / ".coworkguard" / "allowed_downloads.json"
        allow_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if allow_file.exists():
            try:
                existing = json.loads(allow_file.read_text())
            except Exception:
                existing = []
        if path_str not in existing:
            existing.append(path_str)
        existing = existing[-200:]
        allow_file.write_text(json.dumps(existing))
        # Update the original audit log entry so the activity panel shows
        # the outcome and hides the Allow/Stop buttons.
        if timestamp:
            update_audit_entry(timestamp, {
                "action": "ALLOWED",
                "blocked": False,
                "outcome": "user_allowed",
                "outcome_at": datetime.now(timezone.utc).isoformat(),
            })
        app.logger.info("User allowed download: %s", path_str)
        return jsonify({"ok": True, "path": path_str})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# In-memory session state — updated by Chrome extension
_active_sessions: dict = {}  # app_id -> {name, url, last_seen}

@app.route("/api/sessions", methods=["GET"])
def get_sessions():
    """Return currently open AI browser sessions."""
    import time
    now = time.time()
    # Sessions are considered active if seen within last 15 seconds
    sessions = []
    for app_id, info in sorted(_active_sessions.items(), key=lambda x: x[1].get("name","")):
        active = (now - info.get("last_seen", 0)) < 15
        sessions.append({
            "app_id": app_id,
            "name": info.get("name", app_id),
            "url": info.get("url", ""),
            "active": active
        })
    # Only show active ones
    sessions = [s for s in sessions if s["active"]]
    return jsonify({"sessions": sessions})


@app.route("/api/sessions", methods=["POST"])
def update_sessions():
    """Called by Chrome extension every 5s with currently open AI tabs."""
    import time
    data = request.get_json(force=True) or {}
    open_apps = data.get("open_apps", [])
    now = time.time()
    # Update last_seen for open apps
    for app in open_apps:
        app_id = str(app.get("id", ""))[:50]
        if app_id:
            _active_sessions[app_id] = {
                "name": str(app.get("name", app_id))[:50],
                "url": str(app.get("url", ""))[:100],
                "last_seen": now
            }
    return jsonify({"ok": True})


@app.route("/api/dismiss-event", methods=["POST"])
def dismiss_event():
    """Mark an event as reviewed — persists across poll cycles."""
    data = request.get_json(force=True) or {}
    timestamp = str(data.get("timestamp", ""))[:50]
    if not timestamp:
        return jsonify({"ok": False, "error": "no timestamp"}), 400
    try:
        dismissed_file = Path.home() / ".coworkguard" / "dismissed_events.json"
        dismissed_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if dismissed_file.exists():
            try:
                existing = json.loads(dismissed_file.read_text())
            except Exception:
                existing = []
        if timestamp not in existing:
            existing.append(timestamp)
        existing = existing[-500:]
        dismissed_file.write_text(json.dumps(existing))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/block-request/<request_id>", methods=["POST"])
def block_request(request_id: str):
    """Immediately block a held request."""
    if not request_id or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        return jsonify({"ok": False, "error": "invalid request_id"}), 400
    try:
        block_file = Path.home() / ".coworkguard" / "pending_block.json"
        block_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if block_file.exists():
            try:
                existing = json.loads(block_file.read_text())
            except Exception:
                existing = []
        existing.append({
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        block_file.write_text(json.dumps(existing))
        app.logger.info(f"User blocked request {request_id[:8]}")
        return jsonify({"ok": True, "request_id": request_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/allow-request/<request_id>", methods=["POST"])
def allow_request(request_id: str):
    """
    Allow a held request to proceed.
    Writes to a shared file that proxy.py polls — works across separate processes.
    """
    if not request_id or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        return jsonify({"ok": False, "error": "invalid request_id"}), 400
    try:
        allow_file = Path.home() / ".coworkguard" / "pending_allow.json"
        allow_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if allow_file.exists():
            try:
                existing = json.loads(allow_file.read_text())
            except Exception:
                existing = []
        existing.append({
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        allow_file.write_text(json.dumps(existing))
        app.logger.info(f"User allowed request {request_id[:8]}")
        return jsonify({"ok": True, "request_id": request_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500




@app.route("/api/file-preview", methods=["POST"])
def file_preview():
    """Return sensitive lines from a flagged file so the user can judge if it is a real issue."""
    data = request.get_json(force=True) or {}
    path_str = str(data.get("path", ""))[:500]
    if not path_str:
        return jsonify({"ok": False, "error": "no path provided"}), 400
    try:
        path = Path(path_str).expanduser().resolve()
        if not path.exists() or not path.is_file():
            return jsonify({"ok": False, "error": "file not found"}), 404
        if path.stat().st_size > 100 * 1024:
            return jsonify({"ok": False, "error": "file too large to preview"}), 400
        lines = path.read_text(errors="replace").splitlines()
        keywords = ["api", "key", "secret", "token", "password", "credential",
                    "ssn", "aws", "private", "auth", "jwt", "bearer"]
        flagged = [f"Line {i+1}: {line[:120]}"
                   for i, line in enumerate(lines)
                   if any(k in line.lower() for k in keywords)]
        return jsonify({"ok": True, "lines": (flagged or lines[:10])[:20]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/remove-model-file", methods=["POST"])
def remove_model_file():
    """Delete a local AI model file at user request."""
    data = request.get_json(force=True) or {}
    path_str = str(data.get("path", ""))[:500]
    if not path_str:
        return jsonify({"ok": False, "error": "no path provided"}), 400
    try:
        path = Path(path_str).expanduser().resolve()
        ALLOWED_PARENTS = [
            Path.home() / "Library" / "Application Support" / "Google",
            Path.home() / "Library" / "Application Support" / "BraveSoftware",
            Path.home() / "Library" / "Application Support" / "Microsoft Edge",
            Path.home() / ".ollama" / "models",
            Path.home() / ".lmstudio",
        ]
        if not any(path == p or p in path.parents for p in ALLOWED_PARENTS):
            return jsonify({"ok": False, "error": "path outside allowed AI app directories"}), 403
        if not path.exists():
            return jsonify({"ok": False, "error": "file not found"}), 404
        if not path.is_file():
            return jsonify({"ok": False, "error": "path is not a file"}), 400
        path.unlink()
        app.logger.info("Model file removed by user: %s", path)
        log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "LOCAL_MODEL_REMOVED", "source": "user_action",
            "action": "ALLOWED", "blocked": False, "severity": "LOW",
            "url": str(path), "finding_count": 0, "findings": [],
        }
        with open(log_file, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        return jsonify({"ok": True, "path": str(path)})
    except PermissionError:
        return jsonify({"ok": False, "error": "permission denied — file may be in use"}), 403
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/open-url", methods=["POST"])
def open_url():
    """Open a URL or app settings page using macOS open command."""
    data = request.get_json(force=True) or {}
    url = str(data.get("url", ""))[:500]
    ALLOWED_SCHEMES = [
        "googlechrome://", "brave://", "microsoft-edge://",
        "x-apple.systempreferences:",
        "claude://",
        "cursor://",
        "windsurf://",
        "http://localhost",
        "http://127.0.0.1",
        "file://",
    ]
    if not any(url.startswith(s) for s in ALLOWED_SCHEMES):
        return jsonify({"ok": False, "error": "URL scheme not allowed"}), 403
    try:
        subprocess.Popen(["open", url])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/actors")
def get_actors():
    """Return running AI actor processes for the Agent Guard dashboard."""
    if not HAS_PSUTIL or not HAS_REGISTRY:
        return jsonify({"actors": [], "count": 0})
    try:
        # Clear psutil's process cache so we get a fresh snapshot, not stale data
        # from a previous poll cycle where a process may have just quit.
        psutil._pmap = {}

        running = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status']):
            try:
                # Skip zombie/dead processes — these are processes that have exited
                # but haven't been reaped yet. They show up in the process list but
                # are no longer running.
                status = proc.info.get('status', '')
                if status in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD):
                    continue

                name = proc.info['name'] or ''
                cmdline = ' '.join(proc.info.get('cmdline') or [])

                # Skip macOS system XPC services and private frameworks
                if any(x in cmdline for x in ('XPCServices','PrivateFrameworks','SafeBrowsing.Service','SafariPlatformSupport','SafariBookmarksSyncAgent','SafariNotificationAgent','SafariLaunchAgent','Safari.History')):
                    continue

                # Skip helper/renderer subprocesses — these linger after the parent
                # app quits and cause false positives (e.g. "Safari Web Content"
                # persisting after Safari is closed). Only match the main process
                # by requiring the process to either be a session leader or have a
                # parent that is also a matched actor or launchd (pid 1).
                is_helper = any(s in name for s in (
                    'Web Content', 'Helper', 'Renderer', 'GPU Process',
                    'Network', 'Plugin', 'Extension', 'crashpad',
                ))
                if is_helper:
                    try:
                        parent = proc.parent()
                        if parent is None or parent.pid == 1:
                            # Orphaned helper with no real parent — skip
                            continue
                        parent_name = parent.name() or ''
                        # Only keep helper if its parent is itself a matched actor
                        parent_actor = _registry.match_process(name=parent_name)
                        if not parent_actor:
                            continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Resolve parent name for MCP tool matching (python_mcp, node_mcp)
                try:
                    parent = proc.parent()
                    parent_name = parent.name() if parent else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = None

                actor = _registry.match_process(name=name, parent_actor_id=parent_name)
                if actor:
                    running.append({
                        "actor_id": actor.actor_id,
                        "display_name": actor.display_name,
                        "pid": proc.info['pid'],
                        "running": True,
                        "capabilities": actor.capabilities,
                        "risk": "low", "permissions": [],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        seen = set()
        deduped = [a for a in running if not (a['actor_id'] in seen or seen.add(a['actor_id']))]
        return jsonify({"actors": deduped, "count": len(deduped)})
    except Exception as e:
        return jsonify({"actors": [], "count": 0, "error": str(e)})



@app.route("/api/clear-skill-scans", methods=["POST"])
def clear_skill_scans():
    """Delete all skill scan history files."""
    try:
        deleted = 0
        for f in LOG_DIR.glob("skill_scan_*.jsonl"):
            f.unlink()
            deleted += 1
        app.logger.info("Cleared %d skill scan files", deleted)
        return jsonify({"ok": True, "deleted": deleted})
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
    # Start Pro background components if licence is active
    if _PRO_STARTUP_AVAILABLE:
        def _get_registry():
            try:
                return get_registry()
            except Exception:
                return {}
        import threading
        def _deferred_pro_start():
            import time
            time.sleep(3)  # wait for server to be fully up
            pro_status = start_pro_components(_get_registry)
            if pro_status.get("licence_tier") != "free":
                print(f"  Pro components: scanner={pro_status.get('process_scanner')} watcher={pro_status.get('file_watcher')}")
        threading.Thread(target=_deferred_pro_start, daemon=True,
                        name="coworkguard-pro-init").start()

    app.run(host="127.0.0.1", port=7070, debug=False)
