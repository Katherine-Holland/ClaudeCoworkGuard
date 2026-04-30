"""
Copyright (c) 2026 Katherine Weston. All rights reserved.
Licensed under MIT with Commons Clause — see LICENSE for details.

CoworkGuard - Clipboard Monitor
Watches the macOS clipboard for sensitive data patterns and logs
warnings when detected. Does not modify or block clipboard content —
awareness only.

Runs as a background process launched by the menubar app.
Polls every 2 seconds using pbpaste (macOS built-in, no extra deps).
"""

import json
import subprocess
import sys
import time
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from scanner import CoworkScanner

if sys.platform != "darwin":
    print(f"[CoworkGuard] clipboard_monitor is macOS-only (running on {sys.platform}) — exiting.")
    sys.exit(0)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

POLL_INTERVAL = 2.0          # seconds between clipboard checks
LOG_DIR = Path.home() / ".coworkguard" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = Path.home() / ".coworkguard" / "settings.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CoworkGuard Clipboard] %(message)s"
)
log = logging.getLogger("coworkguard.clipboard")

# ─────────────────────────────────────────────
# Scanner — reuse core engine, CRITICAL + HIGH only
# Clipboard is noisy — don't flag emails/IPs
# ─────────────────────────────────────────────

scanner = CoworkScanner(
    block_on_critical=False,  # can't block clipboard — awareness only
    block_on_high=False,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def get_clipboard() -> str:
    """Read clipboard contents using pbpaste (macOS built-in)."""
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.stdout or ""
    except Exception:
        return ""


def clipboard_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def write_clipboard_alert(text: str, findings: list):
    """Write a clipboard alert to the daily JSONL log."""
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "CLIPBOARD_WARNING",
        "action": "FLAGGED",
        "blocked": False,
        "payload_hash": clipboard_hash(text),
        "payload_size_bytes": len(text.encode("utf-8")),
        "finding_count": len(findings),
        "findings": [
            {
                "type": f.pattern_name,
                "severity": f.severity,
                "preview": f.match_preview,
                "blocked": False,
            }
            for f in findings
        ],
    }
    with open(log_file, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def show_notification(findings: list):
    """Show a macOS notification using osascript."""
    types = ", ".join(set(f.pattern_name for f in findings))
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "Sensitive data in clipboard: {types}" '
            f'with title "⚠️ CoworkGuard" subtitle "Clipboard Warning"'
        ], timeout=3)
    except Exception:
        pass


# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────

def main():
    log.info("Clipboard monitor started — polling every %.1fs", POLL_INTERVAL)
    last_hash = ""
    last_alert_hash = ""  # prevent repeat alerts for same content

    while True:
        try:
            settings = load_settings()

            # Respect quiet mode
            if settings.get("quiet_mode", False):
                time.sleep(POLL_INTERVAL)
                continue

            text = get_clipboard()
            if not text or len(text) < 8:
                time.sleep(POLL_INTERVAL)
                continue

            h = clipboard_hash(text)

            # Skip if clipboard hasn't changed
            if h == last_hash:
                time.sleep(POLL_INTERVAL)
                continue
            last_hash = h

            # Scan clipboard content
            result = scanner.scan(text)

            # Only alert on CRITICAL and HIGH — skip MEDIUM to avoid noise
            serious = [
                f for f in result.findings
                if f.severity in ("CRITICAL", "HIGH")
            ]

            if serious and h != last_alert_hash:
                last_alert_hash = h
                types = ", ".join(set(f.pattern_name for f in serious))
                log.warning(
                    "Clipboard contains sensitive data: %s (%d finding%s)",
                    types, len(serious), "s" if len(serious) != 1 else ""
                )
                write_clipboard_alert(text, serious)
                show_notification(serious)

        except Exception as e:
            log.error("Clipboard monitor error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
