"""
Copyright (c) 2026 Katherine Weston. All rights reserved.
Licensed under MIT with Commons Clause — see LICENSE for details.

CoworkGuard - File Write Monitor
Watches the filesystem for files written outside the user's allowed
folders. Warns when AI tools write sensitive data to unexpected locations.

Runs as a background process launched by the menubar app.
Uses watchdog for efficient filesystem event monitoring.
"""

import json
import logging
import subprocess
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from scanner import CoworkScanner

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

LOG_DIR = Path.home() / ".coworkguard" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = Path.home() / ".coworkguard" / "settings.json"

# Directories to always watch for unexpected writes
WATCH_DIRS = [
    Path.home(),
    Path("/tmp"),
]

# Paths to always ignore — system noise
IGNORE_PATHS = {
    ".coworkguard",
    ".cache",
    ".Trash",
    "Library/Caches",
    "Library/Logs",
    "Library/Application Support",
    ".DS_Store",
    "__pycache__",
    ".git",
    "node_modules",
    ".npm",
    ".pyc",
}

# File extensions worth scanning
SCAN_EXTENSIONS = {
    ".txt", ".md", ".json", ".yaml", ".yml", ".env",
    ".log", ".csv", ".xml", ".toml", ".ini", ".cfg",
    ".sh", ".py", ".js", ".ts", ".rb", ".go",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CoworkGuard FileWatch] %(message)s"
)
log = logging.getLogger("coworkguard.filewatch")

scanner = CoworkScanner(block_on_critical=False, block_on_high=False)


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


def is_ignored(path: Path) -> bool:
    """Return True if path should be ignored."""
    path_str = str(path)
    for ignore in IGNORE_PATHS:
        if ignore in path_str:
            return True
    return False


def is_outside_allowed(path: Path, allowed_folders: list) -> bool:
    """Return True if path is outside all allowed folders."""
    if not allowed_folders:
        return False  # no restriction configured
    for folder in allowed_folders:
        try:
            allowed = Path(folder).expanduser().resolve()
            path.resolve().relative_to(allowed)
            return False  # path is inside this allowed folder
        except ValueError:
            continue
    return True  # outside all allowed folders


def write_file_alert(path: Path, findings: list, reason: str):
    """Write a file write alert to the daily audit log."""
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "FILE_WRITE_WARNING",
        "action": "FLAGGED",
        "blocked": False,
        "url": str(path),
        "payload_hash": hashlib.sha256(str(path).encode()).hexdigest()[:16],
        "payload_size_bytes": 0,
        "reason": reason,
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


def show_notification(path: Path, reason: str):
    """Show a macOS notification."""
    filename = path.name
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "File written outside allowed folders: {filename}" '
            f'with title "⚠️ CoworkGuard" subtitle "File Write Warning"'
        ], timeout=3)
    except Exception:
        pass


# ─────────────────────────────────────────────
# Event handler
# ─────────────────────────────────────────────

class CoworkGuardFileHandler(FileSystemEventHandler):

    def __init__(self):
        self._recent: Set[str] = set()  # debounce duplicate events

    def _handle(self, path_str: str):
        path = Path(path_str)

        # Skip ignored paths
        if is_ignored(path):
            return

        # Skip non-scannable extensions
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            return

        # Debounce — skip if we've seen this path in the last 5 seconds
        key = str(path)
        if key in self._recent:
            return
        self._recent.add(key)
        # Clean up debounce set after delay
        import threading
        threading.Timer(5.0, lambda: self._recent.discard(key)).start()

        settings = load_settings()

        # Respect quiet mode
        if settings.get("quiet_mode", False):
            return

        allowed_folders = settings.get("allowed_folders", [])

        # Check if file is outside allowed folders
        outside = is_outside_allowed(path, allowed_folders)

        # Scan file content for sensitive data
        findings = []
        try:
            if path.exists() and path.stat().st_size < 512 * 1024:  # max 512KB
                content = path.read_text(encoding="utf-8", errors="replace")
                result = scanner.scan(content)
                findings = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH")]
        except Exception:
            pass

        # Alert if outside allowed folders AND contains sensitive data
        if outside and findings:
            types = ", ".join(set(f.pattern_name for f in findings))
            reason = f"outside allowed folders + contains {types}"
            log.warning("FILE_WRITE_WARNING: %s — %s", path, reason)
            write_file_alert(path, findings, reason)
            show_notification(path, reason)

        # Alert if sensitive data written anywhere unexpected (even inside allowed)
        elif findings and not allowed_folders:
            types = ", ".join(set(f.pattern_name for f in findings))
            reason = f"contains sensitive data: {types}"
            log.info("FILE_WRITE_SENSITIVE: %s — %s", path, reason)
            write_file_alert(path, findings, reason)

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    if not HAS_WATCHDOG:
        log.error("watchdog not installed — file write monitoring unavailable")
        log.error("Run: pip install watchdog")
        # Poll fallback — just keep alive so main.rs doesn't restart us
        while True:
            time.sleep(60)
        return

    handler = CoworkGuardFileHandler()
    observer = Observer()

    for watch_dir in WATCH_DIRS:
        if watch_dir.exists():
            observer.schedule(handler, str(watch_dir), recursive=True)
            log.info("Watching: %s", watch_dir)

    observer.start()
    log.info("File write monitor started")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
