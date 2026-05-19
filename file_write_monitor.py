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

# File extensions worth scanning for sensitive text content
SCAN_EXTENSIONS = {
    ".txt", ".md", ".json", ".yaml", ".yml", ".env",
    ".log", ".csv", ".xml", ".toml", ".ini", ".cfg",
    ".sh", ".py", ".js", ".ts", ".rb", ".go",
}

# Model file extensions — trigger download alerts regardless of content
MODEL_EXTENSIONS = {".gguf", ".bin", ".safetensors", ".ggml", ".pt", ".pth", ".onnx"}

# Paths that indicate a model download is in progress
MODEL_WATCH_PATHS = [
    ".ollama/models",
    "Library/Application Support/LM Studio",
    "Library/Application Support/Msty",
    "Library/Application Support/AnythingLLM",
    "Library/Application Support/Jan",
    "Library/Application Support/GPT4All",
    ".cache/huggingface",
    ".cache/lm-studio",
]

# Partial/in-progress download suffixes used by various tools
PARTIAL_SUFFIXES = {".part", ".partial", ".download", ".tmp", ".crdownload", "-partial"}

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
    """Return True if path should be ignored.
    Model paths are checked first — they must never be ignored even if
    they happen to live inside Library/Application Support or .cache."""
    if is_model_path(path):
        return False
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


def is_model_path(path: Path) -> bool:
    """Return True if path is inside a known model download directory."""
    path_str = str(path)
    return any(mp in path_str for mp in MODEL_WATCH_PATHS)


def is_partial_download(path: Path) -> bool:
    """Return True if the file looks like an in-progress download."""
    name = path.name.lower()
    return any(name.endswith(s) for s in PARTIAL_SUFFIXES)


def is_model_file(path: Path) -> bool:
    """Return True if the file is a model file, including Ollama blobs.

    Ollama stores completed model blobs as 'sha256-<64 hex chars>' with
    no file extension inside ~/.ollama/models/blobs/. These must be
    detected by path pattern rather than extension.
    """
    import re
    suffix = path.suffix.lower()
    if suffix in MODEL_EXTENSIONS:
        return True
    # Ollama blob: sha256-<64 lowercase hex chars>, no extension
    if re.fullmatch(r'sha256-[0-9a-f]{64}', path.name):
        return True
    return False


def infer_actor_from_path(path: Path) -> str:
    """Best-effort guess at which app is downloading based on path."""
    p = str(path).lower()
    if ".ollama" in p:          return "ollama"
    if "lm studio" in p:        return "lm_studio"
    if "msty" in p:             return "msty"
    if "anythingllm" in p:      return "anythingllm"
    if "jan" in p:              return "jan"
    if "gpt4all" in p:          return "gpt4all"
    if "huggingface" in p:      return "huggingface"
    return "unknown"


# Track paths already alerted to avoid duplicate notifications
_alerted_downloads: Set[str] = set()


def write_model_download_alert(path: Path, event_type: str, actor_id: str):
    """Write a model download event to the audit log."""
    log_file = LOG_DIR / f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    size = 0
    try:
        size = path.stat().st_size
    except Exception:
        pass
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "action": "FLAGGED",
        "blocked": False,
        "severity": "MEDIUM",
        "source": "file_monitor",
        "url": str(path),
        "path": str(path),
        "actor_id": actor_id,
        "payload_size_bytes": size,
        "payload_hash": hashlib.sha256(str(path).encode()).hexdigest()[:16],
        "finding_count": 1,
        "findings": [{
            "type": event_type,
            "severity": "MEDIUM",
            "preview": f"{path.name} ({size // 1024 // 1024}MB)" if size > 0 else path.name,
            "blocked": False,
        }],
    }
    with open(log_file, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def show_download_notification(path: Path, actor_id: str):
    """Show a macOS notification for a model download."""
    size_mb = 0
    try:
        size_mb = path.stat().st_size // 1024 // 1024
    except Exception:
        pass
    size_str = f" ({size_mb}MB)" if size_mb > 0 else ""
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "AI model downloading: {path.name}{size_str}" '
            f'with title "⚠️ CoworkGuard" subtitle "Model Download Detected"'
        ], timeout=3)
    except Exception:
        pass


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

        # ── Model download detection ──────────────────────────────────────
        # Fires before the text-content scan so large binary files are never
        # read into memory. Alerts once per file path per monitor session.
        path_key = str(path)

        if (is_model_file(path) or is_partial_download(path)) and is_model_path(path):
            if path_key not in _alerted_downloads:
                # Load allow and block lists
                allow_file = Path.home() / ".coworkguard" / "allowed_downloads.json"
                block_file = Path.home() / ".coworkguard" / "blocked_downloads.json"
                allowed, blocked = [], []
                try:
                    if allow_file.exists():
                        allowed = json.loads(allow_file.read_text())
                except Exception:
                    pass
                try:
                    if block_file.exists():
                        blocked = json.loads(block_file.read_text())
                except Exception:
                    pass

                # Check by exact path first, then by parent directory — Ollama
                # retries use a different temp filename in the same directory,
                # so blocking the directory suppresses all retries.
                def _matches_list(lst: list) -> bool:
                    return path_key in lst or any(
                        path_key.startswith(str(Path(p).parent) + "/")
                        for p in lst if p
                    )

                if _matches_list(blocked):
                    # Silently drop — user already blocked this download
                    log.info("Suppressed re-alert for blocked download: %s", path)
                elif not _matches_list(allowed):
                    _alerted_downloads.add(path_key)
                    actor_id = infer_actor_from_path(path)
                    event_type = "LOCAL_MODEL_DOWNLOADING" if is_partial_download(path) else "LOCAL_MODEL_DOWNLOADED"
                    log.warning("%s: %s (actor=%s)", event_type, path, actor_id)
                    write_model_download_alert(path, event_type, actor_id)
                    show_download_notification(path, actor_id)
            return  # Never read binary model files as text

        # Skip non-scannable text extensions
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
