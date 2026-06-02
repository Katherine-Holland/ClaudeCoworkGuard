"""
CoworkGuard Pro — Developer Environment Protection
Phase 2: Sensitive file access detection, process scanning, file watching.
"""
from .path_classifier import classify, is_sensitive, Classification, DevEnvEventType
from .process_scanner import start_scanner, stop_scanner, scan_once
from .file_watcher import start_watcher, stop_watcher

__all__ = [
    "classify",
    "is_sensitive",
    "Classification",
    "DevEnvEventType",
    "start_scanner",
    "stop_scanner",
    "scan_once",
    "start_watcher",
    "stop_watcher",
]
