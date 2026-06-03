"""
CoworkGuard Pro — Startup
© 2026 Katherine Weston. All rights reserved.

Starts Pro background components when CoworkGuard protection begins.
Called by server.py on startup — fails silently if pro/ not present.

Components started:
    process_scanner  — lsof polling for AI process file access (every 10s)
    file_watcher     — FSEvents/watchdog for sensitive path writes

Both components:
    - Only start if licence tier is pro, shield, or enterprise
    - Fail silently — never block the free product starting
    - Log to ~/.coworkguard/pro_scanner.log
"""

from __future__ import annotations

import logging
import sys

log = logging.getLogger("coworkguard.pro_startup")


def start_pro_components(get_registry_fn) -> dict:
    """
    Start Pro background components.

    Args:
        get_registry_fn: callable returning current actor registry
                         { pid: { actor_id, bundle_id, ... } }

    Returns:
        dict with status of each component
    """
    status = {
        "licence_tier":    "free",
        "process_scanner": False,
        "file_watcher":    False,
    }

    # Check licence tier first
    try:
        from pro.licence.checker import get_tier, is_pro
        tier = get_tier()
        status["licence_tier"] = tier
        if not is_pro():
            log.info("Pro components not started — licence tier: %s", tier)
            return status
    except ImportError:
        log.debug("Licence checker not available — Pro components not started")
        return status

    log.info("Starting Pro components (tier: %s)...", tier)

    # Start process scanner
    try:
        from pro.dev_env.process_scanner import start_scanner
        start_scanner(get_registry_fn)
        status["process_scanner"] = True
        log.info("✓ Process scanner started")
    except ImportError:
        log.debug("process_scanner not available")
    except Exception as e:
        log.warning("Process scanner failed to start: %s", e)

    # Start file watcher
    try:
        from pro.dev_env.file_watcher import start_watcher
        ok = start_watcher()
        status["file_watcher"] = ok
        if ok:
            log.info("✓ File watcher started")
        else:
            log.info("File watcher not started — watchdog may not be installed")
            log.info("  Install with: pip install watchdog")
    except ImportError:
        log.debug("file_watcher not available")
    except Exception as e:
        log.warning("File watcher failed to start: %s", e)

    return status


def stop_pro_components() -> None:
    """Stop all Pro background components gracefully."""
    try:
        from pro.dev_env.process_scanner import stop_scanner
        stop_scanner()
    except Exception:
        pass

    try:
        from pro.dev_env.file_watcher import stop_watcher
        stop_watcher()
    except Exception:
        pass

    log.info("Pro components stopped")
