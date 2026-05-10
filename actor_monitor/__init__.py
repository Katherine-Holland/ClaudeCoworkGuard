"""
CoworkGuard AI Actor Monitor
© 2026 Katherine Weston. All rights reserved.

Monitors local AI actors on macOS — browsers, desktop AI apps,
agents, extensions, and MCP tools.

Modules:
    actors.json         — registry of known AI actors
    actor_registry.py   — loads registry, matches running processes
    model_monitor.py    — watches for AI model downloads
    agent_guard.py      — permissions scan, sensitive app detection
    consent_engine.py   — policy rules, visibility vs enforcement mode
"""
