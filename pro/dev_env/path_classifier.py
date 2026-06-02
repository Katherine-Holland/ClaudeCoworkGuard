"""
CoworkGuard Pro — Path Classifier
© 2026 Katherine Weston. All rights reserved.

Semantic understanding of file access events.
Maps file paths to human-readable event types, severities, and descriptions.

Not just "user opened file" — but "AI tool accessed GitHub token."

Design principles:
  - Calm, observational language throughout (never "CRITICAL THREAT")
  - Specific over generic — "Accessed GitHub token" not "Accessed config file"
  - Extensible — new categories added without restructuring
  - Environment-aware — understands AI tool config directories specifically

Long-term this becomes the semantic layer for all file access events
across developer, browser, and enterprise environments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# Event types
# ─────────────────────────────────────────────

class DevEnvEventType:
    SSH_KEY_ACCESS          = "SSH_KEY_ACCESS"
    AWS_CREDENTIALS_ACCESS  = "AWS_CREDENTIALS_ACCESS"
    GITHUB_TOKEN_ACCESS     = "GITHUB_TOKEN_ACCESS"
    GIT_CREDENTIALS_ACCESS  = "GIT_CREDENTIALS_ACCESS"
    ENV_FILE_ACCESS         = "ENV_FILE_ACCESS"
    TOKEN_FILE_ACCESS       = "TOKEN_FILE_ACCESS"
    KUBECONFIG_ACCESS       = "KUBECONFIG_ACCESS"
    AI_CONFIG_ACCESS        = "AI_CONFIG_ACCESS"
    MCP_CONFIG_ACCESS       = "MCP_CONFIG_ACCESS"
    REPO_FILE_ACCESS        = "REPO_FILE_ACCESS"
    DOCKER_CONFIG_ACCESS    = "DOCKER_CONFIG_ACCESS"
    CLOUD_CONFIG_ACCESS     = "CLOUD_CONFIG_ACCESS"
    VECTOR_STORE_ACCESS     = "VECTOR_STORE_ACCESS"
    BROWSER_SESSION_ACCESS  = "BROWSER_SESSION_ACCESS"
    SENSITIVE_FILE_ACCESS   = "SENSITIVE_FILE_ACCESS"  # catch-all


# ─────────────────────────────────────────────
# Classification result
# ─────────────────────────────────────────────

@dataclass
class Classification:
    event_type:   str
    severity:     str            # CRITICAL / HIGH / MEDIUM / LOW
    label:        str            # short human label — "Accessed GitHub token"
    description:  str            # one sentence — calm, observational
    category:     str            # credentials / config / secrets / repo / ai_tool
    confidence:   float = 1.0   # 0.0–1.0 — how certain we are of the classification
    tags:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "event_type":  self.event_type,
            "severity":    self.severity,
            "label":       self.label,
            "description": self.description,
            "category":    self.category,
            "confidence":  self.confidence,
            "tags":        self.tags,
        }


# ─────────────────────────────────────────────
# Path rules
# Each rule: (pattern, Classification)
# Patterns matched in order — first match wins
# ─────────────────────────────────────────────

def _home(subpath: str) -> str:
    """Return a regex that matches subpath under any home directory."""
    return rf"^/Users/[^/]+/{re.escape(subpath).replace(r'\*', '[^/]+')}"


def _home_glob(pattern: str) -> str:
    """Convert a glob-style home path to regex."""
    p = pattern.replace("~", r"/Users/[^/]+")
    p = p.replace("**", ".*").replace("*", "[^/]+").replace(".", r"\.")
    return f"^{p}"


_RULES: list[tuple[str, Classification]] = [

    # ── SSH keys ──────────────────────────────────────────────────────────────
    (r"/\.ssh/id_(?:rsa|ecdsa|ed25519|dsa)$",
     Classification("SSH_KEY_ACCESS", "CRITICAL",
        "Accessed SSH private key",
        "An AI tool read an SSH private key from your machine.",
        "credentials", tags=["ssh", "private-key"])),

    (r"/\.ssh/id_[^/]+$",
     Classification("SSH_KEY_ACCESS", "CRITICAL",
        "Accessed SSH key file",
        "An AI tool accessed a file in your SSH directory.",
        "credentials", tags=["ssh"])),

    (r"/\.ssh/known_hosts$",
     Classification("SSH_KEY_ACCESS", "LOW",
        "Accessed SSH known hosts",
        "An AI tool read your SSH known hosts file.",
        "config", confidence=0.6, tags=["ssh"])),

    # ── AWS ──────────────────────────────────────────────────────────────────
    (r"/\.aws/credentials$",
     Classification("AWS_CREDENTIALS_ACCESS", "CRITICAL",
        "Accessed AWS credentials",
        "An AI tool read your AWS access keys and secrets.",
        "credentials", tags=["aws", "cloud"])),

    (r"/\.aws/config$",
     Classification("AWS_CREDENTIALS_ACCESS", "HIGH",
        "Accessed AWS config",
        "An AI tool read your AWS configuration file.",
        "config", tags=["aws", "cloud"])),

    (r"/\.aws/",
     Classification("AWS_CREDENTIALS_ACCESS", "HIGH",
        "Accessed AWS directory",
        "An AI tool accessed a file in your AWS directory.",
        "credentials", confidence=0.8, tags=["aws", "cloud"])),

    # ── GitHub / Git ─────────────────────────────────────────────────────────
    (r"/\.config/gh/hosts\.yml$",
     Classification("GITHUB_TOKEN_ACCESS", "CRITICAL",
        "Accessed GitHub CLI token",
        "An AI tool read your GitHub authentication token.",
        "credentials", tags=["github", "token"])),

    (r"/\.config/gh/",
     Classification("GITHUB_TOKEN_ACCESS", "HIGH",
        "Accessed GitHub CLI config",
        "An AI tool accessed your GitHub CLI configuration.",
        "config", confidence=0.8, tags=["github"])),

    (r"/\.git-credentials$",
     Classification("GIT_CREDENTIALS_ACCESS", "CRITICAL",
        "Accessed Git credentials store",
        "An AI tool read your stored Git credentials.",
        "credentials", tags=["git", "credentials"])),

    (r"/\.gitconfig$",
     Classification("GIT_CREDENTIALS_ACCESS", "MEDIUM",
        "Accessed Git config",
        "An AI tool read your Git configuration file.",
        "config", confidence=0.7, tags=["git"])),

    # ── .env files ────────────────────────────────────────────────────────────
    (r"/\.env\.(?:local|production|staging|development|test)$",
     Classification("ENV_FILE_ACCESS", "CRITICAL",
        "Accessed environment secrets file",
        "An AI tool read an environment secrets file containing credentials.",
        "secrets", tags=["env", "secrets"])),

    (r"/\.env$",
     Classification("ENV_FILE_ACCESS", "HIGH",
        "Accessed .env file",
        "An AI tool read a .env file that may contain API keys and secrets.",
        "secrets", tags=["env", "secrets"])),

    (r"\.env\.",
     Classification("ENV_FILE_ACCESS", "HIGH",
        "Accessed environment file",
        "An AI tool read an environment configuration file.",
        "secrets", confidence=0.8, tags=["env"])),

    # ── npm / pip / package tokens ────────────────────────────────────────────
    (r"/\.npmrc$",
     Classification("TOKEN_FILE_ACCESS", "HIGH",
        "Accessed npm credentials",
        "An AI tool read your npm configuration, which may contain auth tokens.",
        "credentials", tags=["npm", "token"])),

    (r"/\.pypirc$",
     Classification("TOKEN_FILE_ACCESS", "HIGH",
        "Accessed PyPI credentials",
        "An AI tool read your PyPI configuration, which may contain upload tokens.",
        "credentials", tags=["pypi", "token"])),

    (r"/\.netrc$",
     Classification("TOKEN_FILE_ACCESS", "HIGH",
        "Accessed .netrc credentials",
        "An AI tool read your .netrc file containing stored login credentials.",
        "credentials", tags=["netrc"])),

    # ── Kubernetes ────────────────────────────────────────────────────────────
    (r"/\.kube/config$",
     Classification("KUBECONFIG_ACCESS", "HIGH",
        "Accessed Kubernetes config",
        "An AI tool read your Kubernetes configuration, which contains cluster credentials.",
        "credentials", tags=["kubernetes", "k8s", "cloud"])),

    (r"/\.kube/",
     Classification("KUBECONFIG_ACCESS", "MEDIUM",
        "Accessed Kubernetes directory",
        "An AI tool accessed a file in your Kubernetes config directory.",
        "config", confidence=0.7, tags=["kubernetes"])),

    # ── Docker ────────────────────────────────────────────────────────────────
    (r"/\.docker/config\.json$",
     Classification("DOCKER_CONFIG_ACCESS", "HIGH",
        "Accessed Docker credentials",
        "An AI tool read your Docker config, which may contain registry credentials.",
        "credentials", tags=["docker", "registry"])),

    # ── Cloud / GCP / Azure ──────────────────────────────────────────────────
    (r"/\.config/gcloud/",
     Classification("CLOUD_CONFIG_ACCESS", "HIGH",
        "Accessed GCP credentials",
        "An AI tool accessed your Google Cloud configuration.",
        "credentials", tags=["gcp", "cloud"])),

    (r"/\.azure/",
     Classification("CLOUD_CONFIG_ACCESS", "HIGH",
        "Accessed Azure credentials",
        "An AI tool accessed your Azure CLI configuration.",
        "credentials", tags=["azure", "cloud"])),

    # ── AI tool configs ───────────────────────────────────────────────────────
    (r"/\.claude/settings\.json$",
     Classification("AI_CONFIG_ACCESS", "HIGH",
        "Accessed Claude Desktop config",
        "An AI tool read Claude Desktop settings, which may contain API keys.",
        "ai_tool", tags=["claude", "anthropic"])),

    (r"/\.claude/",
     Classification("AI_CONFIG_ACCESS", "MEDIUM",
        "Accessed Claude config directory",
        "An AI tool accessed a file in the Claude Desktop config directory.",
        "ai_tool", confidence=0.7, tags=["claude"])),

    (r"Library/Application Support/Claude/",
     Classification("AI_CONFIG_ACCESS", "MEDIUM",
        "Accessed Claude application data",
        "An AI tool accessed Claude Desktop application data.",
        "ai_tool", confidence=0.7, tags=["claude"])),

    (r"/\.cursor/",
     Classification("AI_CONFIG_ACCESS", "MEDIUM",
        "Accessed Cursor config",
        "An AI tool accessed Cursor IDE configuration.",
        "ai_tool", confidence=0.7, tags=["cursor"])),

    (r"Library/Application Support/Cursor/",
     Classification("AI_CONFIG_ACCESS", "MEDIUM",
        "Accessed Cursor application data",
        "An AI tool accessed Cursor IDE application data.",
        "ai_tool", confidence=0.7, tags=["cursor"])),

    (r"Library/Application Support/Code/User/settings\.json$",
     Classification("AI_CONFIG_ACCESS", "MEDIUM",
        "Accessed VS Code settings",
        "An AI tool read VS Code user settings.",
        "ai_tool", confidence=0.7, tags=["vscode"])),

    # ── MCP configs ───────────────────────────────────────────────────────────
    (r"\.mcp\.json$",
     Classification("MCP_CONFIG_ACCESS", "HIGH",
        "Accessed MCP configuration",
        "An AI tool read an MCP server configuration file.",
        "ai_tool", tags=["mcp"])),

    (r"mcp[_\-]config",
     Classification("MCP_CONFIG_ACCESS", "MEDIUM",
        "Accessed MCP config file",
        "An AI tool accessed an MCP-related configuration.",
        "ai_tool", confidence=0.7, tags=["mcp"])),

    # ── Local vector stores / embeddings ─────────────────────────────────────
    (r"\.chroma/",
     Classification("VECTOR_STORE_ACCESS", "MEDIUM",
        "Accessed ChromaDB vector store",
        "An AI tool accessed a local ChromaDB vector database.",
        "ai_tool", tags=["vectordb", "chroma"])),

    (r"\.faiss/|faiss\.index",
     Classification("VECTOR_STORE_ACCESS", "MEDIUM",
        "Accessed FAISS index",
        "An AI tool accessed a local FAISS vector index.",
        "ai_tool", tags=["vectordb", "faiss"])),

    # ── Browser session storage ───────────────────────────────────────────────
    (r"Library/Application Support/Google/Chrome/Default/",
     Classification("BROWSER_SESSION_ACCESS", "MEDIUM",
        "Accessed Chrome profile data",
        "An AI tool accessed Chrome browser profile data.",
        "browser", confidence=0.7, tags=["chrome", "browser"])),

    (r"Library/Application Support/BraveSoftware/",
     Classification("BROWSER_SESSION_ACCESS", "MEDIUM",
        "Accessed Brave browser data",
        "An AI tool accessed Brave browser profile data.",
        "browser", confidence=0.7, tags=["brave", "browser"])),

    # ── Repo files ────────────────────────────────────────────────────────────
    (r"/\.git/config$",
     Classification("REPO_FILE_ACCESS", "MEDIUM",
        "Accessed git repository config",
        "An AI tool read the git configuration for a repository.",
        "repo", confidence=0.8, tags=["git", "repo"])),

    (r"/\.git/",
     Classification("REPO_FILE_ACCESS", "LOW",
        "Accessed git repository data",
        "An AI tool accessed internal git repository data.",
        "repo", confidence=0.6, tags=["git", "repo"])),
]

# Compile patterns once at import time
_COMPILED_RULES: list[tuple[re.Pattern, Classification]] = [
    (re.compile(pattern, re.IGNORECASE), clf)
    for pattern, clf in _RULES
]


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def classify(path: str) -> Optional[Classification]:
    """
    Classify a file path and return a Classification.
    Returns None if the path is not considered sensitive.
    First match wins — rules are ordered by specificity.
    """
    for pattern, clf in _COMPILED_RULES:
        if pattern.search(path):
            return clf
    return None


def is_sensitive(path: str) -> bool:
    """Quick check — is this path sensitive at all?"""
    return classify(path) is not None


def severity_score(severity: str) -> int:
    """Numeric score for sorting — higher = more severe."""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 0)


def classify_batch(paths: list[str]) -> list[tuple[str, Optional[Classification]]]:
    """Classify multiple paths. Returns (path, classification) pairs."""
    return [(p, classify(p)) for p in paths]


def sensitive_paths_only(paths: list[str]) -> list[tuple[str, Classification]]:
    """Filter to only sensitive paths with their classifications."""
    return [(p, c) for p, c in classify_batch(paths) if c is not None]


# ─────────────────────────────────────────────
# Known sensitive base paths — used by file_watcher.py
# ─────────────────────────────────────────────

WATCH_PATHS = [
    "~/.ssh",
    "~/.aws",
    "~/.config/gh",
    "~/.git-credentials",
    "~/.gitconfig",
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.kube",
    "~/.docker",
    "~/.config/gcloud",
    "~/.azure",
    "~/.claude",
    "~/.cursor",
    "~/Library/Application Support/Claude",
    "~/Library/Application Support/Cursor",
]

ENV_FILE_PATTERNS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
]
