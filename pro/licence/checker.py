"""
CoworkGuard Pro — Licence Checker
© 2026 Katherine Weston. All rights reserved.

Reads and validates ~/.coworkguard/licence.json.
Uses HMAC-SHA256 to verify the key was issued by CoworkGuard.

Licence file shape:
    {
        "tier":       "pro",
        "key":        "CWG-PRO-xxxx-xxxx-xxxx",
        "email":      "user@company.com",
        "issued_at":  "2026-06-01T00:00:00Z",
        "expires_at": "2027-06-01T00:00:00Z",
        "signature":  "hmac_sha256_hex"
    }

Tiers: "free" | "pro" | "shield" | "enterprise"

Usage:
    from pro.licence.checker import get_tier, is_pro, is_shield

Environment:
    CWG_LICENCE_SECRET — must match the secret used in keygen.py
    Set in ~/.zshrc: export CWG_LICENCE_SECRET="your_secret_here"

Notes:
    - Returns "free" on any error — never blocks the product
    - Manual key generation for early users (keygen.py)
    - Stripe integration adds key delivery later
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("coworkguard.licence")

LICENCE_FILE = Path.home() / ".coworkguard" / "licence.json"

# Signing secret — loaded from environment variable
# Must match the secret used when the key was generated (keygen.py)
# Never hardcode this value
def _load_secret() -> str:
    """
    Load the HMAC signing secret. Resolution order:
      1. pro/licence/.secret file (bundled at build time, not in repo)
      2. CWG_LICENCE_SECRET environment variable
    Raises RuntimeError if neither is available — prevents silent fallback
    to a dev secret that would make all keys trivially forgeable.
    """
    # Look for .secret relative to this file (works both in repo and app bundle)
    secret_file = Path(__file__).parent / ".secret"
    if secret_file.exists():
        secret = secret_file.read_text().strip()
        if secret:
            return secret

    # Env var fallback (CI, shell-launched server)
    secret = os.environ.get("CWG_LICENCE_SECRET", "").strip()
    if secret:
        return secret

    raise RuntimeError(
        "CWG_LICENCE_SECRET not set and pro/licence/.secret not found. "
        "Cannot validate licences without a signing secret."
    )

try:
    _SIGNING_SECRET = _load_secret()
except RuntimeError:
    _SIGNING_SECRET = ""  # validation will always fail — no silent dev fallback


# ─────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────

def _sign(key: str, email: str, tier: str, expires_at: str) -> str:
    """Generate HMAC signature for a licence."""
    message = f"{key}:{email}:{tier}:{expires_at}"
    return hmac.new(
        _SIGNING_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()


def _verify_signature(lic: dict) -> bool:
    """Verify the licence signature is valid."""
    try:
        expected = _sign(
            lic["key"],
            lic["email"],
            lic["tier"],
            lic["expires_at"],
        )
        provided = lic.get("signature", "")
        return hmac.compare_digest(expected, provided)
    except Exception:
        return False


def _is_expired(expires_at: str) -> bool:
    """Check if the licence has expired."""
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > expiry
    except Exception:
        return True  # malformed date = treat as expired


def load_licence() -> Optional[dict]:
    """
    Load and validate the licence file.
    Returns the licence dict if valid, None otherwise.
    Never raises — always returns None on any error.
    """
    try:
        if not LICENCE_FILE.exists():
            return None

        lic = json.loads(LICENCE_FILE.read_text())

        required = {"tier", "key", "email", "issued_at", "expires_at", "signature"}
        if not required.issubset(lic.keys()):
            log.debug("Licence missing required fields")
            return None

        if not _verify_signature(lic):
            log.warning("Licence signature invalid")
            return None

        if _is_expired(lic["expires_at"]):
            log.info("Licence expired: %s", lic["expires_at"])
            return None

        return lic

    except Exception as e:
        log.debug("Licence load error: %s", e)
        return None


# ─────────────────────────────────────────────
# Public API — simple tier checks
# ─────────────────────────────────────────────

_TIER_ORDER = {"free": 0, "pro": 1, "shield": 2, "enterprise": 3}


def get_tier() -> str:
    """
    Returns current licence tier: 'free' | 'pro' | 'shield' | 'enterprise'
    Always returns 'free' on any error — never blocks the product.
    """
    lic = load_licence()
    if not lic:
        return "free"
    tier = lic.get("tier", "free").lower()
    return tier if tier in _TIER_ORDER else "free"


def get_licence_info() -> dict:
    """
    Returns dict suitable for /api/licence response.
    Safe to return to the dashboard — no signing secret exposed.
    """
    lic = load_licence()
    if not lic:
        return {
            "tier":       "free",
            "email":      None,
            "expires_at": None,
            "valid":      False,
        }
    return {
        "tier":       lic.get("tier", "free"),
        "email":      lic.get("email"),
        "expires_at": lic.get("expires_at"),
        "issued_at":  lic.get("issued_at"),
        "valid":      True,
    }


def is_pro() -> bool:
    """True for pro, shield, enterprise."""
    return _TIER_ORDER.get(get_tier(), 0) >= _TIER_ORDER["pro"]


def is_shield() -> bool:
    """True for shield and enterprise."""
    return _TIER_ORDER.get(get_tier(), 0) >= _TIER_ORDER["shield"]


def is_enterprise() -> bool:
    return get_tier() == "enterprise"


def requires_pro(feature_name: str = "") -> bool:
    """
    Gate check for Pro features.
    Logs which feature was attempted if not licensed.
    """
    if is_pro():
        return True
    if feature_name:
        log.debug("Pro feature required: %s", feature_name)
    return False
