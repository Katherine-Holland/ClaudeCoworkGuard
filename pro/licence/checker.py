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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("coworkguard.licence")

LICENCE_FILE = Path.home() / ".coworkguard" / "licence.json"

# Signing secret — change before production, keep out of repo
# In production this should come from an environment variable
_SIGNING_SECRET = "coworkguard-licence-secret-2026"


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
