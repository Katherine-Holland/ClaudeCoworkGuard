"""
CoworkGuard Pro — Licence Key Generator
© 2026 Katherine Weston. All rights reserved.

Internal tool for generating signed licence keys for early Pro users.
Run locally — never expose this to the internet.

Usage:
    python3 -m pro.licence.keygen --email user@company.com --tier pro
    python3 -m pro.licence.keygen --email team@company.com --tier shield --months 12

Output:
    Writes ~/.coworkguard/licence.json on the target machine
    OR prints the JSON to stdout for manual delivery

Later: Stripe webhook calls generate_key() automatically on successful payment.

Environment:
    CWG_LICENCE_SECRET — signing secret (required in production)
    Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
    Set in ~/.zshrc: export CWG_LICENCE_SECRET="your_secret_here"
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import string
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from pathlib import Path

# Signing secret — loaded from environment variable
# Never hardcode this value — keep it out of the repo
def _load_secret() -> str:
    """
    Load the HMAC signing secret. Resolution order:
      1. pro/licence/.secret file (bundled at build time, not in repo)
      2. CWG_LICENCE_SECRET environment variable
    Returns empty string if neither is available — caller must check.
    """
    secret_file = Path(__file__).parent / ".secret"
    if secret_file.exists():
        secret = secret_file.read_text().strip()
        if secret:
            return secret
    return os.environ.get("CWG_LICENCE_SECRET", "").strip()

_SIGNING_SECRET = _load_secret()

if not _SIGNING_SECRET:
    raise RuntimeError(
        "CWG_LICENCE_SECRET not set and pro/licence/.secret not found. "
        "Cannot generate licences without a signing secret."
    )

VALID_TIERS = {"pro", "shield", "enterprise"}


def _sign(key: str, email: str, tier: str, expires_at: str) -> str:
    message = f"{key}:{email}:{tier}:{expires_at}"
    return hmac.new(
        _SIGNING_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()


def _generate_key(tier: str) -> str:
    """Generate a readable licence key: CWG-PRO-XXXX-XXXX-XXXX"""
    prefix = {
        "pro":        "CWG-PRO",
        "shield":     "CWG-SHD",
        "enterprise": "CWG-ENT",
    }.get(tier, "CWG-PRO")

    chars = string.ascii_uppercase + string.digits
    segments = [
        "".join(secrets.choice(chars) for _ in range(4))
        for _ in range(3)
    ]
    return f"{prefix}-{'-'.join(segments)}"


def generate_licence(
    email: str,
    tier: str = "pro",
    months: int = 12,
) -> dict:
    """
    Generate a signed licence dict.

    Args:
        email:  Licensee email address
        tier:   'pro' | 'shield' | 'enterprise'
        months: Validity period in months (default 12)

    Returns:
        Licence dict ready to write to licence.json
    """
    if tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier: {tier}. Must be one of {VALID_TIERS}")

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=months * 30)

    key        = _generate_key(tier)
    issued_at  = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    signature  = _sign(key, email, tier, expires_at)

    return {
        "tier":       tier,
        "key":        key,
        "email":      email,
        "issued_at":  issued_at,
        "expires_at": expires_at,
        "signature":  signature,
    }


def write_licence(licence: dict, path: Path | None = None) -> Path:
    """Write licence to disk. Defaults to ~/.coworkguard/licence.json"""
    target = path or (Path.home() / ".coworkguard" / "licence.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(licence, indent=2))
    return target


def print_instructions(licence: dict) -> None:
    """Print installation instructions for the licensee."""
    print("\n" + "="*60)
    print(f"CoworkGuard {licence['tier'].upper()} Licence")
    print("="*60)
    print(f"Email:      {licence['email']}")
    print(f"Key:        {licence['key']}")
    print(f"Issued:     {licence['issued_at']}")
    print(f"Expires:    {licence['expires_at']}")
    print("\nInstallation:")
    print("Save the following to: ~/.coworkguard/licence.json")
    print("-"*60)
    print(json.dumps(licence, indent=2))
    print("-"*60)
    print("\nThen restart CoworkGuard protection.")
    print("="*60 + "\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a CoworkGuard Pro licence key"
    )
    parser.add_argument("--email",  required=True, help="Licensee email address")
    parser.add_argument("--tier",   default="pro",
                        choices=list(VALID_TIERS), help="Licence tier")
    parser.add_argument("--months", type=int, default=12,
                        help="Validity in months (default: 12)")
    parser.add_argument("--write",  action="store_true",
                        help="Write to ~/.coworkguard/licence.json on this machine")
    parser.add_argument("--output", type=str, default=None,
                        help="Write to a specific path instead")

    args = parser.parse_args()

    # Warn if secret not set
    if "CWG_LICENCE_SECRET" not in os.environ:
        print("⚠️  WARNING: CWG_LICENCE_SECRET not set — using dev-only secret.")
        print("   Keys generated here will NOT validate in production.")
        print("   Set CWG_LICENCE_SECRET before generating real keys.\n")

    licence = generate_licence(
        email=args.email,
        tier=args.tier,
        months=args.months,
    )

    if args.output:
        path = write_licence(licence, Path(args.output))
        print(f"Licence written to: {path}")
    elif args.write:
        path = write_licence(licence)
        print(f"Licence written to: {path}")
    else:
        print_instructions(licence)


if __name__ == "__main__":
    main()
