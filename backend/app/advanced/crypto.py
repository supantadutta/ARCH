"""At-rest encryption for test-account secrets and sessions.

Uses Fernet (AES-128-CBC + HMAC). The key is derived from
``ADVANCED_SECRET_KEY`` (or ``JWT_SECRET`` as a fallback) so secrets are never
stored in plaintext. This protects stored test-account credentials and captured
session material.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _fernet() -> Fernet:
    raw = settings.advanced_secret_key or settings.jwt_secret or "dev-fallback"
    # Derive a stable 32-byte urlsafe key from the configured secret.
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())
    return Fernet(key)


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt a string for storage; ``None`` passes through."""
    if plaintext is None:
        return None
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(token: str | None) -> str | None:
    """Decrypt a stored token; returns ``None`` on missing/invalid input."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
