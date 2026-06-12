"""Evidence redaction helpers.

Access-control evidence must never leak real sensitive data. These helpers
redact common sensitive fields and cap the amount of any response body retained,
so findings carry just enough (redacted) signal for a human to review — never a
bulk copy of data.
"""

from __future__ import annotations

import re

from app.config import settings

# Field names whose values are always redacted in stored evidence.
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "api_key", "apikey", "ssn", "social_security", "credit_card",
    "card_number", "cvv", "pan", "iban", "account_number", "private_key",
    "session", "cookie", "otp", "pin",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_LONG_DIGITS_RE = re.compile(r"\b\d{9,}\b")


def redact_value(value):
    """Redact a single value heuristically (emails, long digit runs)."""
    if isinstance(value, str):
        v = _EMAIL_RE.sub("<redacted-email>", value)
        v = _LONG_DIGITS_RE.sub("<redacted-number>", v)
        return v
    return value


def redact_json(obj):
    """Recursively redact sensitive keys/values in a parsed JSON structure."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in SENSITIVE_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = redact_json(v)
        return out
    if isinstance(obj, list):
        # Cap list length so we never retain bulk data as evidence.
        return [redact_json(x) for x in obj[:5]]
    return redact_value(obj)


def redact_text(text: str | None) -> str:
    """Redact and cap a raw text body for safe storage as evidence."""
    if not text:
        return ""
    capped = text[: settings.evidence_max_bytes]
    capped = _EMAIL_RE.sub("<redacted-email>", capped)
    capped = _LONG_DIGITS_RE.sub("<redacted-number>", capped)
    if len(text) > settings.evidence_max_bytes:
        capped += "\n…(truncated; bulk data never retained)…"
    return capped


def json_key_set(obj) -> list[str]:
    """Return the sorted set of top-level keys in a JSON object (no values)."""
    if isinstance(obj, dict):
        return sorted(obj.keys())
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return sorted(obj[0].keys())
    return []
