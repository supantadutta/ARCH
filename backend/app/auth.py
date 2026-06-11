"""Authorization layer — API key enforcement.

Strict authorization is applied to every API route. When ``AUTH_ENABLED`` is
true (the default) a caller must present a valid key in the ``X-API-Key``
header. The resolved caller identity is returned so routes / audit logging can
attribute actions to an actor.

This is intentionally a simple shared-key scheme suitable for a self-hosted
MVP. It is the authorization *control point*; swapping in OAuth/JWT later means
replacing :func:`require_api_key` while keeping the same dependency contract.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, status

from app.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """FastAPI dependency enforcing API-key authorization.

    Returns the actor identity string on success. Raises ``401`` when auth is
    enabled and the key is missing or invalid.
    """
    if not settings.auth_enabled:
        return "anonymous"

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide a valid 'X-API-Key' header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # A single shared key maps to a single logical operator identity. This is
    # surfaced in audit logs as the acting principal.
    return "api-user"
