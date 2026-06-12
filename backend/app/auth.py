"""Authentication & authorization layer.

Supports two credentials, checked in order:

1. ``Authorization: Bearer <jwt>`` — a logged-in user (carries id + role).
2. ``X-API-Key: <key>`` — a service/admin key for automation and the demo.

Both resolve to a :class:`Principal`. Role-based access control is enforced via
:func:`require_role`, and per-program access (only assigned members, plus
admins, may see a program's findings) via :func:`ensure_program_access`.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import ProgramMember, User
from app.security import decode_access_token

# Role constants.
ROLE_ADMIN = "admin"
ROLE_TRIAGER = "triager"
ROLE_RESEARCHER = "researcher"
ROLE_VIEWER = "viewer"
ALL_ROLES = (ROLE_ADMIN, ROLE_TRIAGER, ROLE_RESEARCHER, ROLE_VIEWER)


@dataclass
class Principal:
    """The authenticated caller."""

    user_id: int | None
    email: str
    role: str
    via: str  # "jwt" | "api_key" | "anonymous"

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    """Resolve the calling principal from a JWT or API key."""
    if not settings.auth_enabled:
        return Principal(user_id=None, email="anonymous", role=ROLE_ADMIN, via="anonymous")

    # 1. Bearer JWT.
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = decode_access_token(token)
        except jwt.ExpiredSignatureError as exc:
            raise _unauthorized("Token has expired.") from exc
        except jwt.PyJWTError as exc:
            raise _unauthorized("Invalid authentication token.") from exc
        user_id = int(claims.get("sub", 0)) or None
        user = db.get(User, user_id) if user_id else None
        if not user or not user.is_active:
            raise _unauthorized("User not found or inactive.")
        return Principal(user_id=user.id, email=user.email, role=user.role, via="jwt")

    # 2. API key — maps to a full-access service principal.
    if x_api_key:
        if x_api_key != settings.api_key:
            raise _unauthorized("Invalid API key.")
        return Principal(user_id=None, email="api-user", role=ROLE_ADMIN, via="api_key")

    raise _unauthorized("Authentication required (Bearer token or X-API-Key).")


def require_api_key(principal: Principal = Depends(get_principal)) -> str:
    """Backward-compatible dependency returning the actor identity string."""
    return principal.email


def require_role(*roles: str):
    """Dependency factory enforcing that the caller has one of ``roles``.

    Admins always pass.
    """

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.is_admin or principal.role in roles:
            return principal
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(roles)}. You are '{principal.role}'.",
        )

    return _dep


def user_can_access_program(db: Session, principal: Principal, program_id: int) -> bool:
    """Admins/API key see all programs; others must be assigned members."""
    if principal.is_admin or principal.user_id is None:
        return True
    member = (
        db.query(ProgramMember)
        .filter(
            ProgramMember.program_id == program_id,
            ProgramMember.user_id == principal.user_id,
        )
        .first()
    )
    return member is not None


def ensure_program_access(
    program_id: int,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Principal:
    """Dependency: caller must be an admin or an assigned member of ``program_id``."""
    if not user_can_access_program(db, principal, program_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not assigned to this program.",
        )
    return principal
