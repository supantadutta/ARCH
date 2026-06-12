"""Shared pagination helper for list endpoints."""

from __future__ import annotations

from app.schemas.schemas import Page


def paginate(query, limit: int, offset: int, serializer) -> Page:
    """Return a :class:`Page` for a SQLAlchemy query.

    ``serializer`` maps each ORM row to its output schema.
    """
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    return Page(items=[serializer(r) for r in rows], total=total, limit=limit, offset=offset)
