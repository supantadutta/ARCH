"""Notification service (placeholder).

A minimal, pluggable notification layer. The default ``log`` provider writes
events to the application log; a ``webhook`` provider posts a JSON payload to a
configured URL. This is intentionally a placeholder — it does not integrate with
Slack/email/PagerDuty, but provides the seam to do so later.

Every notification is also recorded in the audit log so dispatch is traceable.
"""

from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.services.audit import record_audit

logger = logging.getLogger("autobughunter.notify")


def notify(db: Session, *, event: str, message: str, meta: dict | None = None) -> None:
    """Dispatch a notification via the configured provider (best-effort)."""
    provider = settings.notify_provider
    detail = f"{event}: {message}"
    try:
        if provider == "webhook" and settings.notify_webhook_url:
            httpx.post(
                settings.notify_webhook_url,
                json={"event": event, "message": message, "meta": meta or {}},
                timeout=5,
            )
        else:
            logger.info("[notify] %s | %s | meta=%s", event, message, meta or {})
    except Exception as exc:  # pragma: no cover - notifications never block flow
        logger.warning("[notify] dispatch failed for %s: %s", event, exc)

    record_audit(
        db,
        action="notification.sent",
        target=event,
        decision="info",
        detail=detail[:480],
        commit=False,
    )
