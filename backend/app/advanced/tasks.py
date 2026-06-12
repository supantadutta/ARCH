"""Celery tasks for the advanced modules that perform network actions.

These wrap the authenticated crawler and the access-control comparator so they
can run asynchronously. The same hard safety controls apply inside the service
layer (scope, kill switch, authorized accounts, rate/size limits, default
dry-run). Transient infra errors are retried with backoff; policy rejections are
never retried.
"""

from __future__ import annotations

from app.celery_app import celery_app
from app.config import settings
from app.database import SessionLocal


@celery_app.task(
    name="advanced.auth_crawl",
    autoretry_for=(ConnectionError, TimeoutError),
    retry_backoff=settings.task_retry_backoff,
    max_retries=settings.task_max_retries,
)
def auth_crawl_task(program_id: int, account_id: int, start_url: str, dry_run: bool = True) -> dict:
    from app.advanced.auth_crawler import run_authenticated_crawl

    db = SessionLocal()
    try:
        return run_authenticated_crawl(db, program_id, account_id, start_url, dry_run=dry_run, actor="celery")
    except Exception as exc:  # pragma: no cover - surfaced to result backend
        return {"error": str(exc)}
    finally:
        db.close()


@celery_app.task(
    name="advanced.access_control_compare",
    autoretry_for=(ConnectionError, TimeoutError),
    retry_backoff=settings.task_retry_backoff,
    max_retries=settings.task_max_retries,
)
def access_control_task(
    program_id: int, account_a_id: int, account_b_id: int, target_urls: list[str], dry_run: bool = True
) -> dict:
    from app.advanced.access_control import compare_access

    db = SessionLocal()
    try:
        return compare_access(
            db, program_id, account_a_id, account_b_id, target_urls, dry_run=dry_run, actor="celery"
        )
    except Exception as exc:  # pragma: no cover
        return {"error": str(exc)}
    finally:
        db.close()
