"""Celery application factory."""

from celery import Celery

from app.config import settings

celery_app = Celery(
    "autobughunter",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=900,
    worker_max_tasks_per_child=50,
)
