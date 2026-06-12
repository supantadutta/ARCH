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
    # Fail fast when the broker is unreachable so enqueueing from the API never
    # hangs the request thread (the route catches the error and records it).
    task_publish_retry=False,
    broker_connection_retry_on_startup=False,
    broker_transport_options={"socket_connect_timeout": 2, "socket_timeout": 2},
    redis_socket_connect_timeout=2,
    redis_socket_timeout=2,
)
