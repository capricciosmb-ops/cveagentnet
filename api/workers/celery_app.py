from __future__ import annotations

from celery import Celery

from api.config import get_settings

settings = get_settings()

celery_app = Celery(
    "cveagentnet",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["api.workers.enrichment_tasks", "api.workers.sync_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "sync-recent-nvd-cves-hourly": {
            "task": "api.workers.sync_tasks.sync_recent_nvd",
            "schedule": 3600.0,
        }
    },
)
