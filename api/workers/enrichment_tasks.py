from __future__ import annotations

import httpx
from redis import Redis

from api.config import get_settings
from api.services.webhook_security import UnsafeWebhookURLError, validate_webhook_redirect, validate_webhook_url
from api.workers.celery_app import celery_app


@celery_app.task(bind=True, autoretry_for=(httpx.HTTPError,), retry_backoff=False, max_retries=3)
def dispatch_webhook(self, subscription_id: str, webhook_url: str, payload: dict) -> dict:
    countdowns = [5, 25, 125]
    try:
        validate_webhook_url(webhook_url)
        with httpx.Client(timeout=10.0) as client:
            response = client.post(webhook_url, json=payload, follow_redirects=False)
            if 300 <= response.status_code < 400:
                validate_webhook_redirect(response.headers.get("location", ""))
            response.raise_for_status()
        return {"subscription_id": subscription_id, "status": response.status_code}
    except UnsafeWebhookURLError as exc:
        redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
        redis.rpush(
            "deadletter:webhooks",
            {"subscription_id": subscription_id, "webhook_url": webhook_url, "payload": payload, "error": str(exc)}.__repr__(),
        )
        raise
    except Exception as exc:
        if self.request.retries < len(countdowns):
            raise self.retry(exc=exc, countdown=countdowns[self.request.retries])
        redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
        redis.rpush(
            "deadletter:webhooks",
            {"subscription_id": subscription_id, "webhook_url": webhook_url, "payload": payload, "error": str(exc)}.__repr__(),
        )
        raise
