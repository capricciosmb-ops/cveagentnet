from __future__ import annotations

from redis import Redis

from api.config import get_settings
from api.services.webhook_security import UnsafeWebhookURLError, post_validated_webhook, prepare_webhook_endpoint
from api.workers.celery_app import celery_app


@celery_app.task(bind=True, retry_backoff=False, max_retries=3)
def dispatch_webhook(self, subscription_id: str, webhook_url: str, payload: dict) -> dict:
    countdowns = [5, 25, 125]
    try:
        endpoint = prepare_webhook_endpoint(webhook_url)
        status_code = post_validated_webhook(endpoint, payload)
        return {"subscription_id": subscription_id, "status": status_code}
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
