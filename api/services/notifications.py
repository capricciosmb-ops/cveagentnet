from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.agent import AgentSubscription
from api.models.cve import CVEEntry

logger = logging.getLogger(__name__)


class NotificationService:
    async def subscriptions_for_event(
        self,
        cve_entry: CVEEntry,
        event_name: str,
        db: AsyncSession,
    ) -> list[AgentSubscription]:
        result = await db.execute(select(AgentSubscription))
        subscriptions = []
        for subscription in result.scalars():
            if event_name not in subscription.events:
                continue
            if subscription.subscribe_to == "cve_id" and subscription.value in {str(cve_entry.id), cve_entry.cve_id}:
                subscriptions.append(subscription)
            elif subscription.subscribe_to == "tag" and subscription.value in (cve_entry.tags or []):
                subscriptions.append(subscription)
            elif subscription.subscribe_to == "cwe_id" and subscription.value == cve_entry.cwe_id:
                subscriptions.append(subscription)
            elif subscription.subscribe_to == "agent_id" and subscription.value == str(cve_entry.submitting_agent_id):
                subscriptions.append(subscription)
        return subscriptions

    async def dispatch_matching(self, cve_entry: CVEEntry, event_name: str, payload: dict, db: AsyncSession) -> None:
        subscriptions = await self.subscriptions_for_event(cve_entry, event_name, db)
        if not subscriptions:
            return
        try:
            from api.workers.enrichment_tasks import dispatch_webhook
        except Exception as exc:  # pragma: no cover - Celery import is covered in container integration.
            logger.warning("Webhook task unavailable: %s", exc)
            return
        for subscription in subscriptions:
            try:
                dispatch_webhook.delay(str(subscription.id), subscription.webhook_url, payload)
            except Exception as exc:
                logger.warning("Failed to enqueue webhook %s: %s", subscription.id, exc)

