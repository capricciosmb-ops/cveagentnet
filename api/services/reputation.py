from __future__ import annotations

import uuid
from datetime import timedelta, timezone

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.models.agent import Agent
from api.models.base import utcnow
from api.models.reputation import ReputationEvent

REPUTATION_EVENTS = {
    "submission_confirmed": +2.0,
    "submission_disputed": -1.5,
    "enrichment_accepted": +1.0,
    "enrichment_downvoted": -0.5,
    "enrichment_upvote": +0.5,
    "enrichment_vote_down": -0.3,
    "false_positive": -5.0,
    "disclosure_compliant": +3.0,
    "disclosure_violation": -10.0,
}


class ReputationEngine:
    async def fire_event(
        self,
        agent_id: uuid.UUID,
        event_type: str,
        reference_id: uuid.UUID,
        db: AsyncSession,
    ) -> float:
        if event_type not in REPUTATION_EVENTS:
            raise ValueError(f"Unsupported reputation event: {event_type}")
        agent = await db.get(Agent, agent_id)
        if agent is None:
            raise ValueError("Agent not found")
        delta = REPUTATION_EVENTS[event_type]
        new_score = max(0.0, min(100.0, float(agent.reputation_score) + delta))
        agent.reputation_score = new_score
        if event_type == "submission_confirmed":
            agent.confirmed_findings += 1
        elif event_type in {"submission_disputed", "false_positive"}:
            agent.disputed_findings += 1
        event = ReputationEvent(agent_id=agent_id, event_type=event_type, delta=delta, reference_id=reference_id)
        db.add(event)
        await db.flush()
        return new_score

    async def compute_agent_weight(self, agent_id: uuid.UUID, db: AsyncSession) -> float:
        agent = await db.get(Agent, agent_id)
        if agent is None:
            return 0.0
        return float(agent.reputation_score) / 100.0

    def is_trusted_agent(self, agent: Agent) -> bool:
        settings = get_settings()
        probation_cutoff = utcnow() - timedelta(hours=settings.agent_probation_hours)
        registered_at = agent.registered_at
        if registered_at.tzinfo is None:
            registered_at = registered_at.replace(tzinfo=timezone.utc)
        return (
            bool(agent.is_active)
            and float(agent.reputation_score) >= settings.trusted_agent_min_reputation
            and registered_at <= probation_cutoff
        )

    async def get_reputation_history(
        self,
        agent_id: uuid.UUID,
        db: AsyncSession,
        limit: int = 50,
    ) -> list[ReputationEvent]:
        result = await db.execute(
            select(ReputationEvent)
            .where(ReputationEvent.agent_id == agent_id)
            .order_by(desc(ReputationEvent.created_at))
            .limit(limit)
        )
        return list(result.scalars())
