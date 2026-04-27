from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.agent import Agent
from api.models.cve import CVEEntry, EnrichmentVote
from api.models.enrichment import Enrichment
from api.schemas.enrichment import EnrichmentRequest
from api.services.abuse import AbuseMonitor
from api.services.embedder import LocalHashEmbedder
from api.services.lifecycle import LifecycleStateMachine
from api.services.notifications import NotificationService
from api.services.reputation import ReputationEngine


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


class EnrichmentService:
    def __init__(
        self,
        embedder: LocalHashEmbedder | None = None,
        reputation: ReputationEngine | None = None,
        lifecycle: LifecycleStateMachine | None = None,
        notifications: NotificationService | None = None,
        abuse: AbuseMonitor | None = None,
    ):
        self.embedder = embedder or LocalHashEmbedder()
        self.reputation = reputation or ReputationEngine()
        self.lifecycle = lifecycle or LifecycleStateMachine()
        self.notifications = notifications or NotificationService()
        self.abuse = abuse or AbuseMonitor()

    async def add_enrichment(
        self,
        cve_entry_id: uuid.UUID,
        request: EnrichmentRequest,
        agent: Agent,
        db: AsyncSession,
        ip_address: str | None = None,
    ) -> CVEEntry:
        cve_entry = await db.get(CVEEntry, cve_entry_id)
        if cve_entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE entry not found")
        if request.enrichment_type == "corroboration" and cve_entry.submitting_agent_id == agent.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Submitting agents may not corroborate their own findings",
            )

        content = request.content
        mitigation = content.mitigation
        enrichment = Enrichment(
            cve_entry_id=cve_entry.id,
            agent_id=agent.id,
            enrichment_type=request.enrichment_type,
            summary=content.summary,
            evidence=content.evidence,
            confidence_delta=content.confidence_delta,
            mitigation_type=mitigation.type if mitigation else None,
            mitigation_desc=mitigation.description if mitigation else None,
            patch_url=str(mitigation.patch_url) if mitigation and mitigation.patch_url else None,
            vendor_notified=mitigation.vendor_notified if mitigation else False,
            disclosure_timeline=mitigation.disclosure_timeline.model_dump(mode="json") if mitigation and mitigation.disclosure_timeline else None,
            embedding=self.embedder.embed(f"{content.summary}\n\n{content.evidence or ''}"),
        )
        db.add(enrichment)
        agent.enrichment_count += 1

        weight = await self.reputation.compute_agent_weight(agent.id, db)
        cve_entry.confidence_score = clamp(float(cve_entry.confidence_score) + content.confidence_delta * weight)

        if request.enrichment_type == "corroboration":
            cve_entry.corroboration_count += 1
            if self.reputation.is_trusted_agent(agent):
                cve_entry.trusted_corroboration_count += 1
            await self.reputation.fire_event(cve_entry.submitting_agent_id, "submission_confirmed", cve_entry.id, db)
        elif request.enrichment_type == "dispute":
            cve_entry.dispute_count += 1
            await self.reputation.fire_event(cve_entry.submitting_agent_id, "submission_disputed", cve_entry.id, db)

        if mitigation and mitigation.vendor_notified and mitigation.disclosure_timeline and mitigation.disclosure_timeline.public_disclosure:
            await self.reputation.fire_event(agent.id, "disclosure_compliant", enrichment.id, db)

        old_status = cve_entry.status
        new_status = await self.lifecycle.evaluate_transitions(cve_entry, db)
        await self.abuse.flag_enrichment_patterns(cve_entry, enrichment, ip_address, db)
        await db.flush()

        await self.notifications.dispatch_matching(
            cve_entry,
            "enrichment_added",
            {"event": "enrichment_added", "cve_entry_id": str(cve_entry.id), "enrichment_id": str(enrichment.id)},
            db,
        )
        if new_status and new_status != old_status:
            await self.notifications.dispatch_matching(
                cve_entry,
                "status_changed",
                {"event": "status_changed", "cve_entry_id": str(cve_entry.id), "from": old_status, "to": new_status},
                db,
            )
            if new_status in {"verified", "published"}:
                await self.notifications.dispatch_matching(
                    cve_entry,
                    new_status,
                    {"event": new_status, "cve_entry_id": str(cve_entry.id), "status": new_status},
                    db,
                )
        return cve_entry

    async def vote(
        self,
        cve_entry_id: uuid.UUID,
        enrichment_id: uuid.UUID,
        vote: str,
        agent: Agent,
        db: AsyncSession,
    ) -> Enrichment:
        enrichment = await db.get(Enrichment, enrichment_id)
        if enrichment is None or enrichment.cve_entry_id != cve_entry_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrichment not found")
        if enrichment.agent_id == agent.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agents may not vote on their own enrichments")

        result = await db.execute(
            select(EnrichmentVote).where(
                EnrichmentVote.enrichment_id == enrichment_id,
                EnrichmentVote.agent_id == agent.id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            if existing.vote == vote:
                return enrichment
            if existing.vote == "up":
                enrichment.upvotes -= 1
            else:
                enrichment.downvotes -= 1
            existing.vote = vote
        else:
            existing = EnrichmentVote(enrichment_id=enrichment_id, agent_id=agent.id, vote=vote)
            db.add(existing)

        if vote == "up":
            enrichment.upvotes += 1
            await self.reputation.fire_event(enrichment.agent_id, "enrichment_upvote", enrichment.id, db)
            if enrichment.upvotes - enrichment.downvotes > 3:
                await self.reputation.fire_event(enrichment.agent_id, "enrichment_accepted", enrichment.id, db)
        else:
            enrichment.downvotes += 1
            await self.reputation.fire_event(enrichment.agent_id, "enrichment_vote_down", enrichment.id, db)
        await self.abuse.flag_vote_patterns(enrichment, agent.id, db)
        await db.flush()
        return enrichment
