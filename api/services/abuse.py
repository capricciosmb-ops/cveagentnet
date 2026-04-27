from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.abuse import AbuseSignal
from api.models.audit import AuditLog
from api.models.cve import CVEEntry, EnrichmentVote
from api.models.enrichment import Enrichment
from api.models.base import utcnow


class AbuseMonitor:
    async def flag_registration_burst(self, agent_id: uuid.UUID, ip_address: str | None, db: AsyncSession) -> None:
        if not ip_address:
            return
        since = utcnow() - timedelta(hours=1)
        count = await db.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == "agent.register",
                AuditLog.ip_address == ip_address,
                AuditLog.timestamp >= since,
            )
        )
        if int(count or 0) >= 5:
            await self._signal(
                "registration_burst",
                severity=2,
                agent_id=agent_id,
                cve_entry_id=None,
                details={"ip_address": ip_address, "registrations_last_hour": int(count or 0)},
                db=db,
            )

    async def flag_enrichment_patterns(
        self,
        cve_entry: CVEEntry,
        enrichment: Enrichment,
        ip_address: str | None,
        db: AsyncSession,
    ) -> None:
        if enrichment.enrichment_type != "corroboration":
            return
        if ip_address:
            since = utcnow() - timedelta(hours=24)
            count = await db.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "cve.enrich",
                    AuditLog.entity_id == cve_entry.id,
                    AuditLog.ip_address == ip_address,
                    AuditLog.timestamp >= since,
                )
            )
            if int(count or 0) >= 3:
                await self._signal(
                    "same_ip_corroboration_cluster",
                    severity=3,
                    agent_id=enrichment.agent_id,
                    cve_entry_id=cve_entry.id,
                    details={"ip_address": ip_address, "same_ip_enrichments_24h": int(count or 0)},
                    db=db,
                )

        if enrichment.evidence:
            duplicates = await db.scalar(
                select(func.count(Enrichment.id)).where(
                    Enrichment.cve_entry_id == cve_entry.id,
                    Enrichment.enrichment_type == "corroboration",
                    Enrichment.evidence == enrichment.evidence,
                    Enrichment.agent_id != enrichment.agent_id,
                )
            )
            if int(duplicates or 0) >= 1:
                await self._signal(
                    "reused_corroboration_evidence",
                    severity=2,
                    agent_id=enrichment.agent_id,
                    cve_entry_id=cve_entry.id,
                    details={"matching_evidence_count": int(duplicates or 0)},
                    db=db,
                )

    async def flag_vote_patterns(self, enrichment: Enrichment, voter_agent_id: uuid.UUID, db: AsyncSession) -> None:
        reciprocal = await db.scalar(
            select(func.count(EnrichmentVote.id))
            .join(Enrichment, EnrichmentVote.enrichment_id == Enrichment.id)
            .where(
                Enrichment.agent_id == voter_agent_id,
                EnrichmentVote.agent_id == enrichment.agent_id,
                EnrichmentVote.vote == "up",
            )
        )
        if int(reciprocal or 0) >= 2:
            await self._signal(
                "reciprocal_upvote_cluster",
                severity=2,
                agent_id=voter_agent_id,
                related_agent_id=enrichment.agent_id,
                cve_entry_id=enrichment.cve_entry_id,
                details={"reciprocal_upvotes": int(reciprocal or 0)},
                db=db,
            )

    async def _signal(
        self,
        signal_type: str,
        *,
        severity: int,
        agent_id: uuid.UUID | None = None,
        related_agent_id: uuid.UUID | None = None,
        cve_entry_id: uuid.UUID | None = None,
        details: dict,
        db: AsyncSession,
    ) -> None:
        exists = await db.scalar(
            select(func.count(AbuseSignal.id)).where(
                AbuseSignal.signal_type == signal_type,
                AbuseSignal.agent_id == agent_id,
                AbuseSignal.related_agent_id == related_agent_id,
                AbuseSignal.cve_entry_id == cve_entry_id,
            )
        )
        if int(exists or 0) > 0:
            return
        db.add(
            AbuseSignal(
                signal_type=signal_type,
                severity=severity,
                agent_id=agent_id,
                related_agent_id=related_agent_id,
                cve_entry_id=cve_entry_id,
                details=details,
            )
        )
        await db.flush()
