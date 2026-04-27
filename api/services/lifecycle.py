from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.cve import CVEEntry, LifecycleEvent
from api.models.enrichment import Enrichment
from api.models.base import utcnow

TERMINAL_STATES = {"published", "rejected"}


class LifecycleStateMachine:
    async def evaluate_transitions(self, cve_entry: CVEEntry, db: AsyncSession) -> str | None:
        if cve_entry.status in TERMINAL_STATES:
            return None

        result = await db.execute(select(Enrichment.enrichment_type).where(Enrichment.cve_entry_id == cve_entry.id))
        enrichment_types = set(result.scalars())
        original_status = cve_entry.status

        while True:
            next_state, reason = self._next_transition(cve_entry, enrichment_types)
            if next_state is None:
                break
            db.add(
                LifecycleEvent(
                    cve_entry_id=cve_entry.id,
                    from_status=cve_entry.status,
                    to_status=next_state,
                    reason=reason,
                )
            )
            cve_entry.status = next_state
            if next_state == "published":
                cve_entry.published_at = utcnow()
            if next_state in TERMINAL_STATES:
                break

        await db.flush()
        return cve_entry.status if cve_entry.status != original_status else None

    def _next_transition(self, cve_entry: CVEEntry, enrichment_types: set[str]) -> tuple[str | None, str | None]:
        if cve_entry.dispute_count >= 3 and cve_entry.dispute_count > cve_entry.corroboration_count:
            return "rejected", "dispute_count >= 3 and exceeds corroborations"

        if cve_entry.status == "discovered" and cve_entry.trusted_corroboration_count >= 3:
            return "triaged", "trusted_corroboration_count >= 3"

        if cve_entry.status == "triaged" and enrichment_types.intersection({"reference", "poc", "patch"}):
            return "enriched", "reference, poc, or patch enrichment exists"

        if cve_entry.status == "enriched" and "mitigation" in enrichment_types:
            return "mitigated", "mitigation enrichment exists"

        if cve_entry.status == "mitigated" and (
            (cve_entry.trusted_corroboration_count >= 5 and cve_entry.dispute_count == 0)
            or (cve_entry.trusted_corroboration_count >= 8 and cve_entry.dispute_count <= 1)
        ):
            return "verified", "trusted corroboration threshold reached with acceptable dispute count"

        if cve_entry.status == "verified" and float(cve_entry.confidence_score) >= 0.92:
            return "published", "auto-published because confidence_score >= 0.92"

        return None, None
