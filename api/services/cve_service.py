from __future__ import annotations

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from api.models.agent import Agent
from api.models.cve import CVEEntry, LifecycleEvent
from api.models.base import utcnow
from api.schemas.cve_submission import CVESubmission
from api.services.cvss import validate_cvss_vector
from api.services.dedup import DeduplicationService, DeduplicationResult
from api.services.embedder import LocalHashEmbedder
from api.services.sanitizer import sanitize_payload_sample

logger = logging.getLogger(__name__)


class DuplicateFindingError(Exception):
    def __init__(self, result: DeduplicationResult):
        super().__init__("Duplicate CVE finding")
        self.result = result


class ScopeValidationError(Exception):
    pass


class CVESubmissionService:
    def __init__(self, dedup: DeduplicationService | None = None, embedder: LocalHashEmbedder | None = None):
        self.dedup = dedup or DeduplicationService()
        self.embedder = embedder or LocalHashEmbedder()

    async def submit(self, submission: CVESubmission, agent: Agent, db: AsyncSession) -> CVEEntry:
        if submission.target_scope not in (agent.authorized_scopes or []):
            raise ScopeValidationError("target_scope is not registered for this agent")

        finding = submission.finding
        cvss = validate_cvss_vector(finding.cvss_v3_vector, finding.cvss_v3_score)

        cve_id_duplicate = await self.dedup.check_cve_id_duplicate(finding.cve_id, db)
        if cve_id_duplicate:
            raise DuplicateFindingError(DeduplicationResult(True, "cve_id", cve_id_duplicate, 1.0))

        fingerprint = self.dedup.compute_fingerprint(finding.title, submission.target_scope, agent.tool_chain)

        hash_duplicate = await self.dedup.check_hash_duplicate(fingerprint, db)
        if hash_duplicate:
            raise DuplicateFindingError(DeduplicationResult(True, "hash", hash_duplicate, 1.0))

        semantic_duplicates = await self.dedup.check_semantic_duplicate(
            finding.title, finding.description, self.embedder, db
        )
        if semantic_duplicates:
            match, score = semantic_duplicates[0]
            raise DuplicateFindingError(DeduplicationResult(True, "semantic", match, score))

        cve_id = finding.cve_id or f"PROVISIONAL-{fingerprint[:16]}"
        embedding = self.embedder.embed(f"{finding.title}\n\n{finding.description}")
        entry = CVEEntry(
            cve_id=cve_id,
            provisional_hash=fingerprint,
            title=finding.title,
            description=finding.description,
            cwe_id=finding.cwe_id,
            cvss_v3_vector=cvss.normalized_vector if cvss else None,
            cvss_v3_score=cvss.computed_score if cvss else finding.cvss_v3_score,
            epss_score=finding.epss_score,
            affected_products=[product.model_dump() for product in finding.affected_products],
            exploit_chain=[step.model_dump() for step in finding.exploit_chain],
            reproduction_steps=finding.reproduction_steps,
            payload_sample=sanitize_payload_sample(finding.payload_sample),
            confidence_score=finding.confidence_score,
            tags=finding.tags,
            references=[str(reference) for reference in finding.references],
            status="discovered",
            submitting_agent_id=agent.id,
            target_scope=submission.target_scope,
            tool_chain=agent.tool_chain,
            embedding=embedding,
        )
        db.add(entry)
        agent.total_submissions += 1
        agent.last_seen_at = utcnow()
        await db.flush()
        db.add(
            LifecycleEvent(
                cve_entry_id=entry.id,
                from_status=None,
                to_status="discovered",
                reason="initial submission accepted",
            )
        )
        await db.flush()

        if finding.cve_id:
            try:
                from api.workers.sync_tasks import sync_nvd_for_cve

                sync_nvd_for_cve.delay(finding.cve_id)
            except Exception as exc:
                logger.warning("Failed to enqueue NVD lookup for %s: %s", finding.cve_id, exc)

        return entry
