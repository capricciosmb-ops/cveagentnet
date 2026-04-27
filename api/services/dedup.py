from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.cve import CVEEntry
from api.schemas.cve_submission import CVESubmission
from api.services.embedder import LocalHashEmbedder, cosine_similarity


@dataclass
class DeduplicationResult:
    is_duplicate: bool
    match_type: str | None = None
    matched_entry: CVEEntry | None = None
    similarity_score: float | None = None


class DeduplicationService:
    """Two-stage deduplication: exact fingerprint first, then pgvector similarity."""

    def compute_fingerprint(self, title: str, target_scope: str, tool_chain: list[str]) -> str:
        normalized = f"{title.lower().strip()}|{target_scope.strip()}|{','.join(sorted(tool_chain))}"
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    async def check_hash_duplicate(self, fingerprint: str, db: AsyncSession) -> CVEEntry | None:
        result = await db.execute(select(CVEEntry).where(CVEEntry.provisional_hash == fingerprint))
        return result.scalar_one_or_none()

    async def check_cve_id_duplicate(self, cve_id: str | None, db: AsyncSession) -> CVEEntry | None:
        if cve_id is None:
            return None
        result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
        return result.scalar_one_or_none()

    async def check_semantic_duplicate(
        self,
        title: str,
        description: str,
        embedder: LocalHashEmbedder,
        db: AsyncSession,
        threshold: float = 0.85,
    ) -> list[tuple[CVEEntry, float]]:
        query_embedding = embedder.embed(f"{title}\n\n{description}")
        if db.bind and db.bind.dialect.name == "postgresql":
            distance = CVEEntry.embedding.cosine_distance(query_embedding)  # type: ignore[attr-defined]
            result = await db.execute(
                select(CVEEntry, (1 - distance).label("similarity"))
                .where(CVEEntry.embedding.is_not(None))
                .order_by(distance)
                .limit(10)
            )
            return [(entry, float(score)) for entry, score in result.all() if float(score) >= threshold]

        result = await db.execute(select(CVEEntry).where(CVEEntry.embedding.is_not(None)))
        matches = []
        for entry in result.scalars():
            score = cosine_similarity(query_embedding, entry.embedding)
            if score >= threshold:
                matches.append((entry, score))
        return sorted(matches, key=lambda item: item[1], reverse=True)

    async def run_full_check(
        self,
        submission: CVESubmission,
        embedder: LocalHashEmbedder,
        db: AsyncSession,
        tool_chain: list[str] | None = None,
    ) -> DeduplicationResult:
        cve_id_match = await self.check_cve_id_duplicate(submission.finding.cve_id, db)
        if cve_id_match:
            return DeduplicationResult(True, "cve_id", cve_id_match, 1.0)
        tools = tool_chain or []
        fingerprint = self.compute_fingerprint(submission.finding.title, submission.target_scope, tools)
        hash_match = await self.check_hash_duplicate(fingerprint, db)
        if hash_match:
            return DeduplicationResult(True, "hash", hash_match, 1.0)
        semantic_matches = await self.check_semantic_duplicate(
            submission.finding.title, submission.finding.description, embedder, db
        )
        if semantic_matches:
            entry, score = semantic_matches[0]
            return DeduplicationResult(True, "semantic", entry, score)
        return DeduplicationResult(False)
