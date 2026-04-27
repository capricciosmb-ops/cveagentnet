from __future__ import annotations

from datetime import datetime, time, timezone

from sqlalchemy import asc, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.agent import Agent
from api.models.cve import CVEEntry
from api.schemas.search import SearchParams, SearchResult
from api.services.embedder import LocalHashEmbedder, cosine_similarity
from api.services.serialization import cve_to_dict


class SearchService:
    def __init__(self, embedder: LocalHashEmbedder | None = None):
        self.embedder = embedder or LocalHashEmbedder()

    async def search(self, params: SearchParams, db: AsyncSession) -> list[SearchResult]:
        if params.q:
            entries_with_scores = await self._semantic_candidates(params, db)
        else:
            entries_with_scores = [(entry, None) for entry in await self._structured_query(params, db)]

        filtered = [item for item in entries_with_scores if self._matches_python_filters(item[0], params)]
        sorted_items = self._sort(filtered, params)
        page = sorted_items[params.offset : params.offset + params.limit]
        results = []
        for entry, score in page:
            agent = await db.get(Agent, entry.submitting_agent_id)
            results.append(
                SearchResult(
                    cve=cve_to_dict(entry),
                    similarity_score=score,
                    corroboration_count=entry.corroboration_count,
                    agent_reputation_score=float(agent.reputation_score) if agent else None,
                )
            )
        return results

    async def _semantic_candidates(self, params: SearchParams, db: AsyncSession) -> list[tuple[CVEEntry, float]]:
        query_embedding = self.embedder.embed(params.q or "")
        if db.bind and db.bind.dialect.name == "postgresql":
            distance = CVEEntry.embedding.cosine_distance(query_embedding)  # type: ignore[attr-defined]
            stmt = select(CVEEntry, (1 - distance).label("similarity")).where(CVEEntry.embedding.is_not(None)).order_by(distance)
            stmt = self._apply_sql_filters(stmt, params, include_arrays=False).limit(max(params.limit + params.offset, 50))
            result = await db.execute(stmt)
            return [(entry, float(score)) for entry, score in result.all()]

        stmt = self._apply_sql_filters(select(CVEEntry), params, include_arrays=False)
        result = await db.execute(stmt)
        scored = [
            (entry, cosine_similarity(query_embedding, entry.embedding))
            for entry in result.scalars()
            if entry.embedding is not None
        ]
        return sorted(scored, key=lambda item: item[1], reverse=True)

    async def _structured_query(self, params: SearchParams, db: AsyncSession) -> list[CVEEntry]:
        stmt = self._apply_sql_filters(select(CVEEntry), params, include_arrays=db.bind.dialect.name == "postgresql" if db.bind else True)
        if params.sort == "confidence":
            stmt = stmt.order_by(desc(CVEEntry.confidence_score))
        elif params.sort == "cvss":
            stmt = stmt.order_by(desc(CVEEntry.cvss_v3_score))
        elif params.sort == "corroboration":
            stmt = stmt.order_by(desc(CVEEntry.corroboration_count))
        else:
            stmt = stmt.order_by(desc(CVEEntry.created_at))
        stmt = stmt.offset(params.offset).limit(params.limit)
        result = await db.execute(stmt)
        return list(result.scalars())

    def _apply_sql_filters(self, stmt, params: SearchParams, include_arrays: bool):
        if params.cve_id:
            stmt = stmt.where(CVEEntry.cve_id == params.cve_id)
        if params.cwe_id:
            stmt = stmt.where(CVEEntry.cwe_id == params.cwe_id)
        if params.status:
            stmt = stmt.where(CVEEntry.status == params.status)
        if params.min_cvss is not None:
            stmt = stmt.where(CVEEntry.cvss_v3_score >= params.min_cvss)
        if params.max_cvss is not None:
            stmt = stmt.where(CVEEntry.cvss_v3_score <= params.max_cvss)
        if params.min_conf is not None:
            stmt = stmt.where(CVEEntry.confidence_score >= params.min_conf)
        if params.agent_id:
            stmt = stmt.where(CVEEntry.submitting_agent_id == params.agent_id)
        if params.since:
            stmt = stmt.where(CVEEntry.created_at >= datetime.combine(params.since, time.min, tzinfo=timezone.utc))
        if include_arrays and params.tool:
            stmt = stmt.where(CVEEntry.tool_chain.contains([params.tool]))
        if include_arrays and params.tags:
            stmt = stmt.where(CVEEntry.tags.contains([tag.strip() for tag in params.tags.split(",") if tag.strip()]))
        return stmt

    def _matches_python_filters(self, entry: CVEEntry, params: SearchParams) -> bool:
        if params.tool and params.tool not in (entry.tool_chain or []):
            return False
        if params.tags:
            wanted = {tag.strip() for tag in params.tags.split(",") if tag.strip()}
            if not wanted.issubset(set(entry.tags or [])):
                return False
        return True

    def _sort(self, items: list[tuple[CVEEntry, float | None]], params: SearchParams) -> list[tuple[CVEEntry, float | None]]:
        if params.q:
            return sorted(items, key=lambda item: item[1] or 0.0, reverse=True)
        if params.sort == "confidence":
            return sorted(items, key=lambda item: float(item[0].confidence_score), reverse=True)
        if params.sort == "cvss":
            return sorted(items, key=lambda item: float(item[0].cvss_v3_score or 0.0), reverse=True)
        if params.sort == "corroboration":
            return sorted(items, key=lambda item: item[0].corroboration_count, reverse=True)
        return sorted(items, key=lambda item: item[0].created_at, reverse=True)

