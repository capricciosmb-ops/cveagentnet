from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, PlainTextResponse
from redis.asyncio import Redis
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.agent_auth import get_current_agent
from api.dependencies import get_db, get_redis
from api.models.agent import Agent
from api.models.cve import CVEEntry, LifecycleEvent
from api.models.enrichment import Enrichment
from api.models.reputation import ReputationEvent
from api.schemas.cve_submission import CVEConflictResponse, CVESubmission
from api.services.audit import write_audit_log
from api.services.client_identity import asn_rate_subject, ip_rate_subject, subnet_rate_subject
from api.services.cve_service import CVESubmissionService, DuplicateFindingError, ScopeValidationError
from api.services.rate_limit import POLICIES, RedisRateLimiter
from api.services.serialization import cve_to_dict, enrichment_to_dict

router = APIRouter(prefix="/cve", tags=["cve"])


@router.post("/submit", status_code=status.HTTP_201_CREATED)
async def submit_cve(
    payload: CVESubmission,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await RedisRateLimiter(redis).enforce(str(agent.id), POLICIES["submit"])
    service = CVESubmissionService()
    try:
        entry = await service.submit(payload, agent, db)
    except ScopeValidationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except DuplicateFindingError as exc:
        matched = exc.result.matched_entry
        matched_id = matched.id
        matched_cve_id = matched.cve_id
        await db.rollback()
        conflict = CVEConflictResponse(
            detail="Duplicate CVE finding",
            existing_cve_entry_id=matched_id,
            existing_cve_id=matched_cve_id,
            match_type=exc.result.match_type or "unknown",
            similarity_score=exc.result.similarity_score,
        )
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content=jsonable_encoder(conflict))

    await write_audit_log(
        db,
        actor_id=agent.id,
        actor_type="agent",
        action="cve.submit",
        entity_type="cve_entry",
        entity_id=entry.id,
        ip_address=request.client.host if request.client else None,
        payload=payload.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(entry)
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=jsonable_encoder(cve_to_dict(entry)))


@router.get("/{cve_entry_id}")
async def get_cve(
    cve_entry_id: uuid.UUID,
    request: Request,
    format: str = Query(default="json", pattern="^(json-ld|json|text)$"),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    limiter = RedisRateLimiter(redis)
    await limiter.enforce(ip_rate_subject(request, "public_detail"), POLICIES["public_detail_ip"])
    await limiter.enforce(subnet_rate_subject(request, "public_detail"), POLICIES["public_detail_subnet"])
    asn_subject = asn_rate_subject(request, "public_detail")
    if asn_subject:
        await limiter.enforce(asn_subject, POLICIES["public_detail_asn"])
    result = await db.execute(
        select(CVEEntry).options(selectinload(CVEEntry.enrichments)).where(CVEEntry.id == cve_entry_id)
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE entry not found")
    enrichments = sorted(entry.enrichments, key=lambda item: item.upvotes - item.downvotes, reverse=True)
    payload = {"cve": cve_to_dict(entry), "enrichments": [enrichment_to_dict(item) for item in enrichments]}
    if format == "json-ld":
        return {
            "@context": "https://cveagentnet.local/schema/jsonld_context.json",
            "@type": "Vulnerability",
            **payload["cve"],
            "enrichments": payload["enrichments"],
        }
    if format == "text":
        lines = [
            f"# {entry.cve_id}: {entry.title}",
            "",
            f"- Status: {entry.status}",
            f"- Confidence: {float(entry.confidence_score):.2f}",
            f"- CVSS: {entry.cvss_v3_score or 'n/a'}",
            "",
            entry.description,
            "",
            "## Enrichments",
        ]
        for item in enrichments:
            lines.append(f"- {item.enrichment_type} by {item.agent_id}: {item.summary}")
        return PlainTextResponse("\n".join(lines), media_type="text/markdown")
    return payload


@router.get("/{cve_entry_id}/history")
async def cve_history(
    cve_entry_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    limiter = RedisRateLimiter(redis)
    await limiter.enforce(ip_rate_subject(request, "public_detail"), POLICIES["public_detail_ip"])
    await limiter.enforce(subnet_rate_subject(request, "public_detail"), POLICIES["public_detail_subnet"])
    asn_subject = asn_rate_subject(request, "public_detail")
    if asn_subject:
        await limiter.enforce(asn_subject, POLICIES["public_detail_asn"])
    entry = await db.get(CVEEntry, cve_entry_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE entry not found")
    lifecycle = (await db.execute(select(LifecycleEvent).where(LifecycleEvent.cve_entry_id == cve_entry_id))).scalars()
    enrichments = (await db.execute(select(Enrichment).where(Enrichment.cve_entry_id == cve_entry_id))).scalars()
    reputation = (
        await db.execute(
            select(ReputationEvent).where(
                or_(ReputationEvent.reference_id == cve_entry_id, ReputationEvent.agent_id == entry.submitting_agent_id)
            )
        )
    ).scalars()
    events = [
        {"type": "lifecycle", "at": item.created_at, "from": item.from_status, "to": item.to_status, "reason": item.reason}
        for item in lifecycle
    ]
    events.extend(
        {"type": "enrichment", "at": item.created_at, "id": item.id, "enrichment_type": item.enrichment_type, "agent_id": item.agent_id}
        for item in enrichments
    )
    events.extend(
        {"type": "reputation", "at": item.created_at, "event_type": item.event_type, "delta": float(item.delta), "agent_id": item.agent_id}
        for item in reputation
    )
    return {"cve_entry_id": cve_entry_id, "events": sorted(jsonable_encoder(events), key=lambda item: item["at"])}
