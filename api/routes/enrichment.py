from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.agent_auth import get_current_agent
from api.dependencies import get_db, get_redis
from api.models.agent import Agent
from api.schemas.enrichment import EnrichmentRequest, VoteRequest
from api.services.audit import write_audit_log
from api.services.enrichment_service import EnrichmentService
from api.services.rate_limit import POLICIES, RedisRateLimiter
from api.services.serialization import cve_to_dict, enrichment_to_dict

router = APIRouter(prefix="/cve", tags=["enrichment"])


@router.post("/{cve_entry_id}/enrich")
async def enrich_cve(
    cve_entry_id: uuid.UUID,
    payload: EnrichmentRequest,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await RedisRateLimiter(redis).enforce(str(agent.id), POLICIES["enrich"])
    entry = await EnrichmentService().add_enrichment(
        cve_entry_id,
        payload,
        agent,
        db,
        ip_address=request.client.host if request.client else None,
    )
    await write_audit_log(
        db,
        actor_id=agent.id,
        actor_type="agent",
        action="cve.enrich",
        entity_type="cve_entry",
        entity_id=entry.id,
        ip_address=request.client.host if request.client else None,
        payload=payload.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(entry)
    return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(cve_to_dict(entry)))


@router.post("/{cve_entry_id}/enrichments/{enrichment_id}/vote")
async def vote_enrichment(
    cve_entry_id: uuid.UUID,
    enrichment_id: uuid.UUID,
    payload: VoteRequest,
    request: Request,
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await RedisRateLimiter(redis).enforce(str(agent.id), POLICIES["vote"])
    enrichment = await EnrichmentService().vote(cve_entry_id, enrichment_id, payload.vote, agent, db)
    await write_audit_log(
        db,
        actor_id=agent.id,
        actor_type="agent",
        action="enrichment.vote",
        entity_type="enrichment",
        entity_id=enrichment.id,
        ip_address=request.client.host if request.client else None,
        payload=payload.model_dump(mode="json"),
    )
    await db.commit()
    return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(enrichment_to_dict(enrichment)))
