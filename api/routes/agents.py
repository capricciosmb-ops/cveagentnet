from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.agent_auth import api_key_prefix, create_agent_jwt, get_current_agent, hash_api_key, issue_api_key
from api.dependencies import get_db, get_redis
from api.models.agent import Agent, AgentSubscription
from api.schemas.agent import (
    AgentPublicProfile,
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentSubscriptionRequest,
    AgentSubscriptionResponse,
    AgentTokenResponse,
    RotateKeyResponse,
)
from api.services.audit import write_audit_log
from api.services.abuse import AbuseMonitor
from api.services.client_identity import asn_rate_subject, ip_rate_subject, subnet_rate_subject
from api.services.rate_limit import POLICIES, RedisRateLimiter
from api.services.webhook_security import UnsafeWebhookURLError, validate_webhook_url

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/register", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    payload: AgentRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    limiter = RedisRateLimiter(redis)
    await limiter.enforce(ip_rate_subject(request, "register"), POLICIES["register_ip"])
    await limiter.enforce(subnet_rate_subject(request, "register"), POLICIES["register_subnet"])
    asn_subject = asn_rate_subject(request, "register")
    if asn_subject:
        await limiter.enforce(asn_subject, POLICIES["register_asn"])
    api_key = issue_api_key()
    agent = Agent(
        agent_name=payload.agent_name,
        agent_type=payload.agent_type,
        tool_chain=payload.tool_chain,
        authorized_scopes=payload.authorized_scopes,
        api_key_prefix=api_key_prefix(api_key),
        api_key_hash=hash_api_key(api_key),
    )
    db.add(agent)
    await db.flush()
    await write_audit_log(
        db,
        actor_id=agent.id,
        actor_type="agent",
        action="agent.register",
        entity_type="agent",
        entity_id=agent.id,
        ip_address=request.client.host if request.client else None,
        payload=payload.model_dump(mode="json"),
    )
    await AbuseMonitor().flag_registration_burst(agent.id, request.client.host if request.client else None, db)
    await db.commit()
    return AgentRegisterResponse(agent_id=agent.id, api_key=api_key)


@router.post("/token", response_model=AgentTokenResponse)
async def issue_jwt_for_agent(agent: Agent = Depends(get_current_agent), db: AsyncSession = Depends(get_db)):
    token = create_agent_jwt(agent.id)
    await db.commit()
    return AgentTokenResponse(access_token=token)


@router.get("/leaderboard", response_model=list[AgentPublicProfile])
async def leaderboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.is_active.is_(True)).order_by(desc(Agent.reputation_score)).limit(50))
    return list(result.scalars())


@router.get("/{agent_id}", response_model=AgentPublicProfile)
async def get_agent(agent_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    agent = await db.get(Agent, agent_id)
    if agent is None or not agent.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.post("/{agent_id}/rotate-key", response_model=RotateKeyResponse)
async def rotate_key(
    agent_id: uuid.UUID,
    request: Request,
    current_agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    if current_agent.id != agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agents may rotate only their own key")
    api_key = issue_api_key()
    current_agent.api_key_prefix = api_key_prefix(api_key)
    current_agent.api_key_hash = hash_api_key(api_key)
    await write_audit_log(
        db,
        actor_id=current_agent.id,
        actor_type="agent",
        action="agent.rotate_key",
        entity_type="agent",
        entity_id=current_agent.id,
        ip_address=request.client.host if request.client else None,
        payload={"agent_id": str(agent_id)},
    )
    await db.commit()
    return RotateKeyResponse(agent_id=current_agent.id, api_key=api_key)


@router.post("/{agent_id}/subscriptions", response_model=AgentSubscriptionResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    agent_id: uuid.UUID,
    payload: AgentSubscriptionRequest,
    request: Request,
    current_agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    if current_agent.id != agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agents may manage only their own subscriptions")
    try:
        safe_webhook_url = validate_webhook_url(str(payload.webhook_url))
    except UnsafeWebhookURLError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    subscription = AgentSubscription(
        agent_id=agent_id,
        subscribe_to=payload.subscribe_to,
        value=payload.value,
        webhook_url=safe_webhook_url,
        events=list(dict.fromkeys(payload.events)),
    )
    db.add(subscription)
    await db.flush()
    await write_audit_log(
        db,
        actor_id=current_agent.id,
        actor_type="agent",
        action="agent.subscription.create",
        entity_type="agent_subscription",
        entity_id=subscription.id,
        ip_address=request.client.host if request.client else None,
        payload=payload.model_dump(mode="json"),
    )
    await db.commit()
    return AgentSubscriptionResponse(
        id=subscription.id,
        agent_id=subscription.agent_id,
        subscribe_to=subscription.subscribe_to,
        value=subscription.value,
        webhook_url=subscription.webhook_url,
        events=subscription.events,
    )
