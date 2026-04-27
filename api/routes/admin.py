from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.admin_auth import require_admin
from api.dependencies import get_db
from api.models.agent import Agent
from api.models.abuse import AbuseSignal
from api.models.audit import AuditLog
from api.schemas.admin import AdminAbuseSignal, AdminAgentProfile, AdminAgentUpdate, AdminAuditLogEntry
from api.services.audit import write_audit_log

router = APIRouter(prefix="/admin", tags=["admin"], include_in_schema=False)


@router.get("/agents", response_model=list[AdminAgentProfile])
async def list_agents(
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).order_by(desc(Agent.registered_at)).limit(200))
    return list(result.scalars())


@router.patch("/agents/{agent_id}", response_model=AdminAgentProfile)
async def update_agent(
    agent_id: uuid.UUID,
    payload: AdminAgentUpdate,
    request: Request,
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    changed: dict[str, object] = {}
    if payload.is_active is not None and agent.is_active != payload.is_active:
        agent.is_active = payload.is_active
        changed["is_active"] = payload.is_active
    if payload.authorized_scopes is not None and agent.authorized_scopes != payload.authorized_scopes:
        agent.authorized_scopes = payload.authorized_scopes
        changed["authorized_scopes"] = payload.authorized_scopes
    if payload.reputation_score is not None and float(agent.reputation_score) != payload.reputation_score:
        agent.reputation_score = payload.reputation_score
        changed["reputation_score"] = payload.reputation_score

    await write_audit_log(
        db,
        actor_id=None,
        actor_type="admin",
        action="admin.agent.update",
        entity_type="agent",
        entity_id=agent.id,
        ip_address=request.client.host if request.client else None,
        payload={"agent_id": str(agent_id), "changed": changed},
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("/audit-log", response_model=list[AdminAuditLogEntry])
async def audit_log(
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
):
    result = await db.execute(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit))
    return list(result.scalars())


@router.get("/abuse-signals", response_model=list[AdminAbuseSignal])
async def abuse_signals(
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
):
    result = await db.execute(select(AbuseSignal).order_by(desc(AbuseSignal.created_at)).limit(limit))
    return list(result.scalars())
