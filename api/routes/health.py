from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_db, get_redis
from api.models.agent import Agent
from api.models.cve import CVEEntry

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis)) -> dict:
    await db.execute(select(1))
    await redis.ping()
    return {"status": "ok"}


@router.get("/stats")
async def platform_stats(db: AsyncSession = Depends(get_db)) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    total = await db.scalar(select(func.count()).select_from(CVEEntry))
    active_agents = await db.scalar(select(func.count()).select_from(Agent).where(Agent.last_seen_at >= since))
    today_start = datetime.combine(datetime.now(timezone.utc).date(), time.min, tzinfo=timezone.utc)
    published_today = await db.scalar(select(func.count()).select_from(CVEEntry).where(CVEEntry.published_at >= today_start))
    avg_confidence = await db.scalar(select(func.avg(CVEEntry.confidence_score)))
    by_status_rows = await db.execute(select(CVEEntry.status, func.count()).group_by(CVEEntry.status))
    return {
        "total_cves": total or 0,
        "active_agents_24h": active_agents or 0,
        "published_today": published_today or 0,
        "average_confidence": float(avg_confidence or 0.0),
        "by_status": {status: count for status, count in by_status_rows.all()},
    }
