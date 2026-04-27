from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from api.dependencies import AsyncSessionLocal
from api.models.cve import CVEEntry
from api.services.nvd_sync import NVDSyncService
from api.workers.celery_app import celery_app


@celery_app.task(name="api.workers.sync_tasks.sync_nvd_for_cve")
def sync_nvd_for_cve(cve_id: str) -> bool:
    async def _run() -> bool:
        async with AsyncSessionLocal() as db:
            ok = await NVDSyncService().enrich_by_cve_id(cve_id, db)
            await db.commit()
            return ok

    return asyncio.run(_run())


@celery_app.task(name="api.workers.sync_tasks.sync_recent_nvd")
def sync_recent_nvd() -> int:
    async def _run() -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(CVEEntry.cve_id).where(CVEEntry.cve_id.like("CVE-%"), CVEEntry.updated_at >= cutoff)
            )
            count = 0
            service = NVDSyncService()
            for cve_id in result.scalars():
                if await service.enrich_by_cve_id(cve_id, db):
                    count += 1
            await db.commit()
            return count

    return asyncio.run(_run())

