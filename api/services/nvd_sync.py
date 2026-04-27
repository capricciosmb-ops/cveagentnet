from __future__ import annotations

import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.models.cve import CVEEntry

logger = logging.getLogger(__name__)


class NVDSyncService:
    async def enrich_by_cve_id(self, cve_id: str, db: AsyncSession) -> bool:
        settings = get_settings()
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
            )
        if response.status_code != 200:
            logger.warning("NVD lookup failed for %s: %s", cve_id, response.status_code)
            return False
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return False
        result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        refs = vulnerabilities[0].get("cve", {}).get("references", {}).get("referenceData", [])
        existing = set(entry.references or [])
        for ref in refs:
            url = ref.get("url")
            if url:
                existing.add(url)
        entry.references = sorted(existing)
        await db.flush()
        return True

