from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.base import utcnow
from api.models.cve import CVEEntry

logger = logging.getLogger(__name__)

FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class EPSSLookupResult:
    found: bool
    score: float | None = None
    percentile: float | None = None
    epss_date: date | None = None


class FIRSTEPSSService:
    """Fetch authoritative EPSS probability metadata from FIRST for published CVEs."""

    async def lookup_by_cve_id(self, cve_id: str) -> EPSSLookupResult | None:
        if not CVE_ID_RE.match(cve_id):
            return None

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                response = await client.get(FIRST_EPSS_URL, params={"cve": cve_id})
            except httpx.HTTPError as exc:
                logger.warning("FIRST EPSS lookup failed for %s: %s", cve_id, exc)
                return None

        if response.status_code != 200:
            logger.warning("FIRST EPSS lookup failed for %s: HTTP %s", cve_id, response.status_code)
            return None

        return self.parse_response(response.json())

    def parse_response(self, payload: dict) -> EPSSLookupResult:
        data = payload.get("data") or []
        if not data:
            return EPSSLookupResult(found=False)

        row = data[0]
        try:
            score = self._probability(row.get("epss"))
            percentile = self._probability(row.get("percentile"))
            epss_date = date.fromisoformat(row["date"]) if row.get("date") else None
        except (TypeError, ValueError) as exc:
            raise ValueError("Malformed FIRST EPSS response") from exc

        return EPSSLookupResult(found=True, score=score, percentile=percentile, epss_date=epss_date)

    async def enrich_by_cve_id(self, cve_id: str, db: AsyncSession) -> bool:
        lookup = await self.lookup_by_cve_id(cve_id)
        if lookup is None:
            return False

        result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
        entry = result.scalar_one_or_none()
        if entry is None:
            return False

        entry.epss_score = lookup.score
        entry.epss_percentile = lookup.percentile
        entry.epss_date = lookup.epss_date
        entry.epss_last_checked_at = utcnow()
        entry.epss_source = "FIRST"
        await db.flush()
        return lookup.found

    @staticmethod
    def _probability(value: object) -> float | None:
        if value is None:
            return None
        probability = float(value)
        if not 0.0 <= probability <= 1.0:
            raise ValueError("EPSS probability value outside 0.0-1.0")
        return probability
