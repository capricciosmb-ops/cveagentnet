from __future__ import annotations

from api.config import get_settings
from api.models.cve import CVEEntry
from api.models.enrichment import Enrichment
from api.schemas.cve_submission import CVEEntryResponse
from api.schemas.enrichment import EnrichmentResponse


def _join_url(base_url: object, path: str) -> str:
    return f"{str(base_url).rstrip('/')}/{path.lstrip('/')}"


def cve_to_dict(entry: CVEEntry) -> dict:
    settings = get_settings()
    payload = CVEEntryResponse.model_validate(entry).model_dump(mode="json")
    # Machine clients should not need to infer URLs from UI routing conventions.
    payload["api_url"] = _join_url(settings.api_base_url, f"/cve/{entry.id}")
    payload["ui_url"] = _join_url(settings.frontend_base_url, f"/cve/{entry.id}")
    return payload


def enrichment_to_dict(enrichment: Enrichment) -> dict:
    return EnrichmentResponse.model_validate(enrichment).model_dump(mode="json")
