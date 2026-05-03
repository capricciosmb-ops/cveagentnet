from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import date

import pytest

from api.models.cve import CVEEntry
from api.services.epss import EPSSLookupResult, FIRSTEPSSService
from api.tests.conftest import register_agent


def test_first_epss_response_parser_accepts_probability_strings():
    result = FIRSTEPSSService().parse_response(
        {"data": [{"cve": "CVE-2024-12345", "epss": "0.123456", "percentile": "0.987654", "date": "2026-04-29"}]}
    )

    assert result.found is True
    assert result.score == 0.123456
    assert result.percentile == 0.987654
    assert result.epss_date == date(2026, 4, 29)


@pytest.mark.asyncio
async def test_first_epss_enrichment_updates_authoritative_fields(client, db_session, agent_registration_payload, cve_payload, monkeypatch):
    _, api_key = register_agent(client, agent_registration_payload)
    payload = deepcopy(cve_payload)
    payload["finding"]["cve_id"] = "CVE-2026-23456"
    payload["finding"]["epss_score"] = 0.99

    response = client.post("/cve/submit", json=payload, headers={"Authorization": f"Bearer {api_key}"})
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["epss_score"] is None

    service = FIRSTEPSSService()

    async def fake_lookup(cve_id: str) -> EPSSLookupResult:
        assert cve_id == "CVE-2026-23456"
        return EPSSLookupResult(found=True, score=0.123456, percentile=0.987654, epss_date=date(2026, 4, 29))

    monkeypatch.setattr(service, "lookup_by_cve_id", fake_lookup)
    assert await service.enrich_by_cve_id("CVE-2026-23456", db_session) is True

    entry = await db_session.get(CVEEntry, uuid.UUID(created["id"]))
    assert entry is not None
    assert float(entry.epss_score) == 0.123456
    assert float(entry.epss_percentile) == 0.987654
    assert entry.epss_date == date(2026, 4, 29)
    assert entry.epss_last_checked_at is not None
    assert entry.epss_source == "FIRST"
