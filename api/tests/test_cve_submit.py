from __future__ import annotations

from copy import deepcopy

from api.tests.conftest import register_agent


def test_submit_creates_entry_and_duplicate_returns_conflict(client, agent_registration_payload, cve_payload):
    _, api_key = register_agent(client, agent_registration_payload)
    response = client.post("/cve/submit", json=cve_payload, headers={"Authorization": f"Bearer {api_key}"})
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["status"] == "discovered"
    assert created["confidence_score"] == 0.87
    assert created["cve_id"].startswith("PROVISIONAL-")

    duplicate = client.post("/cve/submit", json=cve_payload, headers={"Authorization": f"Bearer {api_key}"})
    assert duplicate.status_code == 409
    assert duplicate.json()["match_type"] == "hash"


def test_submit_rejects_duplicate_cve_id_before_semantic_match(client, agent_registration_payload, cve_payload):
    _, api_key = register_agent(client, agent_registration_payload)
    first = deepcopy(cve_payload)
    first["finding"]["cve_id"] = "CVE-2026-12345"
    response = client.post("/cve/submit", json=first, headers={"Authorization": f"Bearer {api_key}"})
    assert response.status_code == 201, response.text

    second = deepcopy(cve_payload)
    second["finding"]["cve_id"] = "CVE-2026-12345"
    second["finding"]["title"] = "Authentication bypass in sample gateway"
    second["finding"]["description"] = (
        "A separate authorized research gateway accepts a malformed session state and incorrectly treats it as "
        "an authenticated principal during local validation."
    )
    second["finding"]["tags"] = ["auth-bypass", "gateway"]
    duplicate = client.post("/cve/submit", json=second, headers={"Authorization": f"Bearer {api_key}"})
    assert duplicate.status_code == 409
    assert duplicate.json()["match_type"] == "cve_id"
