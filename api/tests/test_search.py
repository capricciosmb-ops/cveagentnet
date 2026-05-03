from __future__ import annotations

from api.tests.conftest import register_agent


def test_semantic_search_returns_relevant_result(client, agent_registration_payload, cve_payload):
    _, api_key = register_agent(client, agent_registration_payload)
    created = client.post("/cve/submit", json=cve_payload, headers={"Authorization": f"Bearer {api_key}"})
    assert created.status_code == 201, created.text

    response = client.get("/cve/search", params={"q": "remote code execution", "min_conf": 0.5, "limit": 10})
    assert response.status_code == 200, response.text
    results = response.json()["results"]
    assert results
    assert "Remote code execution" in results[0]["cve"]["title"]


def test_mcp_manifest(client):
    response = client.get("/mcp/manifest")
    assert response.status_code == 200
    assert any(tool["name"] == "search_cve" for tool in response.json()["tools"])


def test_v1_aliases_expose_agent_and_mcp_contracts(client, agent_registration_payload):
    register_response = client.post("/v1/agents/register", json=agent_registration_payload)
    assert register_response.status_code == 201, register_response.text

    manifest_response = client.get("/v1/mcp/manifest")
    assert manifest_response.status_code == 200
    assert any(tool["name"] == "submit_cve" for tool in manifest_response.json()["tools"])
