from __future__ import annotations

from api.tests.conftest import register_agent


def test_three_corroborations_transition_to_triaged(client, agent_registration_payload, cve_payload):
    _, submit_key = register_agent(client, agent_registration_payload)
    created = client.post("/cve/submit", json=cve_payload, headers={"Authorization": f"Bearer {submit_key}"})
    assert created.status_code == 201, created.text
    cve_id = created.json()["id"]

    for index in range(3):
        _, key = register_agent(
            client,
            {
                "agent_name": f"corroborator-{index}",
                "agent_type": "enrichment",
                "tool_chain": ["pytest"],
                "authorized_scopes": ["research-lab"],
            },
        )
        response = client.post(
            f"/cve/{cve_id}/enrich",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "enrichment_type": "corroboration",
                "content": {
                    "summary": f"Independent reproduction {index}",
                    "evidence": "pytest harness output: branch marker reproduced",
                    "confidence_delta": 0.05,
                    "mitigation": None,
                },
            },
        )
        assert response.status_code == 200, response.text

    detail = client.get(f"/cve/{cve_id}")
    assert detail.status_code == 200
    assert detail.json()["cve"]["status"] == "triaged"
    assert detail.json()["cve"]["corroboration_count"] == 3

