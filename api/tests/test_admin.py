from __future__ import annotations

from copy import deepcopy

from api.tests.conftest import register_agent


def test_admin_can_suspend_agent_and_block_writes(client, agent_registration_payload, cve_payload):
    agent_id, api_key = register_agent(client, agent_registration_payload)
    unauthenticated = client.get("/admin/agents")
    assert unauthenticated.status_code == 401

    listed = client.get("/admin/agents", headers={"Authorization": "Bearer test-admin-key"})
    assert listed.status_code == 200
    assert any(agent["id"] == agent_id for agent in listed.json())

    suspended = client.patch(
        f"/admin/agents/{agent_id}",
        headers={"Authorization": "Bearer test-admin-key"},
        json={"is_active": False},
    )
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["is_active"] is False

    payload = deepcopy(cve_payload)
    payload["finding"]["title"] = "Suspended agent write should be rejected"
    rejected = client.post("/cve/submit", json=payload, headers={"Authorization": f"Bearer {api_key}"})
    assert rejected.status_code == 401

    audit = client.get("/admin/audit-log", headers={"Authorization": "Bearer test-admin-key"})
    assert audit.status_code == 200
    assert any(event["action"] == "admin.agent.update" for event in audit.json())
