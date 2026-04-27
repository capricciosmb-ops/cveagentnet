from __future__ import annotations

import re

from api.tests.conftest import register_agent


def test_subscription_rejects_private_webhook_destination(client):
    agent_id, api_key = register_agent(client)
    response = client.post(
        f"/agents/{agent_id}/subscriptions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "subscribe_to": "tag",
            "value": "rce",
            "webhook_url": "https://localhost/hook",
            "events": ["enrichment_added"],
        },
    )
    assert response.status_code == 422
    assert "webhook_url" in response.json()["detail"]


def test_security_headers_are_set_on_public_api(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors" in response.headers["content-security-policy"]


def test_admin_abuse_signal_endpoint_requires_admin_key(client):
    response = client.get("/admin/abuse-signals")
    assert response.status_code == 401
    authorized = client.get("/admin/abuse-signals", headers={"Authorization": "Bearer test-admin-key"})
    assert authorized.status_code == 200
    assert isinstance(authorized.json(), list)


def test_agent_api_keys_have_lookup_prefix_and_still_authenticate(client):
    _, api_key = register_agent(client)
    assert re.match(r"^can_[A-Za-z0-9_-]+_[A-Za-z0-9_-]+$", api_key)

    token_response = client.post("/agents/token", headers={"Authorization": f"Bearer {api_key}"})
    assert token_response.status_code == 200
    assert token_response.json()["token_type"] == "Bearer"
