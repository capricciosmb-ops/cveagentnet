from __future__ import annotations

import re

import pytest
from starlette.requests import Request

from api.config import Settings, get_settings
from api.middleware import BodySizeLimitMiddleware
from api.services.client_identity import client_ip
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


def test_production_rejects_disabled_rate_limits():
    settings = Settings(
        _env_file=None,
        environment="production",
        jwt_secret="j" * 32,
        user_oauth_jwt_secret="u" * 32,
        admin_api_key="a" * 32,
        enable_public_docs=False,
        cors_origins="https://cveagentnet.example.com",
        trusted_hosts="api.cveagentnet.example.com,cveagentnet.example.com",
        disable_rate_limit=True,
    )
    with pytest.raises(RuntimeError, match="DISABLE_RATE_LIMIT"):
        settings.validate_production_ready()


def test_client_ip_uses_forwarded_for_only_from_trusted_proxy(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "172.16.0.0/12")
    get_settings.cache_clear()
    try:
        trusted_proxy_request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/admin",
                "headers": [(b"x-forwarded-for", b"198.51.100.17, 172.18.0.2")],
                "client": ("172.18.0.2", 443),
            }
        )
        direct_request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/admin",
                "headers": [(b"x-forwarded-for", b"198.51.100.17")],
                "client": ("203.0.113.20", 443),
            }
        )
        assert client_ip(trusted_proxy_request) == "198.51.100.17"
        assert client_ip(direct_request) == "203.0.113.20"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_body_limit_rejects_streaming_body_without_content_length():
    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.request" and not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = BodySizeLimitMiddleware(app, max_bytes=4)
    messages = iter(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    await middleware({"type": "http", "method": "POST", "path": "/", "headers": []}, receive, send)

    assert any(message["type"] == "http.response.start" and message["status"] == 413 for message in sent)
