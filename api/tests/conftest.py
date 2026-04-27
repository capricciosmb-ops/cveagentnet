from __future__ import annotations

import os
import sys
from collections.abc import AsyncGenerator
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("DISABLE_RATE_LIMIT", "true")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
os.environ.setdefault("AGENT_PROBATION_HOURS", "0")
os.environ.setdefault("TRUSTED_AGENT_MIN_REPUTATION", "0")

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from fakeredis.aioredis import FakeRedis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.dependencies import get_db, get_redis
from api.main import app
from api.models import Base


@pytest_asyncio.fixture()
async def db_session(tmp_path) -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture()
def client(db_session: AsyncSession) -> TestClient:
    async def override_db():
        yield db_session

    async def override_redis():
        redis = FakeRedis(decode_responses=True)
        try:
            yield redis
        finally:
            await redis.aclose()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = override_redis
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def agent_registration_payload() -> dict:
    return {
        "agent_name": "pytest-agent",
        "agent_type": "hybrid",
        "tool_chain": ["pytest", "openclaw"],
        "authorized_scopes": ["research-lab"],
    }


@pytest.fixture()
def cve_payload() -> dict:
    return {
        "target_scope": "research-lab",
        "finding": {
            "title": "Remote code execution in research harness parser",
            "description": "A parser in the authorized research harness accepts malformed structured input and reaches an unsafe execution branch during validation.",
            "cve_id": None,
            "cwe_id": "CWE-94",
            "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_v3_score": 9.8,
            "epss_score": 0.0,
            "affected_products": [{"vendor": "Research", "product": "Harness", "version_range": "<=1.0.0"}],
            "exploit_chain": [{"step": 1, "action": "Run authorized parser harness", "evidence": "exit=0 branch=unsafe"}],
            "reproduction_steps": "1. Start the local harness.\n2. Submit the sanitized malformed structure.\n3. Observe the unsafe branch marker.",
            "confidence_score": 0.87,
            "payload_sample": "sanitized-structure",
            "references": ["https://example.com/research-note"],
            "tags": ["rce", "parser"],
        },
    }


def register_agent(client: TestClient, payload: dict | None = None) -> tuple[str, str]:
    response = client.post("/agents/register", json=payload or {
        "agent_name": "helper-agent",
        "agent_type": "enrichment",
        "tool_chain": ["pytest"],
        "authorized_scopes": ["research-lab"],
    })
    assert response.status_code == 201, response.text
    body = response.json()
    return body["agent_id"], body["api_key"]
