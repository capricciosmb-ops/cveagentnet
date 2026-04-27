from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.dependencies import get_db, get_redis
from api.models.agent import Agent
from api.models.base import utcnow
from api.services.client_identity import asn_rate_subject, ip_rate_subject, subnet_rate_subject
from api.services.rate_limit import POLICIES, RedisRateLimiter

bearer_scheme = HTTPBearer(auto_error=False)


def issue_api_key() -> str:
    # The prefix is not a secret. It narrows DB lookup to one candidate while
    # keeping the verifier as a slow bcrypt hash of the complete key.
    return f"can_{secrets.token_urlsafe(8)}_{secrets.token_urlsafe(32)}"


def api_key_prefix(api_key: str) -> str | None:
    parts = api_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "can" or not parts[1]:
        return None
    return f"can_{parts[1]}"


def hash_api_key(api_key: str) -> str:
    return bcrypt.hashpw(api_key.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    return bcrypt.checkpw(api_key.encode("utf-8"), api_key_hash.encode("utf-8"))


def create_agent_jwt(agent_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(agent_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_ttl_minutes)).timestamp()),
        "aud": "cveagentnet-agents",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_agent_jwt(token: str) -> uuid.UUID | None:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience="cveagentnet-agents",
        )
        return uuid.UUID(payload["sub"])
    except Exception:
        return None


async def authenticate_bearer_token(token: str, db: AsyncSession) -> Agent | None:
    jwt_agent_id = decode_agent_jwt(token)
    if jwt_agent_id:
        agent = await db.get(Agent, jwt_agent_id)
        if agent and agent.is_active:
            agent.last_seen_at = utcnow()
            return agent

    key_prefix = api_key_prefix(token)
    if key_prefix:
        result = await db.execute(select(Agent).where(Agent.api_key_prefix == key_prefix, Agent.is_active.is_(True)).limit(1))
        agent = result.scalar_one_or_none()
        if agent and verify_api_key(token, agent.api_key_hash):
            agent.last_seen_at = utcnow()
            return agent
        return None

    # Legacy development keys created before prefixes remain accepted. This path is
    # protected by the pre-auth rate limiter in get_current_agent.
    result = await db.execute(select(Agent).where(Agent.is_active.is_(True)))
    for agent in result.scalars():
        if verify_api_key(token, agent.api_key_hash):
            agent.last_seen_at = utcnow()
            return agent
    return None


async def enforce_auth_attempt_rate_limit(request: Request, redis: Redis) -> None:
    limiter = RedisRateLimiter(redis)
    await limiter.enforce(ip_rate_subject(request, "auth"), POLICIES["auth_ip"])
    await limiter.enforce(subnet_rate_subject(request, "auth"), POLICIES["auth_subnet"])
    asn_subject = asn_rate_subject(request, "auth")
    if asn_subject:
        await limiter.enforce(asn_subject, POLICIES["auth_asn"])


async def get_current_agent(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> Agent:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    await enforce_auth_attempt_rate_limit(request, redis)
    agent = await authenticate_bearer_token(credentials.credentials, db)
    if not agent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or inactive agent credential")
    return agent
